"""Cache analysis: where a cache and an origin disagree about a response.

The same idea as the desync engine, one layer up. There, two hops disagree about
where a message ends. Here they disagree about what a response is: the origin
serves a per-user page while the cache decides the URL looks like a static asset
and stores it (web cache deception), or the origin lets a request header change
the response while the cache leaves that header out of its key (cache
poisoning). Either way one response reaches a user it was never written for.

Everything here is offline. It reads a parsed request, a parsed response and the
request target, and reports the disagreement. Nothing is sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .http.types import Message

KIND_DECEPTION = "deception"
KIND_POISONING = "poisoning"

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_SEVERITY_ORDER = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}

# Bounds. Header values and the target come off the wire, so nothing here scans
# an unbounded amount of attacker-chosen text.
MAX_TARGET_BYTES = 8192
MAX_DIRECTIVE_BYTES = 4096
MAX_BODY_SCAN = 1 << 20

# Statuses a shared cache will store with no explicit freshness at all, from
# RFC 9111 section 4.2.2. The 200 in this set is what makes deception work.
HEURISTIC_STATUSES = frozenset({200, 203, 204, 206, 300, 301, 308, 404, 405,
                                410, 414, 501})

# Suffixes a CDN rule commonly keys on, plus the content type each one claims.
# A response whose type contradicts its suffix is the origin and the cache
# disagreeing about what the URL is.
EXTENSION_TYPES = {
    "css": "text/css", "js": "javascript", "mjs": "javascript",
    "json": "json", "xml": "xml", "txt": "text/plain", "pdf": "application/pdf",
    "ico": "image/", "gif": "image/", "jpg": "image/", "jpeg": "image/",
    "png": "image/", "svg": "image/", "webp": "image/", "bmp": "image/",
    "avif": "image/", "woff": "font", "woff2": "font", "ttf": "font",
    "eot": "font", "map": "json", "mp4": "video/",
}

# A server that labels bytes it cannot identify says octet-stream, which is a
# gap in its type table rather than a response written for one user.
OPAQUE_TYPES = frozenset({"application/octet-stream", "binary/octet-stream",
                          "application/binary"})

# Percent-encoded delimiters. A cache that decodes one of these and an origin
# that does not are keying on different paths, which is the cache-buster half of
# web cache deception.
ENCODED_DELIMITERS = ("%2f", "%5c", "%3b", "%3f", "%23", "%00", "%09", "%0a",
                      "%0d", "%20", "%2e")

# Headers a default cache key ignores but an application still trusts.
UNKEYED_HEADERS = ("X-Forwarded-Host", "X-Host", "X-Original-URL",
                   "X-Rewrite-URL", "Forwarded", "X-Forwarded-Server",
                   "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-For")

# Reflecting one of these rewrites where the whole page points, so it outranks a
# reflection of, say, a client IP.
ORIGIN_REWRITING = frozenset({"x-forwarded-host", "x-host", "x-original-url",
                              "x-rewrite-url", "forwarded",
                              "x-forwarded-server"})

# Values too common to be evidence of anything on their own. A page behind a TLS
# terminator carries X-Forwarded-Proto: https and links to https:// URLs for
# reasons that have nothing to do with the header, so neither the bare word nor
# the scheme written into a URL shows that the header steered anything.
GENERIC_VALUES = frozenset({"http", "https", "on", "off", "1", "0", "true",
                            "false", "80", "443", "localhost"})
MIN_REFLECT_LEN = 4


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    target: str
    reason: str
    evidence: str
    severity: str


# --- would a shared cache store this? --------------------------------------

def is_cacheable(response: Message, *, method: str = "GET") -> tuple[bool, str]:
    """Whether a shared cache would store this response, and why.

    Ordered the way a shared cache resolves the directives: no-store and a bare
    private stop everything, s-maxage beats max-age because it is the shared
    cache's own knob, and a 200 with no directives at all is stored on the
    heuristic every cache applies.
    """
    method = (method or "GET").upper()
    directives = _directives(response)

    if _bare(directives, "no-store"):
        return False, "Cache-Control: no-store"
    if _bare(directives, "private"):
        return False, "Cache-Control: private, so no shared cache stores it"

    s_maxage = _delta(directives, "s-maxage")
    max_age = _delta(directives, "max-age")
    explicit = s_maxage is not None or max_age is not None or "public" in directives
    if method not in ("GET", "HEAD") and not explicit:
        return False, f"a {method} response is not stored without explicit freshness"

    # A bare no-cache still permits storage but forbids reuse without asking the
    # origin, so nothing is served from cache on its own.
    if _bare(directives, "no-cache"):
        return False, "Cache-Control: no-cache, revalidated on every reuse"

    if s_maxage is not None:
        if s_maxage > 0:
            return True, f"Cache-Control: s-maxage={s_maxage}"
        return False, "Cache-Control: s-maxage=0"
    if max_age is not None:
        if max_age > 0:
            return True, f"Cache-Control: max-age={max_age}"
        return False, "Cache-Control: max-age=0"
    if "public" in directives:
        return True, "Cache-Control: public"

    expires = response.get("expires")
    if expires is not None:
        if _expires_is_future(expires, response.get("date")):
            return True, f"Expires: {expires}"
        return False, f"Expires: {expires} is already past"

    if response.status in HEURISTIC_STATUSES:
        return True, (f"{response.status} to {method} with no cache directives, "
                      f"stored heuristically")
    return False, f"{response.status} is not stored without explicit freshness"


# --- web cache deception ---------------------------------------------------

def deception_finding(target: str, response: Message, *,
                      method: str = "GET") -> Finding | None:
    """A dynamic response living at a URL a cache reads as a static asset."""
    if not 200 <= response.status < 300:
        return None
    path = _split_target(target)[1]
    shape = _static_shape(path)
    if shape is None:
        return None
    extension, description = shape

    signals = _dynamic_signals(response, extension)
    if not signals:
        return None

    cacheable, why = is_cacheable(response, method=method)
    if not cacheable:
        # A rule that caches by suffix runs before the response headers are
        # read, so it stores what the directives told it not to. Only no-store
        # is honoured widely enough to clear the finding.
        if extension is None or _bare(_directives(response), "no-store"):
            return None
        why = f"{why}, but a rule keying on .{extension} stores it regardless"

    high = response.count("set-cookie") > 0
    return Finding(
        kind=KIND_DECEPTION,
        target=target,
        reason=(f"the origin serves a dynamic {response.status} at {path} while "
                f"the cache sees a static URL: {why}"),
        evidence=f"{description}; {'; '.join(signals)}",
        severity=SEVERITY_HIGH if high else SEVERITY_MEDIUM,
    )


def _static_shape(path: str) -> tuple[str | None, str] | None:
    """The extension a cache would key on, and how the path hides it."""
    low = path.lower()
    for delimiter in ENCODED_DELIMITERS:
        if low.endswith(delimiter):
            return None, (f"path ends in the encoded delimiter {delimiter}, "
                          f"which the cache and the origin decode differently")

    segment = path.rsplit("/", 1)[-1]
    parameter = _split_parameter(segment)
    if parameter is not None:
        extension = _extension(parameter)
        if extension is not None:
            return extension, (f"path parameter {parameter!r} appends a .{extension} "
                               f"suffix the origin drops and the cache keeps")

    extension = _extension(segment)
    if extension is not None:
        return extension, f"path ends in .{extension}"
    return None


def _split_parameter(segment: str) -> str | None:
    """The part after a path parameter delimiter, encoded or not."""
    for delimiter in (";", "%3b", "%3B"):
        if delimiter in segment:
            return segment.rsplit(delimiter, 1)[-1]
    return None


def _extension(segment: str) -> str | None:
    name, dot, extension = segment.rpartition(".")
    if not dot:
        return None
    extension = extension.lower()
    return extension if extension in EXTENSION_TYPES else None


def _dynamic_signals(response: Message, extension: str | None) -> list[str]:
    """Evidence that this response belongs to one user, not to every user."""
    signals = []
    if response.count("set-cookie"):
        signals.append("Set-Cookie in the response")
    if _bare(_directives(response), "private"):
        signals.append("Cache-Control: private")

    content_type = (response.get("content-type") or "").split(";")[0].strip().lower()
    expected = EXTENSION_TYPES.get(extension or "")
    if content_type.startswith("text/html"):
        if expected:
            signals.append(f"Content-Type text/html, not the {expected} "
                           f"a .{extension} suffix implies")
        else:
            signals.append("Content-Type text/html, a generated page")
    elif (expected and content_type and content_type not in OPAQUE_TYPES
            and expected not in content_type):
        signals.append(f"Content-Type {content_type}, not the {expected} "
                       f"a .{extension} suffix implies")
    return signals


# --- cache poisoning -------------------------------------------------------

def cache_key(request: Message, target: str) -> tuple[str, str, str, str]:
    """The default shared-cache key: everything else is unkeyed input."""
    host, path, query = _split_target(target)
    return (request.method or "GET", host or (request.get("host") or ""),
            path, query)


def poisoning_findings(target: str, request: Message,
                       response: Message) -> list[Finding]:
    """Unkeyed request headers that reach a response other users will be served."""
    method = request.method or "GET"
    cacheable, why = is_cacheable(response, method=method)
    if not cacheable:
        return []

    vary = _vary(response)
    if "*" in vary:
        return []

    key = cache_key(request, target)
    key_text = f"{key[0]} {key[1]}{key[2]}{'?' + key[3] if key[3] else ''}"

    findings = []
    for name in UNKEYED_HEADERS:
        if name.lower() in vary:
            continue
        for value in request.get_all(name):
            # A header echoing the host the cache already keys on proves nothing.
            if value.strip().lower() == key[1].strip().lower():
                continue
            needle = _needle(value)
            if needle is None:
                continue
            where = _reflection(needle, response)
            if where is None:
                continue
            in_header = where != "the response body"
            severity = (SEVERITY_HIGH
                        if in_header or name.lower() in ORIGIN_REWRITING
                        else SEVERITY_MEDIUM)
            findings.append(Finding(
                kind=KIND_POISONING,
                target=target,
                reason=(f"{name} is not in the cache key ({key_text}) but reaches "
                        f"{where} of a response the cache stores: {why}"),
                evidence=f"{name}: {value} reflected in {where}",
                severity=severity,
            ))
            break     # one finding per header, not one per duplicate value

    findings.sort(key=lambda finding: _SEVERITY_ORDER[finding.severity])
    return findings


def _vary(response: Message) -> set[str]:
    names = set()
    for value in response.get_all("vary"):
        for token in _split_commas(value):
            names.add(token.strip().lower())
    return names


def _needle(value: str) -> str | None:
    """What counts as a reflection of this value, if anything does."""
    low = value.strip().lower()
    if low in GENERIC_VALUES:
        return None
    return low if len(low) >= MIN_REFLECT_LEN else None


def _reflection(needle: str, response: Message) -> str | None:
    for header in response.headers:
        if needle in header.value.lower():
            return f"the {header.name} response header"
    body = response.body[:MAX_BODY_SCAN].decode("latin-1", "replace").lower()
    if needle in body:
        return "the response body"
    return None


# --- header and target parsing ---------------------------------------------

def _directives(message: Message) -> dict[str, str]:
    """Cache-Control as name -> argument, empty string for a bare directive."""
    out: dict[str, str] = {}
    for value in message.get_all("cache-control"):
        for token in _split_commas(value):
            name, _, argument = token.partition("=")
            name = name.strip().lower()
            # A bare directive is the stronger statement, so a later qualified
            # repeat of the same name does not erase it.
            if name and out.get(name) != "":
                out[name] = argument.strip().strip('"')
    return out


def _bare(directives: dict[str, str], name: str) -> bool:
    """A qualified no-cache="Set-Cookie" restricts one field, not the response."""
    return name in directives and not directives[name]


def _delta(directives: dict[str, str], name: str) -> int | None:
    value = directives.get(name)
    if value is None or not value.isdigit():
        return None
    return int(value)


def _split_commas(value: str) -> list[str]:
    """Split a comma list, respecting the quoted-string form of an argument."""
    parts, current, quoted = [], [], False
    for character in value[:MAX_DIRECTIVE_BYTES]:
        if character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    parts.append("".join(current))
    return [part for part in parts if part.strip()]


def _split_target(target: str) -> tuple[str, str, str]:
    """(host, path, query) from origin-form or absolute-form request target."""
    target = target[:MAX_TARGET_BYTES].split("#", 1)[0]
    host = ""
    for scheme in ("http://", "https://"):
        if target.lower().startswith(scheme):
            authority, slash, rest = target[len(scheme):].partition("/")
            host = authority
            target = slash + rest
            break
    path, _, query = target.partition("?")
    return host, path, query


def _expires_is_future(expires: str, date: str | None) -> bool:
    """An Expires a cache cannot parse is an Expires already past (RFC 9111)."""
    moment = _http_date(expires)
    if moment is None:
        return False
    return moment > (_http_date(date or "") or datetime.now(timezone.utc))


def _http_date(value: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        # A year or zone offset no datetime can hold raises out of the stdlib
        # parser, and the bytes came off the wire, so it is an unusable date.
        return None
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
