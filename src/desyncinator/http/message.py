"""HTTP/1.1 message parsing, from RFC 9112, under a profile.

The one idea the whole tool rests on: parsing an HTTP message is not a function
with a single output. Given the same bytes, a strict parser and a lenient one
can disagree about which headers exist, how the body is framed, and therefore
where the message ends. That disagreement, between a front-end and a back-end,
is request smuggling.

So parse() takes a Profile, and everything ambiguous is decided by it rather
than by this code. The parser records how it framed the body and the offset
where it decided the message ended, so two parses of one buffer can be compared.

Bytes come from the network, so they are hostile. Every length is bounded, the
header block is size-capped, and a malformed message raises ParseError, which is
a normal result here rather than a failure.
"""

from __future__ import annotations

from .chunked import decode as decode_chunked
from .profiles import (PREFER_CHUNKED, PREFER_LENGTH, REJECT_BOTH, Profile)
from .types import (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH, FRAMING_NONE,
                    FRAMING_UNTIL_CLOSE, Header, Message, ParseError)

MAX_HEADER_BYTES = 1 << 18
MAX_HEADERS = 1000
MAX_LINE_BYTES = 1 << 16


def parse(data: bytes, profile: Profile, *, is_request: bool = True) -> Message:
    """Parse one message from the front of data under profile."""
    start_line, offset = _read_line(data, 0, profile)
    if len(data) > MAX_HEADER_BYTES and offset > MAX_HEADER_BYTES:
        raise ParseError("header block too large")

    if profile.tolerate_leading_junk:
        start_line = start_line.lstrip(b"\xef\xbb\xbf \t")

    headers, offset = _read_headers(data, offset, profile)

    if is_request:
        method, target, version = _request_line(start_line)
        return _frame_request(data, offset, profile, method, target, version,
                              headers)
    status, reason, version = _status_line(start_line)
    return _frame_response(data, offset, profile, status, reason, version,
                           headers, method="")


# --- the start line --------------------------------------------------------

def _request_line(line: bytes) -> tuple[str, str, str]:
    parts = line.split(b" ")
    if len(parts) != 3:
        raise ParseError(f"malformed request line {line!r}")
    method, target, version = parts
    if not method or not version.startswith(b"HTTP/"):
        raise ParseError(f"malformed request line {line!r}")
    return method.decode("latin-1"), target.decode("latin-1"), version.decode("latin-1")


def _status_line(line: bytes) -> tuple[int, str, str]:
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise ParseError(f"malformed status line {line!r}")
    try:
        status = int(parts[1])
    except ValueError:
        raise ParseError(f"non-numeric status {parts[1]!r}")
    reason = parts[2].decode("latin-1") if len(parts) == 3 else ""
    return status, reason, parts[0].decode("latin-1")


# --- headers ---------------------------------------------------------------

def _read_headers(data: bytes, offset: int,
                  profile: Profile) -> tuple[list[Header], int]:
    headers: list[Header] = []
    while True:
        if len(headers) > MAX_HEADERS:
            raise ParseError("too many headers")
        line_start = offset
        line, offset = _read_line(data, offset, profile)
        if line == b"":
            return headers, offset
        if line[:1] in (b" ", b"\t"):
            # Obsolete line folding: a continuation of the previous header.
            if not profile.accept_obs_fold or not headers:
                raise ParseError("obsolete line folding")
            previous = headers[-1]
            folded = Header(previous.name,
                            previous.value + " " + line.strip().decode("latin-1"),
                            previous.raw + data[line_start:offset])
            headers[-1] = folded
            continue
        headers.append(_header(line, data[line_start:offset], profile))


def _header(line: bytes, raw: bytes, profile: Profile) -> Header:
    colon = line.find(b":")
    if colon <= 0:
        raise ParseError(f"header without a name {line!r}")
    name = line[:colon]
    if name != name.strip():
        if not profile.accept_space_before_colon:
            raise ParseError(f"whitespace in header name {name!r}")
        name = name.strip()
    if any(b in name for b in b" \t"):
        raise ParseError(f"space inside header name {name!r}")
    value = line[colon + 1:].strip(b" \t")
    return Header(name.decode("latin-1"), value.decode("latin-1"), raw)


# --- body framing, where the profile earns its keep ------------------------

def _frame_request(data, offset, profile, method, target, version, headers):
    framing, length = _decide_framing(headers, profile, is_request=True)
    return _apply_framing(data, offset, profile, framing, length,
                          Message(is_request=True, method=method, target=target,
                                  version=version, headers=tuple(headers),
                                  profile=profile.name))


def _frame_response(data, offset, profile, status, reason, version, headers,
                    method):
    framing, length = _decide_framing(headers, profile, is_request=False)
    if framing == FRAMING_NONE and _response_has_body(status, method):
        framing = FRAMING_UNTIL_CLOSE
    return _apply_framing(data, offset, profile, framing, length,
                          Message(is_request=False, status=status, reason=reason,
                                  version=version, headers=tuple(headers),
                                  profile=profile.name))


def _decide_framing(headers, profile, *, is_request):
    """Choose CL, chunked, or none, resolving the conflicts the profile owns.

    This is the function request smuggling attacks. The order of tests, and how
    a conflict is resolved, is a profile choice, not a fact.
    """
    has_te_chunked = _transfer_encoding_is_chunked(headers, profile)
    length = _content_length(headers, profile)

    if has_te_chunked and length is not None:
        if profile.on_both == REJECT_BOTH:
            raise ParseError("both Transfer-Encoding and Content-Length present")
        if profile.on_both == PREFER_CHUNKED:
            return FRAMING_CHUNKED, None
        return FRAMING_CONTENT_LENGTH, length     # PREFER_LENGTH

    if has_te_chunked:
        return FRAMING_CHUNKED, None
    if length is not None:
        return FRAMING_CONTENT_LENGTH, length
    return FRAMING_NONE, None


def _transfer_encoding_is_chunked(headers, profile) -> bool:
    values = [h.value for h in headers if h.lower == "transfer-encoding"]
    if not values:
        return False
    # Multiple TE headers are combined as a comma list by the spec.
    combined = ",".join(values)
    tokens = [t.strip() for t in combined.split(",")]

    if profile.te_requires_exact_chunked:
        # Only a clean, correctly-placed final "chunked" counts.
        return tokens[-1].lower() == "chunked" and all(
            t for t in tokens)
    # Lenient: the token anywhere, or a fuzzy match, is enough to frame chunked.
    for token in tokens:
        low = token.lower()
        if low == "chunked":
            return True
        if profile.te_chunked_anywhere and "chunked" in low:
            return True
    return False


def _content_length(headers, profile) -> int | None:
    values = [h.value for h in headers if h.lower == "content-length"]
    if not values:
        return None
    parsed = []
    for value in values:
        field = value.strip()
        if not field.isdigit():
            raise ParseError(f"non-numeric Content-Length {value!r}")
        parsed.append(int(field))

    distinct = set(parsed)
    if len(distinct) > 1:
        if profile.on_duplicate_length == REJECT_BOTH:
            raise ParseError("conflicting Content-Length values")
        return parsed[-1] if profile.duplicate_length_takes_last else parsed[0]
    return parsed[0]


def _apply_framing(data, offset, profile, framing, length, message):
    if framing == FRAMING_CHUNKED:
        chunked = decode_chunked(data, offset, profile)
        return _finish(message, FRAMING_CHUNKED, chunked.body, chunked.end, data)
    if framing == FRAMING_CONTENT_LENGTH:
        end = offset + length
        if end > len(data):
            raise ParseError("Content-Length runs past the data")
        return _finish(message, FRAMING_CONTENT_LENGTH, data[offset:end], end, data)
    if framing == FRAMING_UNTIL_CLOSE:
        return _finish(message, FRAMING_UNTIL_CLOSE, data[offset:], len(data), data)
    return _finish(message, FRAMING_NONE, b"", offset, data)


def _finish(message, framing, body, end, data):
    return Message(
        is_request=message.is_request, method=message.method,
        target=message.target, version=message.version, status=message.status,
        reason=message.reason, headers=message.headers, body=body,
        framing=framing, body_end=end, trailing=data[end:], profile=message.profile)


def _response_has_body(status: int, method: str) -> bool:
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return False
    return True


# --- line reading ----------------------------------------------------------

def _read_line(data: bytes, offset: int, profile: Profile) -> tuple[bytes, int]:
    end = data.find(b"\n", offset)
    if end == -1:
        raise ParseError("line without a terminator")
    if end - offset > MAX_LINE_BYTES:
        raise ParseError("line too long")
    line = data[offset:end]
    if line.endswith(b"\r"):
        return line[:-1], end + 1
    if profile.accept_bare_lf:
        return line, end + 1
    raise ParseError("line terminated by bare LF")
