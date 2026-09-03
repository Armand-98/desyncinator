"""Ground-truth corpus: hand-built messages with known labels.

Every attack the tool claims to find needs a message where the answer is known
before any detector runs, and every false positive it must avoid needs a
legitimate message shaped like an attack. This module is that set: bytes plus
labels, assembled by hand against RFC 9112 so a reader can check a label by eye.

It deliberately imports nothing from the detectors (desync, cache). The corpus
produces inputs and expected outputs; the evaluation harness wires them to the
engines. Marking your own homework is not allowed here.
"""

from __future__ import annotations

from dataclasses import dataclass

SMUGGLING_CLASSES = ("CL.TE", "TE.CL", "TE.TE", "CL.CL", "parse-split")
CACHE_FINDINGS = ("deception", "poisoning")
KINDS = SMUGGLING_CLASSES + CACHE_FINDINGS + ("benign",)


@dataclass(frozen=True, slots=True)
class Expected:
    cls: str | None = None        # smuggling class, e.g. "CL.TE"; None otherwise
    smuggled: bytes = b""         # bytes the backend leaves for the next request
    frontend: str = ""            # profile that frames the message the long way
    backend: str = ""             # profile that frames it the short way
    finding: str | None = None    # cache finding kind, or None for benign


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    raw: bytes | tuple[bytes, bytes]   # request bytes, or (request, response)
    kind: str
    expected: Expected
    description: str


def _lines(*lines: bytes, body: bytes = b"") -> bytes:
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _one_chunk(data: bytes) -> bytes:
    """A single data chunk of `data` followed by the terminating zero chunk."""
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)


# The request an attacker wants the backend to run as if it were the next
# client's. It reappears verbatim as the backend's leftover bytes.
SMUGGLED = b"GET /admin HTTP/1.1\r\nHost: victim.example\r\n\r\n"


def smuggling_cases() -> list[Case]:
    cases: list[Case] = []

    # CL.TE: front-end obeys Content-Length and forwards the whole body; back-end
    # obeys chunked, stops at the zero chunk, and treats the rest as a new request.
    body = b"0\r\n\r\n" + SMUGGLED
    cases.append(Case(
        name="cl_te",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Content-Length: %d" % len(body),
                   b"Transfer-Encoding: chunked", body=body),
        kind="CL.TE",
        expected=Expected(cls="CL.TE", smuggled=SMUGGLED,
                          frontend="lenient-length", backend="lenient-chunked"),
        description="CL front-end forwards the body a chunked back-end ends early."))

    # TE.CL: front-end obeys chunked and swallows the smuggled request as chunk
    # data; back-end obeys Content-Length, reads only the size line, and the chunk
    # data becomes its next request.
    size_line = b"%x\r\n" % len(SMUGGLED)
    body = size_line + SMUGGLED + b"\r\n0\r\n\r\n"
    leftover = SMUGGLED + b"\r\n0\r\n\r\n"
    cases.append(Case(
        name="te_cl",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Content-Length: %d" % len(size_line),
                   b"Transfer-Encoding: chunked", body=body),
        kind="TE.CL",
        expected=Expected(cls="TE.CL", smuggled=leftover,
                          frontend="lenient-chunked", backend="lenient-length"),
        description="Chunked front-end hides a request a short CL back-end spills."))

    # TE.TE: both hops hold a Transfer-Encoding and only the token decides whether
    # it frames anything. A lenient hop fuzzy-matches "xchunked" and reads the
    # chunked body; a strict hop reads no chunked coding and, with no
    # Content-Length to fall back on, frames no body at all, so the whole chunked
    # body stays in its buffer as the start of the next request. The class is
    # named for the token because the token is the only reason the hops differ.
    body = _one_chunk(SMUGGLED)
    cases.append(Case(
        name="te_te_obfuscated_token",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Transfer-Encoding: xchunked", body=body),
        kind="TE.TE",
        expected=Expected(cls="TE.TE", smuggled=body,
                          frontend="lenient-chunked", backend="strict"),
        description="Obfuscated TE token: lenient frames chunked, strict frames none."))

    # The same token with a Content-Length present is the shape seen in the wild,
    # and it is a different class: the deceived hop still frames a body, from the
    # length, so the two hops disagree length against chunked. What the token
    # bought the attacker is a strict hop that accepts the message at all, since
    # a conforming "chunked" here would make it reject both framings.
    body = b"0\r\n\r\n" + SMUGGLED
    cases.append(Case(
        name="cl_te_obfuscated_token",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Content-Length: %d" % len(body),
                   b"Transfer-Encoding: xchunked", body=body),
        kind="CL.TE",
        expected=Expected(cls="CL.TE", smuggled=SMUGGLED,
                          frontend="strict", backend="lenient-chunked"),
        description="Obfuscated TE token past a strict hop: it frames the length."))

    # Space before the colon. No profile here reads the message with the header
    # absent: a lenient hop trims the space and obeys it, a strict hop refuses the
    # whole message. So the trick cannot frame two boundaries, only split the hops
    # over whether the request exists; removing the space leaves the lenient pair
    # ending the body at the same two offsets, so the space causes no boundary.
    cases.append(Case(
        name="space_before_colon_split",
        raw=_lines(b"POST /upload HTTP/1.1", b"Host: victim.example",
                   b"Transfer-Encoding : chunked", body=_one_chunk(b"Wiki")),
        kind="parse-split",
        expected=Expected(cls="parse-split", frontend="lenient-length",
                          backend="strict"),
        description="Whitespace before the colon: one hop frames it, one refuses it."))

    # Duplicate Content-Length: one hop takes the first value, the other the last,
    # so they cut the body at different offsets.
    filler = b"AAAA"
    body = filler + SMUGGLED
    cases.append(Case(
        name="duplicate_content_length",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Content-Length: %d" % len(body),
                   b"Content-Length: %d" % len(filler), body=body),
        kind="CL.CL",
        expected=Expected(cls="CL.CL", smuggled=SMUGGLED,
                          frontend="lenient-chunked", backend="lenient-length"),
        description="Two Content-Lengths: first-wins forwards what last-wins spills."))

    # Chunked body with trailing junk after the zero chunk: a chunked back-end
    # ends at the terminator and leaves the junk; a length front-end forwards it.
    body = _one_chunk(b"Wiki") + SMUGGLED
    cases.append(Case(
        name="chunked_trailing_junk",
        raw=_lines(b"POST / HTTP/1.1", b"Host: victim.example",
                   b"Content-Length: %d" % len(body),
                   b"Transfer-Encoding: chunked", body=body),
        kind="CL.TE",
        expected=Expected(cls="CL.TE", smuggled=SMUGGLED,
                          frontend="lenient-length", backend="lenient-chunked"),
        description="Junk after the zero chunk rides past a length front-end."))

    return cases


def cache_cases() -> list[Case]:
    cases: list[Case] = []

    # Web cache deception: a dynamic, per-user page requested under a path that
    # ends in .css. A cache keyed on extension stores the private response and
    # serves another user their victim's session.
    private = b"<html>balance: 4210.55 for alice</html>"
    request = _lines(b"GET /account/profile.css HTTP/1.1", b"Host: victim.example",
                     b"Cookie: session=ALICE-SECRET")
    response = _lines(b"HTTP/1.1 200 OK", b"Content-Type: text/html",
                      b"Set-Cookie: session=ALICE-SECRET; HttpOnly",
                      b"Cache-Control: public, max-age=60",
                      b"Content-Length: %d" % len(private), body=private)
    cases.append(Case(
        name="deception_profile_css",
        raw=(request, response),
        kind="deception",
        expected=Expected(finding="deception"),
        description="Per-user page under a .css path with a cacheable Set-Cookie."))

    # Cache poisoning: X-Forwarded-Host is reflected into a cacheable redirect, so
    # a cached 302 sends every later visitor to the attacker's host.
    request = _lines(b"GET / HTTP/1.1", b"Host: victim.example",
                     b"X-Forwarded-Host: evil.example")
    response = _lines(b"HTTP/1.1 302 Found", b"Location: https://evil.example/",
                      b"Cache-Control: public, max-age=3600", b"Content-Length: 0")
    cases.append(Case(
        name="poisoning_xfh_location",
        raw=(request, response),
        kind="poisoning",
        expected=Expected(finding="poisoning"),
        description="X-Forwarded-Host reflected into a cacheable Location."))

    return cases


def benign_cases() -> list[Case]:
    cases: list[Case] = []

    # A normal Content-Length POST: shaped like CL.TE but with no second framing.
    body = b"user=alice&op=login"
    cases.append(Case(
        name="benign_content_length_post",
        raw=_lines(b"POST /login HTTP/1.1", b"Host: shop.example",
                   b"Content-Type: application/x-www-form-urlencoded",
                   b"Content-Length: %d" % len(body), body=body),
        kind="benign",
        expected=Expected(),
        description="An ordinary length-framed POST, one framing, no desync."))

    # A normal chunked POST: chunked alone, correctly terminated.
    cases.append(Case(
        name="benign_chunked_post",
        raw=_lines(b"POST /upload HTTP/1.1", b"Host: shop.example",
                   b"Transfer-Encoding: chunked",
                   body=b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
        kind="benign",
        expected=Expected(),
        description="An ordinary chunked POST, one framing, no desync."))

    # gzip,chunked is legal: chunked is the final coding, so every profile frames
    # it as chunked and none disagree.
    cases.append(Case(
        name="benign_gzip_chunked",
        raw=_lines(b"GET /feed HTTP/1.1", b"Host: shop.example",
                   b"Transfer-Encoding: gzip, chunked", body=b"0\r\n\r\n"),
        kind="benign",
        expected=Expected(),
        description="Legal gzip,chunked with chunked last: agreed by all profiles."))

    # A genuinely static asset that is safe to cache: no cookies, public.
    css = b"body{margin:0}"
    request = _lines(b"GET /static/app.css HTTP/1.1", b"Host: shop.example")
    response = _lines(b"HTTP/1.1 200 OK", b"Content-Type: text/css",
                      b"Cache-Control: public, max-age=86400",
                      b"Content-Length: %d" % len(css), body=css)
    cases.append(Case(
        name="benign_static_css",
        raw=(request, response),
        kind="benign",
        expected=Expected(),
        description="A real static .css asset, public and cookie-free."))

    # An unkeyed header that the response never reflects: no poisoning primitive.
    body = b"<html>home</html>"
    request = _lines(b"GET / HTTP/1.1", b"Host: shop.example",
                     b"X-Forwarded-Host: evil.example")
    response = _lines(b"HTTP/1.1 200 OK", b"Content-Type: text/html",
                      b"Cache-Control: public, max-age=3600",
                      b"Content-Length: %d" % len(body), body=body)
    cases.append(Case(
        name="benign_unreflected_header",
        raw=(request, response),
        kind="benign",
        expected=Expected(),
        description="X-Forwarded-Host sent but never reflected: nothing to poison."))

    # The header is reflected, but the cache is told to key on it, so the poisoned
    # entry is only ever served back to a request carrying the same value.
    request = _lines(b"GET / HTTP/1.1", b"Host: shop.example",
                     b"X-Forwarded-Host: evil.example")
    response = _lines(b"HTTP/1.1 302 Found", b"Location: https://evil.example/",
                      b"Vary: X-Forwarded-Host",
                      b"Cache-Control: public, max-age=3600", b"Content-Length: 0")
    cases.append(Case(
        name="benign_reflected_but_varied",
        raw=(request, response),
        kind="benign",
        expected=Expected(),
        description="Reflected host, but Vary puts it in the key: nothing to poison."))

    # The header is reflected, but the response forbids caching: no cache entry to
    # poison, so it is a false-positive guard, not a finding.
    request = _lines(b"GET / HTTP/1.1", b"Host: shop.example",
                     b"X-Forwarded-Host: evil.example")
    response = _lines(b"HTTP/1.1 302 Found", b"Location: https://evil.example/",
                      b"Cache-Control: no-store", b"Content-Length: 0")
    cases.append(Case(
        name="benign_reflected_but_no_store",
        raw=(request, response),
        kind="benign",
        expected=Expected(),
        description="Reflected host in a no-store response: uncacheable, so safe."))

    return cases


def all_cases() -> list[Case]:
    return smuggling_cases() + cache_cases() + benign_cases()
