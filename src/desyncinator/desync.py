"""The differential engine: the same bytes, two profiles, two boundaries.

A front-end and a back-end each parse the request they are given. Neither is
wrong about it in a way it could detect on its own; they simply resolved an
ambiguity differently. Where the front-end ends the message and where the
back-end ends it are two offsets, and the bytes between them are a request the
back-end will run that the front-end never saw. That is request smuggling, and
it is all this module computes: parse under two profiles, compare body_end,
name the disagreement.

The classes are the taxonomy an analyst already thinks in: CL.TE, TE.CL, TE.TE,
CL.CL, plus a boundary catch-all and the split where one hop parses what the
other rejects. Nothing here reconstructs an attack; the smuggled prefix is a
slice of the caller's own bytes, taken between the two offsets the two parses
actually produced.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .http.message import parse
from .http.profiles import PROFILES, Profile
from .http.types import (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH, FRAMING_NONE,
                         Message, ParseError)

# Front-end framed by Content-Length, back-end by chunked. The back-end stops at
# the chunked terminator and reads the rest of the length window as a request.
CL_TE = "CL.TE"
# The mirror: front-end chunked, back-end length. The back-end stops short and
# the tail of the chunked body becomes its next request.
TE_CL = "TE.CL"
# Both hops read a Transfer-Encoding header, one was fooled by an obfuscated
# token into not framing chunked at all.
TE_TE = "TE.TE"
# Two Content-Length headers, resolved to different values.
CL_CL = "CL.CL"
# Any other pair of body_end offsets that do not agree.
BOUNDARY = "boundary"
# One hop parses the message, the other refuses it. Exploitable in both
# directions: what one hop forwards, the other rejects or never sees.
PARSE_SPLIT = "parse-split"

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

SEVERITY = {
    CL_TE: SEVERITY_CRITICAL,
    TE_CL: SEVERITY_CRITICAL,
    TE_TE: SEVERITY_CRITICAL,
    CL_CL: SEVERITY_HIGH,
    BOUNDARY: SEVERITY_HIGH,
    PARSE_SPLIT: SEVERITY_MEDIUM,
}

_RANK = {SEVERITY_CRITICAL: 3, SEVERITY_HIGH: 2, SEVERITY_MEDIUM: 1}


@dataclass(frozen=True, slots=True)
class Divergence:
    """One disagreement about where the request ends.

    frontend_body_end and backend_body_end are offsets into the bytes that were
    analysed; either is None when that hop rejected the message. Both parses are
    kept so a reader can see what each hop believed rather than take the verdict
    on trust.
    """

    kind: str
    severity: str
    frontend: str
    backend: str
    frontend_body_end: int | None
    backend_body_end: int | None
    smuggled_prefix: bytes
    detail: str
    frontend_message: Message | None = None
    backend_message: Message | None = None


def analyze(data: bytes, frontend: Profile, backend: Profile) -> Divergence | None:
    """Compare one request under two profiles; None when the hops agree."""
    front, front_error = _parse(data, frontend)
    back, back_error = _parse(data, backend)

    if front is None and back is None:
        return None                     # both hops refuse it: nothing to smuggle
    if front is None or back is None:
        return _split(frontend, backend, front, back, front_error, back_error)
    if front.body_end == back.body_end and front.framing == back.framing:
        return None

    kind = classify(front, back)
    prefix = _prefix(data, front.body_end, back.body_end)
    fate = (f"the {len(prefix)}-byte tail becomes the start of the back-end's "
            f"next request" if prefix else
            "the back-end reads past what the front-end forwards and consumes "
            "the next request on the connection")
    detail = (f"{frontend.name} framed the body as {front.framing} ending at "
              f"byte {front.body_end}, {backend.name} as {back.framing} ending "
              f"at byte {back.body_end}; {fate}")
    return Divergence(kind=kind, severity=SEVERITY[kind], frontend=frontend.name,
                      backend=backend.name, frontend_body_end=front.body_end,
                      backend_body_end=back.body_end, smuggled_prefix=prefix,
                      detail=detail, frontend_message=front, backend_message=back)


def classify(front_msg: Message | None, back_msg: Message | None) -> str:
    """Name the disagreement between two parses of one request."""
    if front_msg is None or back_msg is None:
        return PARSE_SPLIT

    front, back = front_msg.framing, back_msg.framing
    if front == back:
        if front == FRAMING_CONTENT_LENGTH and (
                front_msg.count("content-length") > 1
                or back_msg.count("content-length") > 1):
            return CL_CL
        return BOUNDARY

    if FRAMING_CHUNKED in (front, back):
        ignored = back_msg if front == FRAMING_CHUNKED else front_msg
        # A hop holding a Transfer-Encoding header and still framing no body at
        # all did not read the token as chunked: the TE.TE token trick. With a
        # Content-Length also in play the primitive is length against chunked
        # however the token was read, so it is named for that instead.
        both_saw_te = (front_msg.count("transfer-encoding")
                       and back_msg.count("transfer-encoding"))
        if (ignored.framing == FRAMING_NONE and both_saw_te
                and _te_obfuscated(ignored)):
            return TE_TE
        if front == FRAMING_CONTENT_LENGTH:
            return CL_TE
        if back == FRAMING_CONTENT_LENGTH:
            return TE_CL
    return BOUNDARY


def scan(data: bytes,
         profiles: Sequence[Profile] | None = None) -> list[Divergence]:
    """Every ordered pair of profiles, worst finding first.

    Ordered, because which hop is in front decides what is exploitable: the same
    two parsers swapped give a different attack, or none.
    """
    candidates = list(PROFILES.values()) if profiles is None else list(profiles)
    found: dict[tuple[str, int | None, int | None], Divergence] = {}
    for frontend in candidates:
        for backend in candidates:
            if frontend is backend:
                continue
            divergence = analyze(data, frontend, backend)
            if divergence is None:
                continue
            # One kind at one pair of offsets is one finding, however many
            # profile pairs happen to produce it.
            key = (divergence.kind, divergence.frontend_body_end,
                   divergence.backend_body_end)
            found.setdefault(key, divergence)
    return sorted(found.values(), key=_worst_first)


def _parse(data: bytes, profile: Profile) -> tuple[Message | None, str]:
    try:
        return parse(data, profile), ""
    except ParseError as error:
        return None, str(error)


def _split(frontend: Profile, backend: Profile, front: Message | None,
           back: Message | None, front_error: str, back_error: str) -> Divergence:
    if front is not None:
        parsed, accepted, rejected, error = front, frontend, backend, back_error
    else:
        parsed, accepted, rejected, error = back, backend, frontend, front_error
    detail = (f"{accepted.name} parsed the request as {parsed.framing} ending at "
              f"byte {parsed.body_end}, {rejected.name} rejected it: {error}")
    return Divergence(
        kind=PARSE_SPLIT, severity=SEVERITY[PARSE_SPLIT], frontend=frontend.name,
        backend=backend.name,
        frontend_body_end=front.body_end if front is not None else None,
        backend_body_end=back.body_end if back is not None else None,
        # Nothing is smuggled past a hop that refuses the message; the exposure
        # is that the two hops disagree about whether the request exists at all.
        smuggled_prefix=b"", detail=detail, frontend_message=front,
        backend_message=back)


def _prefix(data: bytes, front_end: int, back_end: int) -> bytes:
    """The bytes the front-end forwarded that the back-end did not consume."""
    if back_end >= front_end:
        return b""
    return data[back_end:front_end]


def _te_obfuscated(message: Message) -> bool:
    """True when a Transfer-Encoding line is not a plain, conforming chunked."""
    headers = [h for h in message.headers if h.lower == "transfer-encoding"]
    if not headers:
        return False
    for header in headers:
        name = header.raw.split(b":", 1)[0]
        if name != name.strip():                  # "Transfer-Encoding : chunked"
            return True
    tokens = [t.strip() for t in ",".join(h.value for h in headers).split(",")]
    # RFC 9112 6.1: chunked must be the final coding, and every token non-empty.
    return tokens[-1].lower() != "chunked" or not all(tokens)


def _worst_first(divergence: Divergence) -> tuple:
    return (-_RANK[divergence.severity], -len(divergence.smuggled_prefix),
            divergence.kind, divergence.frontend, divergence.backend)
