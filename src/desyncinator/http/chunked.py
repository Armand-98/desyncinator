"""Chunked transfer-coding, decoded under a profile.

RFC 9112 section 7.1 defines chunked as a sequence of size-prefixed chunks
ending in a zero-size chunk. It is simple until you ask what a parser does with
the malformed cases, and that is exactly what request smuggling turns on: a
front-end and a back-end that end the body at different bytes.

decode returns where the body ended, so the differential engine can compare the
boundary two profiles computed rather than only the bytes they decoded.
"""

from __future__ import annotations

from dataclasses import dataclass

from .profiles import Profile
from .types import ParseError

# A single chunk larger than this, or a body of more chunks than this, is not a
# real message and is refused before it can be used to allocate.
MAX_CHUNK_BYTES = 1 << 30
MAX_CHUNKS = 1 << 20


@dataclass(frozen=True, slots=True)
class Chunked:
    body: bytes         # the decoded body
    end: int            # offset in the source one past the terminating chunk
    complete: bool      # the zero chunk and its trailer were actually seen


def decode(data: bytes, start: int, profile: Profile) -> Chunked:
    """Decode a chunked body beginning at start.

    A strict profile rejects a chunk size with surrounding whitespace, leading
    plus, or a bare LF terminator. A lenient one accepts them, which is how two
    hops end up reading different chunk sizes from the same bytes.
    """
    out = bytearray()
    offset = start
    chunks = 0

    while True:
        if chunks > MAX_CHUNKS:
            raise ParseError("too many chunks")
        chunks += 1

        line, offset = _read_line(data, offset, profile)
        size = _chunk_size(line, profile)

        if size == 0:
            # The last chunk is followed by an optional trailer section and a
            # final empty line. A lenient parser that stops at the first CRLF
            # after the zero, and a strict one that consumes the trailer, end
            # the message at different offsets: a smuggling primitive.
            offset = _consume_trailers(data, offset, profile)
            return Chunked(bytes(out), offset, complete=True)

        if size > MAX_CHUNK_BYTES:
            raise ParseError(f"chunk claims {size} bytes")
        if offset + size > len(data):
            raise ParseError("chunk longer than the data")

        out += data[offset:offset + size]
        offset += size
        offset = _require_crlf(data, offset, profile)


def _read_line(data: bytes, offset: int, profile: Profile) -> tuple[bytes, int]:
    end = data.find(b"\n", offset)
    if end == -1:
        raise ParseError("chunk header without a line ending")
    line = data[offset:end]
    if line.endswith(b"\r"):
        return line[:-1], end + 1
    if profile.accept_bare_lf:
        return line, end + 1
    raise ParseError("chunk header terminated by bare LF")


def _chunk_size(line: bytes, profile: Profile) -> int:
    # A chunk line is the hex size, optionally followed by ";ext=val".
    size_field = line.split(b";", 1)[0]
    if not profile.te_requires_exact_chunked:
        size_field = size_field.strip()
    if size_field != size_field.strip():
        raise ParseError("whitespace around chunk size")
    if not size_field:
        raise ParseError("empty chunk size")
    if size_field[:1] in (b"+", b"-"):
        raise ParseError("signed chunk size")
    # int(base=16) accepts a leading 0x under some readings; forbid it, since a
    # parser that reads 0x10 as 16 and another that reads it as 0 desync.
    if size_field[:2].lower() == b"0x":
        raise ParseError("0x prefix on chunk size")
    try:
        return int(size_field, 16)
    except ValueError:
        raise ParseError(f"non-hex chunk size {size_field!r}")


def _require_crlf(data: bytes, offset: int, profile: Profile) -> int:
    if data[offset:offset + 2] == b"\r\n":
        return offset + 2
    if profile.accept_bare_lf and data[offset:offset + 1] == b"\n":
        return offset + 1
    raise ParseError("chunk data not followed by CRLF")


def _consume_trailers(data: bytes, offset: int, profile: Profile) -> int:
    """Consume the trailer section after the zero chunk, up to the final line."""
    while True:
        line, offset = _read_line(data, offset, profile)
        if line == b"":
            return offset
