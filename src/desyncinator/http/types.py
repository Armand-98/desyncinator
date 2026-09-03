"""Types shared across the tool.

The desync engine, the cache analysis and the report all speak in these, so how
a message was parsed stays separate from what is concluded about it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ParseError(Exception):
    """A message could not be parsed under the given profile.

    That a message fails under one profile and parses under another is the whole
    point of this tool, so a ParseError is a result, not a bug.
    """


# How a parser decided where the body ends. The disagreement this tool looks for
# is two hops choosing different frameworks for the same bytes.
FRAMING_CONTENT_LENGTH = "content-length"
FRAMING_CHUNKED = "chunked"
FRAMING_UNTIL_CLOSE = "until-close"    # response with neither, body ends at EOF
FRAMING_NONE = "none"                  # no body permitted or expected


@dataclass(frozen=True, slots=True)
class Header:
    """One header field, keeping the bytes as they appeared.

    Case, surrounding whitespace and duplication are all load-bearing for
    smuggling, so nothing is normalised away at parse time. The name is exposed
    lowercased for lookup and raw for analysis.
    """

    name: str            # as written
    value: str           # as written, without the surrounding optional whitespace
    raw: bytes = b""     # the whole field line, for showing the reader the truth

    @property
    def lower(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Message:
    """A parsed HTTP/1.1 message, request or response.

    body_end is the offset in the original bytes where this parser decided the
    message ends. Two profiles returning different body_end for the same input
    is a desync.
    """

    is_request: bool
    method: str = ""
    target: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: tuple[Header, ...] = ()
    body: bytes = b""
    framing: str = FRAMING_NONE
    body_end: int = 0          # offset one past the last body byte
    trailing: bytes = b""      # bytes after this message in the buffer
    profile: str = ""          # the profile that produced this parse

    def get_all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [h.value for h in self.headers if h.lower == wanted]

    def get(self, name: str) -> str | None:
        values = self.get_all(name)
        return values[0] if values else None

    def count(self, name: str) -> int:
        wanted = name.lower()
        return sum(1 for h in self.headers if h.lower == wanted)


# The two ends of a proxy chain, named so a finding reads the way an analyst
# thinks about it.
FRONTEND = "frontend"
BACKEND = "backend"
