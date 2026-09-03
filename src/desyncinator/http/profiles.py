"""Parser profiles: the choices a real HTTP implementation makes.

Request smuggling exists because "parse this HTTP message" has more than one
correct-looking answer. RFC 9112 is precise about most of it, but real proxies
and origins have historically differed on the ambiguous edges, and an attacker
only needs two hops in a chain to differ on one.

A Profile is that set of choices, named. The differential engine parses the same
bytes under two profiles and looks for a body boundary they disagree on. The
profiles here are not claims that a specific named vendor behaves this way today;
they are the documented behaviours from the request-smuggling literature, each of
which some deployed intermediary has exhibited.
"""

from __future__ import annotations

from dataclasses import dataclass

# When both Content-Length and Transfer-Encoding: chunked are present, RFC 9112
# section 6.3 says a proxy MUST use chunked and SHOULD strip Content-Length, or
# treat the message as unrecoverable. The attacks come from the parsers that did
# not. A profile declares which header it obeys when both are present.
PREFER_CHUNKED = "chunked"
PREFER_LENGTH = "length"
REJECT_BOTH = "reject"


@dataclass(frozen=True, slots=True)
class Profile:
    name: str

    # Which framing wins when both CL and TE:chunked are present and valid.
    on_both: str = PREFER_CHUNKED

    # Accept a Transfer-Encoding whose value is not exactly "chunked", for
    # example "chunked, chunked", "xchunked", "chunked ", or a value smuggled
    # past a header check with unusual whitespace. A strict parser reads only a
    # clean "chunked"; a lenient one still treats several of these as chunked.
    te_requires_exact_chunked: bool = True

    # Treat Transfer-Encoding as chunked when the token appears anywhere in a
    # comma list ("gzip, chunked" is legitimate; "chunked, gzip" is not, because
    # chunked must be last, and a lenient parser that accepts it desyncs).
    te_chunked_anywhere: bool = False

    # A second, conflicting Content-Length. RFC 9112 says reject; some parsers
    # take the first, some the last.
    on_duplicate_length: str = REJECT_BOTH   # or PREFER_LENGTH meaning "first"
    duplicate_length_takes_last: bool = False

    # Accept obsolete line folding (a header continued on a line starting with
    # whitespace). RFC 9112 says a server MUST reject it in a request; a proxy
    # that folds it back together can smuggle a header past one that does not.
    accept_obs_fold: bool = False

    # Accept whitespace between the header name and the colon ("Foo : bar").
    # Forbidden by the spec; a lenient parser that trims it can hide a header
    # from a strict one.
    accept_space_before_colon: bool = False

    # Accept a bare LF as a line terminator instead of CRLF. Origins written
    # against loose parsers do; a front-end that requires CRLF will frame the
    # body differently.
    accept_bare_lf: bool = False

    # Strip a leading byte-order-mark or other junk before the request line.
    tolerate_leading_junk: bool = False


# A conservative reading of RFC 9112: reject the ambiguous, obey chunked over
# length, require exact tokens and CRLF. What a careful modern origin does.
STRICT = Profile(
    name="strict",
    on_both=REJECT_BOTH,
    te_requires_exact_chunked=True,
    on_duplicate_length=REJECT_BOTH,
    accept_obs_fold=False,
    accept_space_before_colon=False,
    accept_bare_lf=False,
)

# A permissive front-end: obeys Content-Length when both are present, accepts
# loose chunked tokens and bare LF. The classic CL.TE front-end.
LENIENT_LENGTH = Profile(
    name="lenient-length",
    on_both=PREFER_LENGTH,
    te_requires_exact_chunked=False,
    te_chunked_anywhere=True,
    on_duplicate_length=PREFER_LENGTH,
    duplicate_length_takes_last=True,
    accept_obs_fold=True,
    accept_space_before_colon=True,
    accept_bare_lf=True,
    tolerate_leading_junk=True,
)

# A permissive back-end that prefers chunked but still accepts loose tokens and
# folding. The classic TE.CL / TE.TE back-end.
LENIENT_CHUNKED = Profile(
    name="lenient-chunked",
    on_both=PREFER_CHUNKED,
    te_requires_exact_chunked=False,
    te_chunked_anywhere=True,
    on_duplicate_length=PREFER_LENGTH,
    duplicate_length_takes_last=False,
    accept_obs_fold=True,
    accept_space_before_colon=True,
    accept_bare_lf=True,
)

PROFILES = {p.name: p for p in (STRICT, LENIENT_LENGTH, LENIENT_CHUNKED)}


def profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"unknown profile {name!r}; "
                         f"known: {', '.join(sorted(PROFILES))}")
