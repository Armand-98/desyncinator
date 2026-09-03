"""Differential engine tests, from bytes assembled by hand against RFC 9112.

Every payload here is written the way an attacker would write it, so a pass says
the engine agrees with the published taxonomy rather than with a capture. The
two properties that matter are opposite: the classic desyncs must be found and
named, and a request with one honest framing must produce nothing at all under
any pair of profiles, because a smuggling tool that cries wolf is not used.
"""

import pytest

from desyncinator.desync import (BOUNDARY, CL_CL, CL_TE, PARSE_SPLIT,
                                 SEVERITY_CRITICAL, SEVERITY_HIGH,
                                 SEVERITY_MEDIUM, TE_CL, TE_TE, Divergence,
                                 analyze, classify, scan)
from desyncinator.http.profiles import (LENIENT_CHUNKED, LENIENT_LENGTH,
                                        PREFER_LENGTH, PROFILES, STRICT, Profile)
from desyncinator.http.types import (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH,
                                     FRAMING_NONE, Header, Message)

ALL = list(PROFILES.values())


def req(*lines, body=b""):
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def headers_len(*lines):
    return len(req(*lines))


def pairs(profiles=ALL):
    return [(f, b) for f in profiles for b in profiles if f is not b]


# --- CL.TE -----------------------------------------------------------------

CL_TE_LINES = (b"POST /x HTTP/1.1", b"Host: h", b"Content-Length: 6",
               b"Transfer-Encoding: chunked")
CL_TE_DATA = req(*CL_TE_LINES, body=b"0\r\n\r\nG")


def test_cl_te_is_found_and_named():
    """Front-end obeys the length, back-end stops at the chunked terminator."""
    d = analyze(CL_TE_DATA, LENIENT_LENGTH, LENIENT_CHUNKED)
    assert d.kind == CL_TE
    assert d.severity == SEVERITY_CRITICAL
    assert (d.frontend, d.backend) == ("lenient-length", "lenient-chunked")
    assert d.frontend_body_end == headers_len(*CL_TE_LINES) + 6
    assert d.backend_body_end == headers_len(*CL_TE_LINES) + 5
    assert d.frontend_message.framing == FRAMING_CONTENT_LENGTH
    assert d.backend_message.framing == FRAMING_CHUNKED


def test_the_cl_te_prefix_is_what_follows_the_terminator_in_the_length_window():
    d = analyze(CL_TE_DATA, LENIENT_LENGTH, LENIENT_CHUNKED)
    assert d.smuggled_prefix == b"G"
    # Not reconstructed: it is the slice between the two offsets the parses gave.
    assert d.smuggled_prefix == CL_TE_DATA[d.backend_body_end:d.frontend_body_end]


def test_a_full_smuggled_request_survives_as_the_prefix():
    smuggled = b"GET /admin HTTP/1.1\r\nX: "
    data = req(b"POST / HTTP/1.1", b"Host: h",
               b"Content-Length: %d" % (5 + len(smuggled)),
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\n" + smuggled)
    d = analyze(data, LENIENT_LENGTH, LENIENT_CHUNKED)
    assert d.kind == CL_TE
    assert d.smuggled_prefix == smuggled


# --- TE.CL -----------------------------------------------------------------

TE_CL_BODY = b"8\r\nSMUGGLED\r\n0\r\n\r\n"
TE_CL_LINES = (b"POST / HTTP/1.1", b"Host: h", b"Content-Length: 3",
               b"Transfer-Encoding: chunked")
TE_CL_DATA = req(*TE_CL_LINES, body=TE_CL_BODY)


def test_te_cl_is_the_same_headers_with_the_roles_reversed():
    d = analyze(TE_CL_DATA, LENIENT_CHUNKED, LENIENT_LENGTH)
    assert d.kind == TE_CL
    assert d.severity == SEVERITY_CRITICAL
    assert d.frontend_message.framing == FRAMING_CHUNKED
    assert d.backend_message.framing == FRAMING_CONTENT_LENGTH
    # The back-end consumed only "8\r\n" and starts its next request at the
    # chunk data the front-end already forwarded.
    assert d.smuggled_prefix == b"SMUGGLED\r\n0\r\n\r\n"


def test_the_same_bytes_are_cl_te_or_te_cl_depending_on_which_hop_is_first():
    assert analyze(TE_CL_DATA, LENIENT_CHUNKED, LENIENT_LENGTH).kind == TE_CL
    assert analyze(TE_CL_DATA, LENIENT_LENGTH, LENIENT_CHUNKED).kind == CL_TE


def test_a_back_end_that_wants_more_than_the_front_end_forwards_has_no_prefix():
    """The back-end blocks and swallows the next real request instead."""
    d = analyze(CL_TE_DATA, LENIENT_CHUNKED, LENIENT_LENGTH)
    assert d.kind == TE_CL
    assert d.backend_body_end > d.frontend_body_end
    assert d.smuggled_prefix == b""
    assert "consumes the next request" in d.detail


# --- TE.TE -----------------------------------------------------------------

TE_TE_BODY = b"7\r\nGPOST /\r\n0\r\n\r\n"


@pytest.mark.parametrize("te", [b"Transfer-Encoding: xchunked",
                                b"Transfer-Encoding: chunked, gzip"])
def test_te_te_an_obfuscated_token_only_one_hop_honours(te):
    """Both hops see a Transfer-Encoding; only the lenient one frames chunked."""
    lines = (b"POST / HTTP/1.1", b"Host: h", te)
    data = req(*lines, body=TE_TE_BODY)
    d = analyze(data, LENIENT_CHUNKED, STRICT)
    assert d.kind == TE_TE
    assert d.severity == SEVERITY_CRITICAL
    assert d.frontend_message.framing == FRAMING_CHUNKED
    assert d.backend_message.framing == FRAMING_NONE
    # The strict back-end ended the request at the headers, so everything the
    # front-end forwarded as a body is the start of its next request.
    assert d.smuggled_prefix == TE_TE_BODY
    assert d.backend_body_end == headers_len(*lines)


def test_te_te_holds_with_the_roles_reversed():
    lines = (b"POST / HTTP/1.1", b"Host: h", b"Transfer-Encoding: xchunked")
    d = analyze(req(*lines, body=TE_TE_BODY), STRICT, LENIENT_CHUNKED)
    assert d.kind == TE_TE
    assert d.smuggled_prefix == b""


def test_a_clean_chunked_token_with_a_length_is_named_for_the_framings():
    """CL.TE, not TE.TE: nothing tricked either hop about the token itself."""
    assert analyze(CL_TE_DATA, LENIENT_LENGTH, LENIENT_CHUNKED).kind == CL_TE


# --- CL.CL -----------------------------------------------------------------

CL_CL_LINES = (b"POST / HTTP/1.1", b"Host: h", b"Content-Length: 3",
               b"Content-Length: 8")
CL_CL_DATA = req(*CL_CL_LINES, body=b"AAABBBBB")


def test_cl_cl_two_lengths_resolved_differently():
    d = analyze(CL_CL_DATA, LENIENT_LENGTH, LENIENT_CHUNKED)
    assert d.kind == CL_CL
    assert d.severity == SEVERITY_HIGH
    assert d.frontend_message.body == b"AAABBBBB"   # takes the last
    assert d.backend_message.body == b"AAA"        # takes the first
    assert d.smuggled_prefix == b"BBBBB"


def test_identical_duplicate_lengths_are_not_a_divergence():
    data = req(b"POST / HTTP/1.1", b"Content-Length: 5", b"Content-Length: 5",
               body=b"hello")
    assert scan(data) == []


# --- one hop parses what the other refuses ---------------------------------

def test_parse_split_when_the_front_end_rejects():
    d = analyze(CL_TE_DATA, STRICT, LENIENT_LENGTH)
    assert d.kind == PARSE_SPLIT
    assert d.severity == SEVERITY_MEDIUM
    assert d.frontend_body_end is None
    assert d.frontend_message is None
    assert d.backend_body_end == headers_len(*CL_TE_LINES) + 6
    assert "rejected it" in d.detail and "both" in d.detail
    assert d.smuggled_prefix == b""


def test_parse_split_when_the_back_end_rejects():
    d = analyze(CL_TE_DATA, LENIENT_LENGTH, STRICT)
    assert d.kind == PARSE_SPLIT
    assert d.backend_body_end is None
    assert d.frontend_message.framing == FRAMING_CONTENT_LENGTH


def test_a_message_both_hops_refuse_is_not_a_divergence():
    assert analyze(b"not http at all\r\n\r\n", STRICT, LENIENT_LENGTH) is None
    assert scan(b"not http at all\r\n\r\n") == []


def test_obsolete_folding_splits_the_parse():
    data = req(b"POST / HTTP/1.1", b"X-Pad: pad", b"\tContent-Length: 4",
               body=b"body")
    d = analyze(data, LENIENT_CHUNKED, STRICT)
    assert d.kind == PARSE_SPLIT
    assert "folding" in d.detail


# --- the false-positive guard, the property that matters most --------------

CLEAN = {
    "content-length post": req(b"POST /f HTTP/1.1", b"Host: h",
                               b"Content-Length: 5", body=b"hello"),
    "chunked post": req(b"POST /f HTTP/1.1", b"Host: h",
                        b"Transfer-Encoding: chunked",
                        body=b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
    "get with no body": req(b"GET / HTTP/1.1", b"Host: h"),
    "empty body": req(b"POST / HTTP/1.1", b"Host: h", b"Content-Length: 0"),
    "gzip then chunked": req(b"POST / HTTP/1.1", b"Host: h",
                             b"Transfer-Encoding: gzip, chunked",
                             body=b"0\r\n\r\n"),
    "pipelined": req(b"POST / HTTP/1.1", b"Host: h", b"Content-Length: 5",
                     body=b"hello") + req(b"GET /next HTTP/1.1", b"Host: h"),
}


@pytest.mark.parametrize("name", sorted(CLEAN))
def test_a_single_framing_diverges_under_no_pair(name):
    data = CLEAN[name]
    for frontend, backend in pairs():
        assert analyze(data, frontend, backend) is None, (name, frontend.name,
                                                          backend.name)
    assert scan(data) == []


@pytest.mark.parametrize("name", sorted(CLEAN))
def test_clean_requests_end_at_the_same_byte_everywhere(name):
    """The guard behind the guard: agreement is real, not an unparsed input."""
    ends = {p.name: analyze(CLEAN[name], p, STRICT) for p in ALL}
    assert set(ends.values()) == {None}


# --- classify on its own ---------------------------------------------------

def msg(framing, body_end, headers=()):
    return Message(is_request=True, method="POST", target="/", version="HTTP/1.1",
                   headers=tuple(headers), framing=framing, body_end=body_end)


def header(name, value):
    return Header(name, value, b"%s: %s\r\n" % (name.encode(), value.encode()))


def test_classify_names_each_framing_pair():
    length = msg(FRAMING_CONTENT_LENGTH, 40, [header("Content-Length", "6"),
                                              header("Transfer-Encoding", "chunked")])
    chunked = msg(FRAMING_CHUNKED, 39, [header("Content-Length", "6"),
                                        header("Transfer-Encoding", "chunked")])
    assert classify(length, chunked) == CL_TE
    assert classify(chunked, length) == TE_CL


def test_classify_needs_a_second_length_header_to_call_it_cl_cl():
    two = [header("Content-Length", "3"), header("Content-Length", "8")]
    assert classify(msg(FRAMING_CONTENT_LENGTH, 30, two),
                    msg(FRAMING_CONTENT_LENGTH, 25, two)) == CL_CL
    one = [header("Content-Length", "3")]
    assert classify(msg(FRAMING_CONTENT_LENGTH, 30, one),
                    msg(FRAMING_CONTENT_LENGTH, 25, one)) == BOUNDARY


def test_classify_falls_back_to_boundary():
    """Same framing, different offset: still a desync, just not a named one."""
    assert classify(msg(FRAMING_CHUNKED, 60), msg(FRAMING_CHUNKED, 44)) == BOUNDARY
    assert classify(msg(FRAMING_NONE, 20),
                    msg(FRAMING_CONTENT_LENGTH, 25)) == BOUNDARY


def test_classify_reserves_te_te_for_an_ignored_obfuscated_token():
    fooled = msg(FRAMING_NONE, 20, [header("Transfer-Encoding", "xchunked")])
    honoured = msg(FRAMING_CHUNKED, 40, [header("Transfer-Encoding", "xchunked")])
    assert classify(honoured, fooled) == TE_TE
    assert classify(fooled, honoured) == TE_TE

    clean = [header("Transfer-Encoding", "chunked")]
    assert classify(msg(FRAMING_NONE, 20, clean),
                    msg(FRAMING_CHUNKED, 40, clean)) == BOUNDARY


def test_classify_treats_space_before_the_colon_as_obfuscation():
    raw = Header("Transfer-Encoding", "chunked", b"Transfer-Encoding : chunked\r\n")
    assert classify(msg(FRAMING_CHUNKED, 40, [raw]),
                    msg(FRAMING_NONE, 20, [raw])) == TE_TE


def test_classify_calls_a_missing_parse_a_split():
    assert classify(None, msg(FRAMING_CHUNKED, 40)) == PARSE_SPLIT
    assert classify(msg(FRAMING_CHUNKED, 40), None) == PARSE_SPLIT


# --- scan ------------------------------------------------------------------

def test_scan_reports_the_worst_finding_first():
    found = scan(CL_TE_DATA)
    assert found[0].kind == CL_TE
    assert found[0].smuggled_prefix == b"G"
    ranks = [{SEVERITY_CRITICAL: 3, SEVERITY_HIGH: 2, SEVERITY_MEDIUM: 1}[d.severity]
             for d in found]
    assert ranks == sorted(ranks, reverse=True)
    assert [d.kind for d in found[:2]] == [CL_TE, TE_CL]


def test_scan_deduplicates_the_same_divergence_from_different_pairs():
    """Four ordered pairs find this TE.TE; it is one finding in each direction."""
    lines = (b"POST / HTTP/1.1", b"Host: h", b"Transfer-Encoding: xchunked")
    data = req(*lines, body=TE_TE_BODY)
    raw = [analyze(data, f, b) for f, b in pairs()]
    assert sum(1 for d in raw if d is not None) == 4

    found = scan(data)
    assert [d.kind for d in found] == [TE_TE, TE_TE]
    assert found[0].smuggled_prefix == TE_TE_BODY      # the exploitable direction
    assert found[1].smuggled_prefix == b""
    assert {(d.frontend_body_end, d.backend_body_end) for d in found} == {
        (headers_len(*lines) + len(TE_TE_BODY), headers_len(*lines)),
        (headers_len(*lines), headers_len(*lines) + len(TE_TE_BODY)),
    }


def test_scan_takes_a_profile_list():
    found = scan(CL_TE_DATA, profiles=[LENIENT_LENGTH, LENIENT_CHUNKED])
    assert [d.kind for d in found] == [CL_TE, TE_CL]


def test_scan_of_a_custom_profile_pair_that_differs_only_on_duplicate_length():
    first = Profile(name="first", on_duplicate_length=PREFER_LENGTH,
                    duplicate_length_takes_last=False)
    last = Profile(name="last", on_duplicate_length=PREFER_LENGTH,
                   duplicate_length_takes_last=True)
    found = scan(CL_CL_DATA, profiles=[first, last])
    assert [d.kind for d in found] == [CL_CL, CL_CL]
    assert found[0].smuggled_prefix == b"BBBBB"


def test_scan_returns_divergences_only():
    assert all(isinstance(d, Divergence) for d in scan(CL_TE_DATA))


# --- hostile input ---------------------------------------------------------

HOSTILE = [
    b"",
    b"\x00" * 1000,
    b"GET",
    b"GET / HTTP/1.1\r\n",
    b"\r\n\r\n\r\n",
    req(b"POST / HTTP/1.1", b"Content-Length: 99999999999999999999", body=b"x"),
    req(b"POST / HTTP/1.1", b"Content-Length: -1", body=b"x"),
    req(b"POST / HTTP/1.1", b"Transfer-Encoding: chunked",
        body=b"ffffffffffffffff\r\nx"),
    req(b"POST / HTTP/1.1", b"Transfer-Encoding: chunked", body=b"0" * 5000),
    req(b"POST / HTTP/1.1", *[b"X-%d: v" % i for i in range(2000)]),
    b"GET / HTTP/1.1\nHost: x\n\n",
    b"POST / HTTP/1.1\r\nTransfer-Encoding:\r\nContent-Length: 1\r\n\r\nA",
    b"\xef\xbb\xbfGET / HTTP/1.1\r\nHost: h\r\n\r\n",
]


@pytest.mark.parametrize("data", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_bytes_never_escape_as_an_exception(data):
    for frontend, backend in pairs():
        result = analyze(data, frontend, backend)
        assert result is None or isinstance(result, Divergence)
    assert isinstance(scan(data), list)


@pytest.mark.parametrize("cut", range(0, len(CL_TE_DATA), 7))
def test_every_truncation_of_an_attack_is_still_handled(cut):
    assert isinstance(scan(CL_TE_DATA[:cut]), list)


def test_offsets_always_lie_inside_the_analysed_bytes():
    for data in [CL_TE_DATA, TE_CL_DATA, CL_CL_DATA] + HOSTILE:
        for d in scan(data):
            for end in (d.frontend_body_end, d.backend_body_end):
                assert end is None or 0 <= end <= len(data)
            assert d.smuggled_prefix in data
