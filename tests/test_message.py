"""HTTP message parser tests, from bytes assembled against RFC 9112.

The load-bearing property is not that the parser is correct in the abstract, but
that it is correct-per-profile: the same bytes must yield different framing under
profiles that disagree, because that difference is the entire subject of the
tool.
"""

import pytest

from desyncinator.http.message import parse
from desyncinator.http.profiles import (LENIENT_CHUNKED, LENIENT_LENGTH, STRICT,
                                        Profile)
from desyncinator.http.types import (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH,
                                      FRAMING_NONE, FRAMING_UNTIL_CLOSE, ParseError)


def req(*lines, body=b""):
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


# --- the basics ------------------------------------------------------------

def test_a_simple_request():
    m = parse(req(b"GET /path HTTP/1.1", b"Host: example.com"), STRICT)
    assert m.is_request
    assert (m.method, m.target, m.version) == ("GET", "/path", "HTTP/1.1")
    assert m.get("host") == "example.com"
    assert m.framing == FRAMING_NONE
    assert m.body == b""


def test_content_length_frames_the_body():
    m = parse(req(b"POST / HTTP/1.1", b"Content-Length: 5", body=b"hello!!"), STRICT)
    assert m.framing == FRAMING_CONTENT_LENGTH
    assert m.body == b"hello"
    assert m.trailing == b"!!"


def test_chunked_frames_the_body():
    data = req(b"POST / HTTP/1.1", b"Transfer-Encoding: chunked",
               body=b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
    m = parse(data, STRICT)
    assert m.framing == FRAMING_CHUNKED
    assert m.body == b"Wikipedia"
    assert m.trailing == b""


def test_headers_keep_their_case_and_order_and_duplication():
    m = parse(req(b"GET / HTTP/1.1", b"X-A: 1", b"x-a: 2", b"Host: h"), STRICT)
    assert m.get_all("x-a") == ["1", "2"]
    assert m.count("x-a") == 2
    assert m.headers[0].name == "X-A"


def test_a_response_is_parsed():
    data = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    m = parse(data, STRICT, is_request=False)
    assert not m.is_request
    assert m.status == 200 and m.reason == "OK"
    assert m.body == b"hi"


def test_a_response_with_no_framing_reads_until_close():
    data = b"HTTP/1.1 200 OK\r\n\r\nbody bytes"
    m = parse(data, STRICT, is_request=False)
    assert m.framing == FRAMING_UNTIL_CLOSE
    assert m.body == b"body bytes"


@pytest.mark.parametrize("status", [204, 304])
def test_bodyless_responses_have_no_body(status):
    data = b"HTTP/1.1 %d x\r\n\r\n" % status
    m = parse(data, STRICT, is_request=False)
    assert m.framing == FRAMING_NONE


# --- framing decisions are the profile's, not the parser's -----------------

def test_both_headers_are_rejected_by_strict():
    data = req(b"POST / HTTP/1.1", b"Content-Length: 6",
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\nG")
    with pytest.raises(ParseError, match="both"):
        parse(data, STRICT)


def test_both_headers_prefer_length_under_a_length_profile():
    data = req(b"POST / HTTP/1.1", b"Content-Length: 6",
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\nG")
    m = parse(data, LENIENT_LENGTH)
    assert m.framing == FRAMING_CONTENT_LENGTH
    assert m.body == b"0\r\n\r\nG"


def test_both_headers_prefer_chunked_under_a_chunked_profile():
    data = req(b"POST / HTTP/1.1", b"Content-Length: 6",
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\nG")
    m = parse(data, LENIENT_CHUNKED)
    assert m.framing == FRAMING_CHUNKED
    assert m.body == b""
    assert m.trailing == b"G"


def test_the_same_bytes_desync_across_two_profiles():
    """The property the whole tool is built on."""
    data = req(b"POST / HTTP/1.1", b"Content-Length: 6",
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\nG")
    front = parse(data, LENIENT_LENGTH)
    back = parse(data, LENIENT_CHUNKED)
    assert front.body_end != back.body_end
    assert back.trailing == b"G" and front.trailing == b""


# --- conflicting Content-Length --------------------------------------------

def test_conflicting_content_length_is_rejected_by_strict():
    with pytest.raises(ParseError, match="conflicting"):
        parse(req(b"POST / HTTP/1.1", b"Content-Length: 5",
                  b"Content-Length: 6", body=b"hello!"), STRICT)


def test_duplicate_content_length_takes_first_or_last_by_profile():
    data = req(b"POST / HTTP/1.1", b"Content-Length: 3",
               b"Content-Length: 5", body=b"hello")
    takes_last = parse(data, LENIENT_LENGTH)
    assert takes_last.body == b"hello"
    first = Profile(name="first", on_duplicate_length="length",
                    duplicate_length_takes_last=False)
    assert parse(data, first).body == b"hel"


def test_identical_duplicate_content_length_is_fine():
    m = parse(req(b"POST / HTTP/1.1", b"Content-Length: 5",
                  b"Content-Length: 5", body=b"hello"), STRICT)
    assert m.body == b"hello"


# --- transfer-encoding token games -----------------------------------------

def test_strict_requires_chunked_to_be_the_last_token():
    """gzip,chunked is legal; chunked,gzip is not, and a parser that accepts it
    frames a body a strict parser will not."""
    ok = req(b"POST / HTTP/1.1", b"Transfer-Encoding: gzip, chunked",
             body=b"0\r\n\r\n")
    assert parse(ok, STRICT).framing == FRAMING_CHUNKED

    bad = req(b"POST / HTTP/1.1", b"Transfer-Encoding: chunked, gzip",
              body=b"nope")
    assert parse(bad, STRICT).framing == FRAMING_NONE


def test_lenient_accepts_a_fuzzy_chunked_token():
    data = req(b"POST / HTTP/1.1", b"Transfer-Encoding: xchunked",
               body=b"0\r\n\r\n")
    assert parse(data, STRICT).framing == FRAMING_NONE
    assert parse(data, LENIENT_CHUNKED).framing == FRAMING_CHUNKED


def test_multiple_transfer_encoding_headers_combine():
    data = req(b"POST / HTTP/1.1", b"Transfer-Encoding: gzip",
               b"Transfer-Encoding: chunked", body=b"0\r\n\r\n")
    assert parse(data, STRICT).framing == FRAMING_CHUNKED


# --- obsolete syntax gated by profile --------------------------------------

def test_obsolete_line_folding():
    data = req(b"GET / HTTP/1.1", b"X-Long: one", b"  two")
    with pytest.raises(ParseError, match="folding"):
        parse(data, STRICT)
    folded = parse(data, LENIENT_CHUNKED)
    assert folded.get("x-long") == "one two"


def test_space_before_colon():
    data = req(b"GET / HTTP/1.1", b"Host : example.com")
    with pytest.raises(ParseError, match="whitespace in header name"):
        parse(data, STRICT)
    assert parse(data, LENIENT_LENGTH).get("host") == "example.com"


def test_bare_lf_line_endings():
    data = b"GET / HTTP/1.1\nHost: x\n\n"
    with pytest.raises(ParseError, match="bare LF"):
        parse(data, STRICT)
    assert parse(data, LENIENT_LENGTH).get("host") == "x"


# --- hostile input ---------------------------------------------------------

@pytest.mark.parametrize("data", [
    b"", b"GET", b"GET /\r\n", b"GET / HTTP/1.1\r\nbadheader\r\n\r\n",
    b"GET / HTTP/1.1\r\n: emptyname\r\n\r\n",
    b"not a request line at all\r\n\r\n",
])
def test_malformed_requests_raise_parse_error(data):
    with pytest.raises(ParseError):
        parse(data, STRICT)


def test_content_length_past_the_data_is_refused():
    with pytest.raises(ParseError, match="past the data"):
        parse(req(b"POST / HTTP/1.1", b"Content-Length: 1000", body=b"short"),
              STRICT)


def test_non_numeric_content_length():
    with pytest.raises(ParseError, match="non-numeric"):
        parse(req(b"POST / HTTP/1.1", b"Content-Length: five", body=b"hello"),
              STRICT)


def test_a_header_line_that_never_ends():
    with pytest.raises(ParseError, match="without a terminator"):
        parse(b"GET / HTTP/1.1\r\nHost: unterminated", STRICT)


def test_the_message_records_which_profile_parsed_it():
    m = parse(req(b"GET / HTTP/1.1", b"Host: h"), STRICT)
    assert m.profile == "strict"
