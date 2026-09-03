"""Chunked decoder tests, from bytes built against RFC 9112 section 7.1."""

import pytest

from desyncinator.http.chunked import decode
from desyncinator.http.profiles import LENIENT_CHUNKED, STRICT
from desyncinator.http.types import ParseError


def test_a_normal_chunked_body():
    data = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    result = decode(data, 0, STRICT)
    assert result.body == b"Wikipedia"
    assert result.end == len(data)
    assert result.complete


def test_chunk_extensions_are_ignored():
    data = b"5;name=value\r\nhello\r\n0\r\n\r\n"
    assert decode(data, 0, STRICT).body == b"hello"


def test_a_trailer_section_is_consumed():
    data = b"3\r\nabc\r\n0\r\nX-Checksum: 7\r\n\r\n"
    result = decode(data, 0, STRICT)
    assert result.body == b"abc"
    assert result.end == len(data)


def test_the_boundary_is_reported_so_trailing_bytes_are_visible():
    data = b"0\r\n\r\nSMUGGLED"
    result = decode(data, 0, STRICT)
    assert result.body == b""
    assert result.end == len(b"0\r\n\r\n")
    assert data[result.end:] == b"SMUGGLED"


# --- the malformed cases that drive smuggling ------------------------------

def test_whitespace_around_the_size_splits_parsers():
    data = b"5 \r\nhello\r\n0\r\n\r\n"
    with pytest.raises(ParseError, match="whitespace"):
        decode(data, 0, STRICT)
    assert decode(data, 0, LENIENT_CHUNKED).body == b"hello"


def test_a_hex_prefix_on_the_size_is_refused():
    with pytest.raises(ParseError, match="0x"):
        decode(b"0x5\r\nhello\r\n0\r\n\r\n", 0, STRICT)


def test_a_signed_size_is_refused():
    with pytest.raises(ParseError, match="signed"):
        decode(b"+5\r\nhello\r\n0\r\n\r\n", 0, STRICT)


def test_a_non_hex_size_is_refused():
    with pytest.raises(ParseError, match="non-hex"):
        decode(b"zz\r\nhello\r\n0\r\n\r\n", 0, STRICT)


def test_hex_sizes_are_read_in_base_16():
    data = b"a\r\n0123456789\r\n0\r\n\r\n"
    assert decode(data, 0, STRICT).body == b"0123456789"


def test_bare_lf_between_chunks_is_gated_by_profile():
    data = b"4\nWiki\n0\n\n"
    with pytest.raises(ParseError, match="bare LF"):
        decode(data, 0, STRICT)
    assert decode(data, 0, LENIENT_CHUNKED).body == b"Wiki"


def test_a_chunk_longer_than_the_data_is_refused():
    with pytest.raises(ParseError, match="longer than"):
        decode(b"ff\r\nshort\r\n0\r\n\r\n", 0, STRICT)


def test_an_absurd_chunk_size_is_refused_without_allocating():
    with pytest.raises(ParseError, match="claims"):
        decode(b"ffffffff\r\n", 0, STRICT)


def test_a_chunk_not_followed_by_crlf():
    with pytest.raises(ParseError, match="not followed by CRLF"):
        decode(b"4\r\nWikiX0\r\n\r\n", 0, STRICT)


def test_data_that_never_terminates():
    with pytest.raises(ParseError, match="without a line ending"):
        decode(b"4\r\nWiki\r\n", 0, STRICT)
