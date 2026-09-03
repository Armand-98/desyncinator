"""The corpus checked against the parser, not against the detectors.

Every label here claims something checkable with message.py and profiles.py
alone: a smuggling case must actually parse to the boundaries its label claims
under the two profiles it names, and a benign case must parse cleanly and agree.
If a label and the parser disagree, the corpus is wrong, and these tests say so
before any detector is trusted with it.

Nothing here compares a label to another label: the class, the smuggled bytes and
the mechanism each have to survive a parse of the raw bytes.
"""

import pytest

from desyncinator.corpus import (CACHE_FINDINGS, KINDS, SMUGGLED,
                                 SMUGGLING_CLASSES, all_cases, benign_cases,
                                 cache_cases, smuggling_cases)
from desyncinator.http.message import parse
from desyncinator.http.profiles import PROFILES, profile
from desyncinator.http.types import (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH,
                                     FRAMING_NONE, ParseError)


def _boundary_cases():
    """Smuggling cases where both hops parse and end the body at different bytes."""
    return [c for c in smuggling_cases() if c.expected.cls != "parse-split"]


def _split_cases():
    return [c for c in smuggling_cases() if c.expected.cls == "parse-split"]


def _te_lines(raw: bytes) -> list[bytes]:
    return [line for line in raw.split(b"\r\n")
            if line.split(b":", 1)[0].strip().lower() == b"transfer-encoding"]


def _canonical_te(raw: bytes) -> bytes:
    """The same message with every Transfer-Encoding written the conforming way."""
    lines = []
    for line in raw.split(b"\r\n"):
        name = line.split(b":", 1)[0].strip().lower()
        lines.append(b"Transfer-Encoding: chunked"
                     if name == b"transfer-encoding" else line)
    return b"\r\n".join(lines)


def _diverges(raw: bytes, front_name: str, back_name: str) -> bool:
    """Two boundaries out of one message. A hop that refuses it is not a boundary
    disagreement, so a ParseError counts as no divergence here."""
    try:
        front = parse(raw, profile(front_name))
        back = parse(raw, profile(back_name))
    except ParseError:
        return False
    return front.body_end != back.body_end


# --- internal consistency --------------------------------------------------

def test_every_case_is_well_formed():
    for c in all_cases():
        assert c.name
        assert c.description
        assert c.kind in KINDS
        if isinstance(c.raw, tuple):
            assert len(c.raw) == 2
            assert all(isinstance(part, bytes) for part in c.raw)
        else:
            assert isinstance(c.raw, bytes)


def test_names_are_unique():
    names = [c.name for c in all_cases()]
    assert len(names) == len(set(names))


def test_required_attack_shapes_are_present():
    names = {c.name for c in smuggling_cases()}
    for required in ("cl_te", "te_cl", "te_te_obfuscated_token",
                     "space_before_colon_split", "duplicate_content_length",
                     "chunked_trailing_junk"):
        assert required in names


def test_smuggling_profiles_are_real_profiles():
    for c in smuggling_cases():
        assert c.expected.frontend in PROFILES
        assert c.expected.backend in PROFILES


# --- the smuggling labels are true under the parser ------------------------

def test_smuggling_cases_desync_to_the_labelled_boundary():
    for c in _boundary_cases():
        assert c.kind == c.expected.cls
        assert c.expected.smuggled
        front = parse(c.raw, profile(c.expected.frontend))
        back = parse(c.raw, profile(c.expected.backend))
        # The front-end forwards the whole message; the back-end cuts it short and
        # keeps the smuggled bytes as its next request.
        assert front.body_end > back.body_end, c.name
        assert front.trailing == b"", c.name
        assert back.trailing == c.expected.smuggled, c.name


def test_class_label_matches_the_framing_each_hop_chose():
    """CL.TE and TE.CL are directional: a swapped label is a wrong label."""
    for c in _boundary_cases():
        front = parse(c.raw, profile(c.expected.frontend))
        back = parse(c.raw, profile(c.expected.backend))
        pair = (front.framing, back.framing)
        if c.expected.cls == "CL.TE":
            assert pair == (FRAMING_CONTENT_LENGTH, FRAMING_CHUNKED), c.name
        elif c.expected.cls == "TE.CL":
            assert pair == (FRAMING_CHUNKED, FRAMING_CONTENT_LENGTH), c.name
        elif c.expected.cls == "CL.CL":
            assert pair == (FRAMING_CONTENT_LENGTH, FRAMING_CONTENT_LENGTH), c.name
            assert front.count("content-length") > 1, c.name
        elif c.expected.cls == "TE.TE":
            # Both hops read a Transfer-Encoding and only one made a body of it.
            # A hop that framed by length instead is disagreeing about length
            # against chunked, which is CL.TE or TE.CL however the token was read.
            assert pair == (FRAMING_CHUNKED, FRAMING_NONE), c.name
            assert front.count("transfer-encoding"), c.name
            assert back.count("transfer-encoding"), c.name
        else:
            pytest.fail(f"unlabelled boundary class {c.expected.cls} in {c.name}")


def test_transfer_encoding_obfuscation_is_load_bearing():
    """Where a case writes Transfer-Encoding unconventionally, that must be what
    splits the hops: with the header written plainly they have to agree."""
    for c in smuggling_cases():
        lines = _te_lines(c.raw)
        if not lines or all(line == b"Transfer-Encoding: chunked" for line in lines):
            continue
        assert not _diverges(_canonical_te(c.raw), c.expected.frontend,
                             c.expected.backend), c.name


def test_the_backend_is_left_holding_the_planted_request():
    for c in _boundary_cases():
        assert SMUGGLED in c.expected.smuggled, c.name
        if c.expected.smuggled.startswith(SMUGGLED):
            # Where the leftover starts at the planted request, the back-end runs
            # it directly; elsewhere it first has to eat the chunk framing.
            assert parse(c.expected.smuggled, profile("strict")).target == "/admin"


def test_parse_split_cases_are_accepted_by_one_hop_and_refused_by_the_other():
    for c in _split_cases():
        assert c.expected.smuggled == b"", c.name
        parse(c.raw, profile(c.expected.frontend))
        with pytest.raises(ParseError):
            parse(c.raw, profile(c.expected.backend))


# --- benign traffic parses and does not desync -----------------------------

def test_no_benign_message_diverges_under_any_profile():
    for c in benign_cases():
        parts = c.raw if isinstance(c.raw, tuple) else (c.raw,)
        for index, part in enumerate(parts):
            ends = {name: parse(part, p, is_request=(index == 0)).body_end
                    for name, p in PROFILES.items()}
            assert len(set(ends.values())) == 1, (c.name, index, ends)


def test_benign_requests_carry_one_framing_only():
    """A single framing is why they cannot desync: two would be the attack."""
    for c in benign_cases():
        request = c.raw[0] if isinstance(c.raw, tuple) else c.raw
        message = parse(request, profile("strict"))
        assert message.count("content-length") <= 1, c.name
        assert not (message.count("content-length")
                    and message.count("transfer-encoding")), c.name


def test_cache_pairs_parse_cleanly_as_request_and_response():
    for c in all_cases():
        if not isinstance(c.raw, tuple):
            continue
        request, response = c.raw
        assert parse(request, profile("strict")).method
        assert parse(response, profile("strict"), is_request=False).status


# --- label coverage: the corpus spans what the detectors detect ------------

def test_labels_cover_every_smuggling_class():
    covered = {c.kind for c in smuggling_cases()}
    assert set(SMUGGLING_CLASSES) <= covered


def test_labels_cover_every_cache_finding():
    findings = {c.expected.finding for c in cache_cases()}
    assert set(CACHE_FINDINGS) == findings


def test_benign_guards_are_several():
    assert len(benign_cases()) >= 5
    assert all(c.expected.cls is None and c.expected.finding is None
               for c in benign_cases())


def test_cache_cases_carry_a_finding_label():
    for c in cache_cases():
        assert c.expected.finding in CACHE_FINDINGS
        assert c.kind == c.expected.finding
        assert isinstance(c.raw, tuple)
