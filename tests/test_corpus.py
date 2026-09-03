"""The corpus checked against the parser, not against the detectors.

Every label here claims something checkable with message.py and profiles.py
alone: a smuggling case must actually parse to two different boundaries under the
two profiles it names, and a benign case must parse cleanly and agree. If a label
and the parser disagree, the corpus is wrong, and these tests say so before any
detector is trusted with it.
"""

import pytest

from desyncinator.corpus import (CACHE_FINDINGS, KINDS, SMUGGLING_CLASSES,
                                  all_cases, benign_cases, cache_cases,
                                  smuggling_cases)
from desyncinator.http.message import parse
from desyncinator.http.profiles import profile
from desyncinator.http.profiles import PROFILES


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
                     "te_te_space_before_colon", "duplicate_content_length",
                     "chunked_trailing_junk"):
        assert required in names


# --- the smuggling labels are true under the parser ------------------------

def test_smuggling_cases_desync_to_the_labelled_boundary():
    for c in smuggling_cases():
        assert c.kind in SMUGGLING_CLASSES
        assert c.kind == c.expected.cls
        assert c.expected.smuggled
        front = parse(c.raw, profile(c.expected.frontend))
        back = parse(c.raw, profile(c.expected.backend))
        # The front-end forwards the whole message; the back-end cuts it short and
        # keeps the smuggled bytes as its next request.
        assert front.body_end > back.body_end, c.name
        assert front.trailing == b"", c.name
        assert back.trailing == c.expected.smuggled, c.name


def test_smuggling_profiles_are_real_profiles():
    for c in smuggling_cases():
        assert c.expected.frontend in PROFILES
        assert c.expected.backend in PROFILES


# --- benign traffic parses and does not desync -----------------------------

def _smuggling_shaped_benign():
    return [c for c in benign_cases() if isinstance(c.raw, bytes)]


def test_benign_requests_agree_across_every_profile():
    for c in _smuggling_shaped_benign():
        ends = {name: parse(c.raw, p).body_end for name, p in PROFILES.items()}
        assert len(set(ends.values())) == 1, (c.name, ends)


def test_benign_and_cache_pairs_parse_cleanly():
    for c in all_cases():
        if not isinstance(c.raw, tuple):
            continue
        request, response = c.raw
        parse(request, profile("strict"), is_request=True)
        parse(response, profile("strict"), is_request=False)


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
