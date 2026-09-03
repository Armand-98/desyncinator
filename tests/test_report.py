"""Report tests, focused on the deduplication a person actually needs."""

from desyncinator.desync import (BOUNDARY, CL_CL, CL_TE, Divergence, PARSE_SPLIT,
                                 TE_CL, TE_TE)
from desyncinator.cache import Finding
from desyncinator.report import Summary, render_json, render_text
import json


def div(kind, severity="critical", fe=81, be=80, prefix=b"G"):
    return Divergence(kind=kind, severity=severity, frontend="lenient-length",
                      backend="lenient-chunked", frontend_body_end=fe,
                      backend_body_end=be, smuggled_prefix=prefix,
                      detail=f"{kind} detail", frontend_message=None,
                      backend_message=None)


def test_one_ambiguous_request_is_one_finding_not_six():
    """A CL.TE payload produces the class, its TE.CL mirror, and parse-splits
    against strict. A reader wants the vector once."""
    summary = Summary(divergences=[
        div(CL_TE), div(TE_CL),
        div(PARSE_SPLIT, "medium"), div(PARSE_SPLIT, "medium"),
        div(PARSE_SPLIT, "medium"), div(PARSE_SPLIT, "medium"),
    ])
    primary = summary.primary()
    assert len(primary) == 1
    assert primary[0].kind == CL_TE
    assert summary.total == 1


def test_distinct_classes_are_kept_separately():
    summary = Summary(divergences=[div(CL_TE), div(CL_CL, "high", 90, 80, b"XX")])
    kinds = {d.kind for d in summary.primary()}
    assert kinds == {CL_TE, CL_CL}


def test_a_parse_split_survives_when_nothing_concrete_was_found():
    """If the only disagreement is one hop rejecting what another accepts, that
    split is the actual result, not noise to fold away."""
    summary = Summary(divergences=[div(PARSE_SPLIT, "medium")])
    assert len(summary.primary()) == 1
    assert summary.primary()[0].kind == PARSE_SPLIT


def test_the_strongest_of_a_class_is_kept():
    summary = Summary(divergences=[div(CL_TE, "medium"), div(CL_TE, "critical")])
    assert summary.primary()[0].severity == "critical"


def test_nothing_found_message_is_honest_about_its_limits():
    text = render_text(Summary(source="x.bin"), colour=False)
    assert "No disagreement found" in text
    assert "not proof of safety" in text


def test_text_shows_the_smuggled_prefix():
    text = render_text(Summary(divergences=[div(CL_TE)]), colour=False)
    assert "smuggled prefix" in text
    assert "'G'" in text
    assert "CL.TE" in text


def test_cache_findings_render():
    f = Finding(kind="poisoning", target="/", reason="X-Forwarded-Host reflected",
                evidence="header=X-Forwarded-Host value=evil.com", severity="high")
    text = render_text(Summary(cache_findings=[f]), colour=False)
    assert "poisoning" in text
    assert "X-Forwarded-Host" in text


def test_json_is_parseable_and_deduplicated():
    summary = Summary(source="x", divergences=[div(CL_TE), div(TE_CL),
                                               div(PARSE_SPLIT, "medium")])
    data = json.loads(render_json(summary))
    assert len(data["smuggling"]) == 1
    assert data["smuggling"][0]["smuggled_prefix"] == "G"
    assert data["counts"] == {"critical": 1}


def test_colour_off_has_no_escapes():
    assert "\033[" not in render_text(Summary(divergences=[div(CL_TE)]), colour=False)
