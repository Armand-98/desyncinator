"""Rendering findings.

Every finding shows the bytes and the two interpretations that produced it. A
smuggling or cache result that cannot be reproduced by hand is not actionable,
so the report gives the reader what each hop saw, not a verdict to trust.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

from .cache import Finding
from .desync import (BOUNDARY, CL_CL, CL_TE, Divergence, PARSE_SPLIT, TE_CL,
                     TE_TE)

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
_COLOURS = {CRITICAL: "\033[1;31m", HIGH: "\033[31m",
            MEDIUM: "\033[33m", LOW: "\033[36m"}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"


# A concrete smuggling class and its mirror describe one vector from the two
# ends. The parse-splits against a rejecting profile restate the same header
# conflict, so once a concrete class is present they are corroboration, not new
# findings, and are folded away by default.
_CONCRETE = (CL_TE, TE_CL, TE_TE, CL_CL, BOUNDARY)
_MIRROR = {CL_TE: TE_CL, TE_CL: CL_TE}


@dataclass(slots=True)
class Summary:
    source: str = ""
    divergences: list[Divergence] = field(default_factory=list)
    cache_findings: list[Finding] = field(default_factory=list)

    def primary(self) -> list[Divergence]:
        """The distinct vectors, one per class, mirrors and parse-splits folded.

        A single ambiguous request produces a concrete class, its reversed-role
        mirror, and several parse-splits against the strict profile. They are
        one problem. The strongest concrete finding of each class is kept; a
        parse-split survives only when no concrete class was found at all, since
        then the one-hop-rejects-it split is the actual result.
        """
        concrete = [d for d in self.divergences if d.kind in _CONCRETE]
        if not concrete:
            return _dedupe(self.divergences)

        seen: set[str] = set()
        primary: list[Divergence] = []
        for d in sorted(concrete, key=lambda x: _ORDER.get(x.severity, 9)):
            canon = _MIRROR.get(d.kind, d.kind)
            key = min(d.kind, canon)
            if key not in seen:
                seen.add(key)
                primary.append(d)
        return primary

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in (*self.primary(), *self.cache_findings):
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

    @property
    def total(self) -> int:
        return len(self.primary()) + len(self.cache_findings)


def _dedupe(divergences: list[Divergence]) -> list[Divergence]:
    seen, out = set(), []
    for d in sorted(divergences, key=lambda x: _ORDER.get(x.severity, 9)):
        key = (d.kind, d.frontend_body_end, d.backend_body_end)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_json(summary: Summary) -> str:
    return json.dumps({
        "source": summary.source,
        "counts": summary.counts(),
            "smuggling": [_divergence_dict(d) for d in summary.primary()],
        "cache": [_finding_dict(f) for f in summary.cache_findings],
    }, indent=2)


def _divergence_dict(d: Divergence) -> dict:
    return {
        "kind": d.kind,
        "severity": d.severity,
        "frontend_profile": d.frontend,
        "backend_profile": d.backend,
        "frontend_body_end": d.frontend_body_end,
        "backend_body_end": d.backend_body_end,
        "smuggled_prefix": d.smuggled_prefix.decode("latin-1") if d.smuggled_prefix else "",
        "detail": d.detail,
    }


def _finding_dict(f: Finding) -> dict:
    return {"kind": f.kind, "severity": f.severity, "target": f.target,
            "reason": f.reason, "evidence": f.evidence}


def render_text(summary: Summary, *, colour: bool | None = None) -> str:
    colour = use_colour() if colour is None else colour
    paint = _painter(colour)
    lines = [paint(f"desyncinator {summary.source}", _BOLD)]

    if summary.total == 0:
        lines.append("")
        lines.append("  No disagreement found. Every profile pair framed this "
                     "request the same way.")
        lines.append(paint("  That is not proof of safety: only the profiles "
                           "modelled here were tried, and a real chain may hold "
                           "a parser none of them captures.", _DIM))
        return "\n".join(lines) + "\n"

    counts = summary.counts()
    tally = "  ".join(f"{paint(level, _COLOURS.get(level, ''))} {counts[level]}"
                      for level in (CRITICAL, HIGH, MEDIUM, LOW) if level in counts)
    lines.append(paint(f"  {tally}", ""))
    lines.append("")

    for d in summary.primary():
        lines.extend(_render_divergence(d, paint))
    for f in sorted(summary.cache_findings, key=lambda x: _ORDER.get(x.severity, 9)):
        lines.extend(_render_finding(f, paint))
    return "\n".join(lines)


def _render_divergence(d: Divergence, paint) -> list[str]:
    tag = paint(f"[{d.severity.upper()}]", _COLOURS.get(d.severity, ""))
    out = [f"  {tag} {paint(d.kind, _BOLD)} request smuggling",
           f"        {'detail':<18} {d.detail}",
           f"        {'front-end':<18} {d.frontend} ends the body at "
           f"byte {d.frontend_body_end}",
           f"        {'back-end':<18} {d.backend} ends the body at "
           f"byte {d.backend_body_end}"]
    if d.smuggled_prefix:
        out.append(f"        {'smuggled prefix':<18} "
                   f"{d.smuggled_prefix.decode('latin-1')!r}")
        out.append(paint("        the back-end treats these bytes as the start "
                         "of the next request", _DIM))
    out.append("")
    return out


def _render_finding(f: Finding, paint) -> list[str]:
    tag = paint(f"[{f.severity.upper()}]", _COLOURS.get(f.severity, ""))
    return [f"  {tag} {paint(f.kind, _BOLD)} on {f.target}",
            f"        {'why':<18} {f.reason}",
            f"        {'evidence':<18} {f.evidence}",
            ""]


def _painter(colour: bool):
    if not colour:
        return lambda text, _code="": text
    return lambda text, code="": f"{code}{text}{_RESET}" if code else text
