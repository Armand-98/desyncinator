#!/usr/bin/env python3
"""Measure the analyzer against the built-in corpus.

The corpus carries a known label for every case: which smuggling class or cache
finding it should produce, or that it is benign and must produce nothing. This
runs each case through the same code path the CLI uses and reports detection and
false positives.

The honest limit, as with the other tools: the corpus is written by hand, so it
measures the engine against a documented taxonomy rather than against the whole
messy population of real proxies. The taxonomy is the public request-smuggling
and cache-abuse literature, not one person's guess.

    ./.venv/bin/python tools/evaluate.py
    ./.venv/bin/python tools/evaluate.py --markdown
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from desyncinator import cache as cache_mod                # noqa: E402
from desyncinator import corpus as corpus_mod             # noqa: E402
from desyncinator.desync import scan                      # noqa: E402
from desyncinator.http.message import parse               # noqa: E402
from desyncinator.http.profiles import STRICT             # noqa: E402


def _smuggling_classes(raw: bytes) -> set[str]:
    return {d.kind for d in scan(raw)}


def _cache_kinds(request_bytes: bytes, response_bytes: bytes) -> set[str]:
    request = parse(request_bytes, STRICT)
    response = parse(response_bytes, STRICT, is_request=False)
    kinds = set()
    if cache_mod.deception_finding(request.target, response,
                                   method=request.method):
        kinds.add("deception")
    if cache_mod.poisoning_findings(request.target, request, response):
        kinds.add("poisoning")
    return kinds


def evaluate():
    detected = missed = benign_clean = false_positive = 0
    rows = []
    for case in corpus_mod.all_cases():
        raw = case.raw
        if isinstance(raw, tuple):
            fired = _cache_kinds(raw[0], raw[1])
        else:
            fired = _smuggling_classes(raw)

        if case.kind == "benign":
            ok = not fired
            benign_clean += ok
            false_positive += not ok
            rows.append(("benign", case.name, "clean" if ok else f"FP {fired}"))
        else:
            ok = bool(fired)
            detected += ok
            missed += not ok
            rows.append((case.kind, case.name,
                         "detected" if ok else "MISSED"))
    return rows, detected, missed, benign_clean, false_positive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    rows, detected, missed, clean, fp = evaluate()
    attacks = detected + missed
    benign = clean + fp

    if args.markdown:
        print(f"Measured against the built-in corpus: {attacks} attack cases "
              f"across the documented classes, {benign} benign cases shaped to "
              f"resemble them.\n")
        print("| | Count |")
        print("|---|---|")
        print(f"| Attacks detected | {detected}/{attacks} |")
        print(f"| Missed | {missed} |")
        print(f"| Benign correctly cleared | {clean}/{benign} |")
        print(f"| False positives | {fp} |")
    else:
        print("desyncinator evaluation")
        print("=" * 60)
        for kind, name, verdict in rows:
            mark = "ok  " if verdict in ("detected", "clean") else "!!  "
            print(f"  {mark} {kind:12} {name:30} {verdict}")
        print("=" * 60)
        print(f"  attacks detected {detected}/{attacks}, "
              f"benign clean {clean}/{benign}, false positives {fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
