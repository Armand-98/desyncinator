"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import cache as cache_mod
from . import corpus as corpus_mod
from .desync import scan
from .http.message import parse
from .http.profiles import PROFILES, STRICT, profile
from .http.types import ParseError
from .menu import TUTORIAL, ask, interactive
from .menu import run as run_menu
from .prober import NotAuthorized, probe
from .report import Summary, render_json, render_text, use_colour

VERSION = "0.1.0"
EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


def analyze_bytes(data: bytes, source: str) -> Summary:
    return Summary(source=source, divergences=scan(data))


def cache_summary(request_bytes: bytes, response_bytes: bytes,
                  source: str) -> Summary:
    request = parse(request_bytes, STRICT)
    response = parse(response_bytes, STRICT, is_request=False)
    findings = []
    deception = cache_mod.deception_finding(request.target, response,
                                            method=request.method)
    if deception:
        findings.append(deception)
    findings.extend(cache_mod.poisoning_findings(request.target, request,
                                                 response))
    return Summary(source=source, cache_findings=findings)


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def _emit(summary: Summary, args) -> int:
    if args.json:
        print(render_json(summary))
    else:
        colour = False if args.no_color else None
        print(render_text(summary, colour=colour), end="" if summary.total else "\n")
    return EXIT_FOUND if summary.total else EXIT_CLEAN


def cmd_analyze(args) -> int:
    summary = analyze_bytes(_read(args.request), args.request)
    return _emit(summary, args)


def cmd_smuggle(args) -> int:
    """Show how each profile frames one request, side by side."""
    data = _read(args.request)
    print(f"desyncinator {args.request}\n")
    for name in sorted(PROFILES):
        try:
            m = parse(data, profile(name))
            print(f"  {name:16} framing={m.framing:16} "
                  f"body_end={m.body_end:<6} trailing={m.trailing[:32]!r}")
        except ParseError as error:
            print(f"  {name:16} rejects it: {error}")
    print()
    summary = analyze_bytes(data, args.request)
    if summary.total:
        colour = False if args.no_color else None
        print(render_text(summary, colour=colour), end="")
    return EXIT_FOUND if summary.total else EXIT_CLEAN


def cmd_cache(args) -> int:
    summary = cache_summary(_read(args.request), _read(args.response),
                            args.request)
    return _emit(summary, args)


def cmd_demo(args) -> int:
    """Run the built-in corpus of known payloads, so the tool proves itself."""
    cases = corpus_mod.all_cases()
    caught = benign_clean = 0
    attacks = benign = 0
    print("desyncinator demo, running the built-in corpus\n")
    for case in cases:
        raw = case.raw
        if isinstance(raw, tuple):
            summary = cache_summary(raw[0], raw[1], case.name)
        else:
            summary = analyze_bytes(raw, case.name)
        fired = summary.total > 0

        if case.kind == "benign":
            benign += 1
            benign_clean += not fired
            mark = "ok  " if not fired else "FP  "
        else:
            attacks += 1
            caught += fired
            mark = "ok  " if fired else "MISS"
        print(f"  {mark} {case.kind:12} {case.name:28} {case.description[:40]}")
    print(f"\n  attacks detected {caught}/{attacks}, "
          f"benign clean {benign_clean}/{benign}")
    return EXIT_CLEAN


def cmd_probe(args) -> int:
    try:
        result = probe(args.url, _read(args.request),
                       authorized=args.i_am_authorized,
                       allowed_hosts=frozenset(args.allow_host))
    except NotAuthorized as error:
        print(f"desyncinator: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"  host              {result.host}")
    print(f"  control response  {result.control_seconds:.2f}s")
    print(f"  probe response    {result.probe_seconds:.2f}s")
    print(f"  {result.detail}")
    return EXIT_FOUND if result.delayed else EXIT_CLEAN


def _menu_action(number: int, entry) -> int | None:
    name, _blurb = entry
    args = _defaults()
    if name == "Tutorial":
        print(TUTORIAL)
        return None
    if name == "Demo":
        return _guard(lambda: cmd_demo(args))
    request = ask("Request file")
    if not request:
        return None
    if not Path(request).is_file():
        print(f"   no such file: {request}")
        return None
    args.request = request
    if name == "Cache":
        response = ask("Response file")
        if not response or not Path(response).is_file():
            print("   need a readable response file")
            return None
        args.response = response
        return _guard(lambda: cmd_cache(args))
    if name == "Smuggle":
        return _guard(lambda: cmd_smuggle(args))
    return _guard(lambda: cmd_analyze(args))


def _guard(action) -> None:
    try:
        action()
    except (OSError, ParseError) as error:
        print(f"   {error}")
    return None


def _defaults(**overrides) -> argparse.Namespace:
    base = dict(request="", response="", json=False, no_color=False,
                i_am_authorized=False, allow_host=[], url="")
    base.update(overrides)
    return argparse.Namespace(**base)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="desyncinator",
        description="Find where two HTTP hops disagree about a request: message "
                    "boundaries (request smuggling) and caching (cache abuse).",
        epilog="Exit status: 0 nothing found, 1 findings reported, 2 error.")
    parser.add_argument("--version", action="version",
                        version=f"desyncinator {VERSION}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine readable")
    common.add_argument("--no-color", action="store_true")

    subs = parser.add_subparsers(dest="command")

    analyze = subs.add_parser("analyze", parents=[common],
                              help="check a request file for smuggling")
    analyze.add_argument("request", help="file of raw HTTP request bytes")
    analyze.set_defaults(func=cmd_analyze)

    smuggle = subs.add_parser("smuggle", parents=[common],
                              help="show how each profile frames one request")
    smuggle.add_argument("request")
    smuggle.set_defaults(func=cmd_smuggle)

    cache = subs.add_parser("cache", parents=[common],
                            help="check a request and response for cache abuse")
    cache.add_argument("--request", required=True)
    cache.add_argument("--response", required=True)
    cache.set_defaults(func=cmd_cache)

    demo = subs.add_parser("demo", parents=[common],
                           help="run the built-in corpus of known payloads")
    demo.set_defaults(func=cmd_demo)

    probe_cmd = subs.add_parser(
        "probe", parents=[common],
        help="send one probe to a live target (authorization required)")
    probe_cmd.add_argument("url")
    probe_cmd.add_argument("--request", required=True)
    probe_cmd.add_argument("--i-am-authorized", action="store_true",
                           help="affirm you are permitted to test this target")
    probe_cmd.add_argument("--allow-host", action="append", default=[],
                           metavar="HOST",
                           help="a host you are permitted to test, repeatable")
    probe_cmd.set_defaults(func=cmd_probe)

    args = parser.parse_args(argv)

    if args.command is None:
        if interactive() and argv is None:
            return run_menu("desyncinator", _menu_action)
        parser.print_help()
        return EXIT_ERROR

    try:
        return args.func(args)
    except FileNotFoundError as error:
        print(f"desyncinator: {error}", file=sys.stderr)
        return EXIT_ERROR
    except ParseError as error:
        print(f"desyncinator: cannot parse: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"desyncinator: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
