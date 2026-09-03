"""Interactive menu shown when the tool is run with no arguments.

Same shape as the other tools: the flags are the real interface, and the menu
exists so someone with a captured request and a question can use it without
first reading the help. It only runs when stdin and stdout are both terminals,
so a pipeline fails fast rather than hanging on a prompt.
"""

from __future__ import annotations

import sys

BRAND = "LyfieldCreationsOS"

ENTRIES = (
    ("Analyze", "check a request file for smuggling and cache flaws"),
    ("Smuggle", "show how each parser profile frames one request"),
    ("Cache", "check a request and response for cache abuse"),
    ("Demo", "run the built-in corpus of known payloads"),
    ("Tutorial", "how to use this tool"),
    ("Quit", ""),
)


def banner(title: str) -> str:
    label = f"   {title.upper()}  ·  {BRAND}   "
    rule = "═" * len(label)
    return f"  ╔{rule}╗\n  ║{label}║\n  ╚{rule}╝"


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def ask(prompt: str, default: str = "") -> str:
    shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
    try:
        answer = input(f"   {shown}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return answer or default


def run(title: str, dispatch) -> int:
    while True:
        print()
        print(banner(title))
        for number, (name, blurb) in enumerate(ENTRIES, start=1):
            print(f"   {number}) {name:<12}{blurb}".rstrip())
        print()
        try:
            choice = input(f"   Pick 1-{len(ENTRIES)}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n   Done. See you next time.")
            return 0
        print()

        if choice in ("", "q", str(len(ENTRIES))):
            print("   Done. See you next time.")
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(ENTRIES):
            print(f"   Please type a number from 1 to {len(ENTRIES)}.")
            continue

        status = dispatch(int(choice), ENTRIES[int(choice) - 1])
        if status is not None:
            return status


TUTORIAL = """\
   desyncinator finds where two HTTP hops disagree about a request.

   Almost every site has more than one HTTP parser in front of it: a CDN, a
   load balancer, a WAF, then the origin. They are supposed to read a request
   the same way. When two of them disagree, an attacker can exploit the gap.

   Two kinds of disagreement, one tool:

   Request smuggling  the front-end and back-end disagree about where one
                      request ends, so an attacker hides a second request
                      inside the first. Classes: CL.TE, TE.CL, TE.TE, CL.CL.
   Cache abuse        a cache and the origin disagree about caching. Deception
                      caches a private page under a static-looking URL;
                      poisoning gets an attacker-controlled value stored in a
                      response served to everyone else.

   Analyze a captured request, offline:
     desync analyze request.bin
     desync analyze request.bin --frontend lenient-length --backend strict

   Show how each profile frames the same request:
     desync smuggle request.bin

   Check a request and response together for cache abuse:
     desync cache --request req.bin --response resp.bin

   See it work on known payloads with no input of your own:
     desync demo

   About the live prober: it exists, but it refuses to run without --i-am
   -authorized and only against a host you name as yours. Testing HTTP parsing
   against a system you do not control is an attack, not a scan. The analysis
   does not need it: a request is just bytes, and the offline mode is the tool.
"""
