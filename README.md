# desyncinator

Finds where two HTTP hops disagree about a request. Two hops disagreeing about
message **boundaries** is request smuggling; two hops disagreeing about
**caching** is cache deception and poisoning. One idea, one tool: exploitable
disagreement between intermediaries.

**No third-party dependencies.** The HTTP/1.1 message parser and the chunked
decoder are written from RFC 9112. There is no `http.client` parser underneath,
because the whole point is to implement the *ambiguous* cases rather than defer
to one library's single answer. Python 3.10+ standard library only.

## Measured results

Against the built-in corpus: 9 attack cases across the documented smuggling and
cache classes, and 7 benign cases shaped to resemble them. Reproduce with
`python tools/evaluate.py`.

| | |
|---|---|
| Attacks detected | **9/9** |
| Benign correctly cleared | **7/7** |
| False positives | **0** |

The honest limit: the corpus is written by hand, so it measures the engine
against the documented request-smuggling and cache-abuse taxonomy, not against
the whole messy population of deployed proxies.

## Quick start

```bash
python -m venv .venv
./.venv/bin/pip install -e ".[dev]"

# optional: callable from anywhere, as desyncinator or desync
tools/install.sh

# run with no arguments for a menu, or use the subcommands
desyncinator

# prove it on the built-in payloads, no input of your own
desync demo

# analyze a captured request for smuggling
desync analyze request.bin

# see how each parser profile frames the same bytes
desync smuggle request.bin

# check a request and response for cache abuse
desync cache --request req.bin --response resp.bin
```

```
desyncinator request.bin
  critical 1

  [CRITICAL] CL.TE request smuggling
        detail             lenient-length framed the body as content-length
                           ending at byte 81, lenient-chunked as chunked ending
                           at byte 80; the 1-byte tail becomes the start of the
                           back-end's next request
        front-end          lenient-length ends the body at byte 81
        back-end           lenient-chunked ends the body at byte 80
        smuggled prefix    'G'
```

Exit status is `0` for nothing found, `1` when findings are reported, `2` on
error.

## The idea

Almost every site has more than one HTTP parser in front of it: a CDN, a load
balancer, a WAF, then the origin. They are supposed to read a request the same
way. When two of them disagree, an attacker exploits the gap.

Parsing an HTTP message is not a function with one output. RFC 9112 is precise
about most of it, but real implementations have historically differed on the
ambiguous edges, and an attacker needs only two hops in a chain to differ on
one. `desyncinator` encodes those differences as named **profiles** and parses
the same bytes under two of them, looking for a message boundary they compute
differently.

| Class | The disagreement |
|---|---|
| `CL.TE` | front-end uses Content-Length, back-end uses Transfer-Encoding |
| `TE.CL` | front-end uses Transfer-Encoding, back-end uses Content-Length |
| `TE.TE` | both would honour chunked, but one is fooled by an obfuscated token |
| `CL.CL` | a duplicate Content-Length resolved differently by each hop |
| parse-split | one hop parses the message, the other rejects it |
| deception | a cache stores a per-user page under a static-looking URL |
| poisoning | an unkeyed input is reflected into a cacheable response |

## How it works

```
http/profiles.py  the choices a real implementation makes: CL vs TE precedence,
                  fuzzy chunked tokens, duplicate Content-Length, obsolete
                  folding, space before the colon, bare LF. Each is a documented
                  behaviour from the smuggling literature.
http/message.py   parse(bytes, profile) recording the framing it chose and the
                  offset where it decided the message ended.
http/chunked.py   the chunked coding, including the malformed cases that make
                  two decoders end a body at different bytes.
desync.py         parse under two profiles, classify the boundary disagreement,
                  extract the smuggled prefix.
cache.py          offline cache-key model, web cache deception and unkeyed-input
                  poisoning detection.
corpus.py         the labelled ground-truth payloads and benign lookalikes.
prober.py         the optional live prober, gated behind explicit authorization.
report.py         findings that show the bytes and both interpretations.
```

## Design decisions

**HTTP bytes are untrusted input.** They come off the network, so every length
is bounded before it is used to allocate, the header block is size-capped, and a
malformed message raises a defined ParseError rather than crashing. A message
failing under one profile and parsing under another is a *result*, not a bug;
that is what a parse-split finding is.

**The analysis is offline, and that is deliberate.** A request is bytes.
Analysing bytes harms nobody, needs no target, and is fully reproducible. The
whole tool works on a captured request with no network at all.

**The live prober refuses to run without authorization.** Sending crafted,
deliberately ambiguous HTTP to a running server is different from analysing
bytes: against a system you do not control it is an attack, whatever it is
called. So the prober requires `--i-am-authorized` and refuses any host not
named with `--allow-host`, and both refusals happen before a socket is opened.
The offline analysis does not need it.

**One vector is one finding.** A single ambiguous request produces a concrete
class, its reversed-role mirror, and several parse-splits against the strict
profile. They are one problem, and the report folds them into the strongest
concrete finding rather than listing six restatements.

## Limitations

Stated because a detector without known limits has not been tested properly.

- **The profiles are a model, not an inventory.** They encode documented
  behaviours, not a census of every deployed proxy. A real chain may hold a
  parser none of them captures, so "no disagreement found" is not proof of
  safety.
- **Offline analysis cannot confirm exploitability**, only the precondition. Two
  hops disagreeing is necessary for smuggling, not sufficient; whether a
  specific chain is actually vulnerable needs the (authorized) live prober.
- **Only HTTP/1.1.** HTTP/2 downgrade smuggling is a different mechanism and is
  not modelled.
- **Cache analysis works on one request/response pair.** It flags an unkeyed
  reflected input; confirming the poisoned response is actually served from
  cache to others needs live testing.
- **The corpus is hand-written**, so the numbers measure the engine against a
  taxonomy rather than against real traffic.

## Development

```bash
./.venv/bin/python -m pytest        # 247 tests, no network required
./.venv/bin/python tools/evaluate.py
```

Tests are built from bytes assembled by hand against RFC 9112 rather than from
captured samples, so a pass means agreement with the specification. No test
touches the network.

## License

MIT
