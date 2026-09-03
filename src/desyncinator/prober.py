"""The optional live prober, gated behind explicit authorization.

Everything else in this tool is offline: a request is bytes, and analysing bytes
harms nobody. Sending crafted, deliberately ambiguous HTTP to a running server
is different. Against a system you do not control it is an attack, whatever it
is called, so the prober refuses to run unless the caller both affirms
authorization and names the exact host as one they are allowed to test.

The prober does not itself attempt exploitation. It sends one request built to
reveal a framing disagreement and times the response, because a back-end left
waiting for bytes that a front-end already ended is the observable signal. It
reports what it saw; it never chains a second victim request.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

CONNECT_TIMEOUT = 10.0
# A back-end still waiting for the body a front-end already closed shows up as a
# response that takes at least this much longer than the control.
DESYNC_DELAY = 5.0


class NotAuthorized(Exception):
    """The prober was asked to touch a host without the required affirmation."""


@dataclass(frozen=True, slots=True)
class ProbeResult:
    host: str
    control_seconds: float
    probe_seconds: float
    delayed: bool
    detail: str


def probe(url: str, request_bytes: bytes, *, authorized: bool,
          allowed_hosts: frozenset[str], timeout: float = CONNECT_TIMEOUT
          ) -> ProbeResult:
    """Send one probe to url, only if authorized and the host is on the list."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not authorized:
        raise NotAuthorized(
            "the live prober needs --i-am-authorized. Testing HTTP parsing "
            "against a system you do not control is an attack, not a scan.")
    if host not in allowed_hosts:
        raise NotAuthorized(
            f"{host!r} is not in the authorized set. Pass it with "
            f"--allow-host {host} to confirm you are permitted to test it.")

    port = parts.port or (443 if parts.scheme == "https" else 80)
    use_tls = parts.scheme == "https"

    control = _time_request(host, port, use_tls, _control_for(request_bytes),
                            timeout)
    probed = _time_request(host, port, use_tls, request_bytes, timeout)
    delayed = probed - control >= DESYNC_DELAY
    detail = ("the probe took markedly longer than the control, consistent with "
              "a back-end still waiting for a body the front-end ended"
              if delayed else
              "no timing difference; this pair of hops did not visibly desync")
    return ProbeResult(host, control, probed, delayed, detail)


def _time_request(host, port, use_tls, data, timeout) -> float:
    start = _now()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(data)
        sock.settimeout(timeout)
        try:
            while sock.recv(4096):
                pass
        except (socket.timeout, TimeoutError):
            pass
    finally:
        sock.close()
    return _now() - start


def _control_for(request_bytes: bytes) -> bytes:
    """A benign version of the request, used to establish baseline timing."""
    head = request_bytes.split(b"\r\n\r\n", 1)[0]
    lines = [line for line in head.split(b"\r\n")
             if not line.lower().startswith((b"transfer-encoding:",
                                             b"content-length:"))]
    return b"\r\n".join(lines) + b"\r\nContent-Length: 0\r\n\r\n"


def _now() -> float:
    return time.monotonic()
