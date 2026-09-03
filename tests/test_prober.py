"""Prober authorization tests. The gate must hold before any socket opens."""

from unittest.mock import patch

import pytest

from desyncinator.prober import NotAuthorized, probe

REQUEST = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"


def test_unauthorized_refuses_before_connecting():
    with patch("desyncinator.prober.socket.create_connection") as connect:
        with pytest.raises(NotAuthorized, match="not a scan"):
            probe("http://example.com", REQUEST, authorized=False,
                  allowed_hosts=frozenset())
        connect.assert_not_called()


def test_authorized_but_host_not_allowed_refuses_before_connecting():
    with patch("desyncinator.prober.socket.create_connection") as connect:
        with pytest.raises(NotAuthorized, match="not in the authorized set"):
            probe("http://example.com", REQUEST, authorized=True,
                  allowed_hosts=frozenset({"other.com"}))
        connect.assert_not_called()


def test_the_control_request_strips_the_framing_headers():
    from desyncinator.prober import _control_for
    control = _control_for(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Length: 6\r\n\r\n0\r\n\r\nG")
    assert b"Transfer-Encoding" not in control
    assert b"Content-Length: 0" in control
    assert control.endswith(b"\r\n\r\n")
