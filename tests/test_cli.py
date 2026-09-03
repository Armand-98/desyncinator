"""CLI and prober gating tests. Nothing here touches the network."""

import json
from pathlib import Path

import pytest

from desyncinator.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FOUND, main

CLTE = (b"POST / HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG")
CLEAN = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_analyze_reports_a_smuggling_vector(tmp_path, capsys):
    code = main(["analyze", "--no-color", write(tmp_path, "r.bin", CLTE)])
    assert code == EXIT_FOUND
    assert "CL.TE" in capsys.readouterr().out


def test_analyze_is_clean_on_a_well_formed_request(tmp_path, capsys):
    code = main(["analyze", "--no-color", write(tmp_path, "r.bin", CLEAN)])
    assert code == EXIT_CLEAN
    assert "No disagreement" in capsys.readouterr().out


def test_analyze_json(tmp_path, capsys):
    main(["analyze", "--json", write(tmp_path, "r.bin", CLTE)])
    data = json.loads(capsys.readouterr().out)
    assert data["smuggling"][0]["smuggled_prefix"] == "G"


def test_smuggle_shows_each_profile(tmp_path, capsys):
    main(["smuggle", "--no-color", write(tmp_path, "r.bin", CLTE)])
    out = capsys.readouterr().out
    assert "lenient-length" in out and "lenient-chunked" in out and "strict" in out


def test_demo_runs_the_corpus(capsys):
    code = main(["demo"])
    out = capsys.readouterr().out
    assert code == EXIT_CLEAN
    assert "attacks detected" in out
    assert "MISS" not in out
    assert "FP  " not in out


# --- the prober is gated ---------------------------------------------------

def test_probe_refuses_without_authorization(tmp_path, capsys):
    code = main(["probe", "http://example.com", "--request",
                 write(tmp_path, "r.bin", CLTE)])
    assert code == EXIT_ERROR
    assert "not a scan" in capsys.readouterr().err


def test_probe_refuses_a_host_not_on_the_allow_list(tmp_path, capsys):
    code = main(["probe", "http://example.com", "--request",
                 write(tmp_path, "r.bin", CLTE), "--i-am-authorized"])
    assert code == EXIT_ERROR
    assert "not in the authorized set" in capsys.readouterr().err


def test_probe_gating_does_not_depend_on_reaching_the_network(tmp_path):
    """Both refusals must happen before any socket is opened, so the gate holds
    even with no network. The refusal is the assertion."""
    from unittest.mock import patch
    with patch("desyncinator.prober.socket.create_connection") as connect:
        main(["probe", "http://internal.example", "--request",
              write(tmp_path, "r.bin", CLTE)])
        main(["probe", "http://internal.example", "--request",
              write(tmp_path, "r.bin", CLTE), "--i-am-authorized"])
        connect.assert_not_called()


def test_a_missing_file_is_reported(capsys):
    code = main(["analyze", "/nope/missing.bin"])
    assert code == EXIT_ERROR
    assert "desyncinator:" in capsys.readouterr().err


def test_no_command_from_a_script_prints_help(capsys):
    from unittest.mock import patch
    with patch("desyncinator.cli.interactive", return_value=False):
        code = main([])
    assert code == EXIT_ERROR
    assert "usage" in capsys.readouterr().out.lower()
