"""Menu tests. First thing seen, and the one part that can hang."""

from unittest.mock import patch

import pytest

from desyncinator.menu import ENTRIES, banner, run


def test_banner_box_is_square():
    lines = banner("desyncinator").split("\n")
    assert len({len(line) for line in lines}) == 1
    assert "DESYNCINATOR" in lines[1] and "LyfieldCreationsOS" in lines[1]


@pytest.mark.parametrize("title", ["desync", "desyncinator", "a-long-tool-name"])
def test_banner_adapts(title):
    assert len({len(line) for line in banner(title).split("\n")}) == 1


@pytest.mark.parametrize("answer", [str(len(ENTRIES)), "q", "Q", ""])
def test_every_way_of_quitting(answer, capsys):
    with patch("builtins.input", side_effect=[answer]):
        assert run("desyncinator", lambda *_: None) == 0
    assert "Done. See you next time." in capsys.readouterr().out


@pytest.mark.parametrize("interrupt", [EOFError, KeyboardInterrupt])
def test_closing_the_terminal_exits_cleanly(interrupt, capsys):
    with patch("builtins.input", side_effect=interrupt):
        assert run("desyncinator", lambda *_: None) == 0
    assert "Done" in capsys.readouterr().out


def test_bad_input_reprompts(capsys):
    with patch("builtins.input", side_effect=["x", "0", "99", "q"]):
        run("desyncinator", lambda *_: None)
    assert capsys.readouterr().out.count(
        f"Please type a number from 1 to {len(ENTRIES)}") == 3


def test_choices_reach_dispatch():
    seen = []
    with patch("builtins.input", side_effect=["1", "4", "q"]):
        run("desyncinator", lambda n, e: seen.append((n, e[0])))
    assert seen == [(1, "Analyze"), (4, "Demo")]


def test_no_trailing_whitespace(capsys):
    with patch("builtins.input", side_effect=["q"]):
        run("desyncinator", lambda *_: None)
    for line in capsys.readouterr().out.split("\n"):
        assert line == line.rstrip()
