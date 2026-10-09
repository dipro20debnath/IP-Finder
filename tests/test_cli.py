import io
import json

import pytest

from ipfinder import __version__
from ipfinder.cli import main


class FakeStdin(io.StringIO):
    def __init__(self, text, tty):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.fixture
def no_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeStdin("", tty=True))


def test_lookup_text(capsys, no_stdin):
    assert main(["lookup", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "Public unicast" in out
    assert "does not identify a person" in out


def test_shorthand_without_subcommand(capsys, no_stdin):
    assert main(["1.1.1.1"]) == 0
    assert "1.1.1.1" in capsys.readouterr().out


def test_json_output_with_invalid_input(capsys, no_stdin):
    assert main(["lookup", "-f", "json", "8.8.8.8", "999.1.1.1"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "ip-finder"
    assert doc["version"] == __version__
    assert [r["ip"] for r in doc["reports"]] == ["8.8.8.8"]
    assert doc["errors"][0]["input"] == "999.1.1.1"


def test_json_to_file(tmp_path, capsys, no_stdin):
    out = tmp_path / "r.json"
    assert main(["lookup", "-f", "json", "-o", str(out), "2001:db8::1"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["reports"][0]["lookup"]["eligible"] is False
    assert "Saved JSON report" in capsys.readouterr().out


def test_text_to_file(tmp_path, no_stdin):
    out = tmp_path / "r.txt"
    assert main(["lookup", "-o", str(out), "fe80::21a:2bff:fe3c:4d5e"]) == 0
    text = out.read_text(encoding="utf-8")
    assert "00:1a:2b:3c:4d:5e" in text
    assert "\x1b[" not in text  # no colour codes in files


def test_input_file(tmp_path, capsys, no_stdin):
    src = tmp_path / "ips.txt"
    src.write_text("# my list\n8.8.8.8\n\n1.1.1.1  # cloudflare\n", encoding="utf-8")
    assert main(["lookup", "-f", "json", "-i", str(src)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [r["ip"] for r in doc["reports"]] == ["8.8.8.8", "1.1.1.1"]


def test_missing_input_file(tmp_path, capsys, no_stdin):
    assert main(["lookup", "-i", str(tmp_path / "nope.txt")]) == 2
    assert "Cannot read" in capsys.readouterr().out


def test_piped_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", FakeStdin("8.8.8.8\n10.0.0.1\n", tty=False))
    assert main(["lookup", "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [r["ip"] for r in doc["reports"]] == ["8.8.8.8", "10.0.0.1"]


def test_interactive_prompt(monkeypatch, capsys, no_stdin):
    monkeypatch.setattr("builtins.input", lambda prompt: "9.9.9.9")
    assert main([]) == 0
    assert "9.9.9.9" in capsys.readouterr().out


def test_interactive_eof(monkeypatch, capsys, no_stdin):
    def eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert main([]) == 2
    assert "No IP address given" in capsys.readouterr().out


def test_user_input_is_not_parsed_as_rich_markup(capsys, no_stdin):
    assert main(["lookup", "[bold]x[/bold]"]) == 1
    assert "[bold]x[/bold]" in capsys.readouterr().out


def test_verbose_shows_python_flags(capsys, no_stdin):
    assert main(["lookup", "-v", "2001:1::1"]) == 0
    out = capsys.readouterr().out
    assert "is_global" in out
    assert "IETF Protocol Assignments" in out


def test_sources(capsys, monkeypatch):
    monkeypatch.setenv("IPINFO_TOKEN", "x")
    assert main(["sources"]) == 0
    out = capsys.readouterr().out
    assert "offline" in out and "ip-api" in out
    assert "IPINFO_TOKEN set" in out
    assert "ABUSEIPDB_API_KEY missing" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_usage_error_exit_code(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["lookup", "-f", "xml", "8.8.8.8"])
    assert excinfo.value.code == 2


def test_internal_error_is_reported_not_raised(monkeypatch, capsys, no_stdin):
    def explode(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("ipfinder.cli.analyze_many", explode)
    assert main(["lookup", "8.8.8.8"]) == 3
    assert "Internal error: RuntimeError: kaboom" in capsys.readouterr().out
