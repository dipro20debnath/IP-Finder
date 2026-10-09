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
    assert "Saved JSON report" in capsys.readouterr().err


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
    assert "Cannot read" in capsys.readouterr().err


def test_piped_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", FakeStdin("8.8.8.8\n10.0.0.1\n", tty=False))
    assert main(["lookup", "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [r["ip"] for r in doc["reports"]] == ["8.8.8.8", "10.0.0.1"]


def test_interactive_prompt(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", FakeStdin("9.9.9.9\n", tty=True))
    assert main([]) == 0
    captured = capsys.readouterr()
    assert "9.9.9.9" in captured.out
    assert "Enter an IP address" in captured.err  # prompt never pollutes stdout


def test_prompt_keeps_json_stdout_valid(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", FakeStdin("8.8.8.8\n", tty=True))
    assert main(["-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["reports"][0]["ip"] == "8.8.8.8"


def test_interactive_eof(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", FakeStdin("", tty=True))
    assert main([]) == 2
    assert "No IP address given" in capsys.readouterr().err


def test_ctrl_c_at_prompt_exits_130(monkeypatch):
    class Interrupting(FakeStdin):
        def readline(self, *args):
            raise KeyboardInterrupt

    monkeypatch.setattr("sys.stdin", Interrupting("", tty=True))
    assert main([]) == 130


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
    assert "Internal error: RuntimeError: kaboom" in capsys.readouterr().err


@pytest.mark.parametrize("target", ["dir", "missing/dir/r.json"])
def test_unwritable_output_is_a_usage_error(tmp_path, capsys, no_stdin, target):
    out = tmp_path if target == "dir" else tmp_path / target
    assert main(["lookup", "-f", "json", "-o", str(out), "8.8.8.8"]) == 2
    assert "Cannot write" in capsys.readouterr().err


@pytest.mark.parametrize(
    "data",
    [
        b"\xef\xbb\xbf8.8.8.8\r\n1.1.1.1\r\n",  # UTF-8 with BOM (Notepad, PowerShell 5.1)
        "8.8.8.8\r\n1.1.1.1\r\n".encode("utf-16"),  # PowerShell 5.1 '>' redirection
    ],
)
def test_input_file_encodings(tmp_path, capsys, no_stdin, data):
    src = tmp_path / "ips.txt"
    src.write_bytes(data)
    assert main(["lookup", "-f", "json", "-i", str(src)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [r["ip"] for r in doc["reports"]] == ["8.8.8.8", "1.1.1.1"]


def test_binary_input_file_is_a_usage_error(tmp_path, capsys, no_stdin):
    src = tmp_path / "ips.bin"
    src.write_bytes(b"8.8.8.8\n\xff\xfe\xfa\n")
    assert main(["lookup", "-i", str(src)]) == 2
    assert "not UTF-8 or UTF-16" in capsys.readouterr().err


def test_escape_sequences_never_reach_output(tmp_path, capsys, no_stdin):
    src = tmp_path / "hostile.txt"
    src.write_text(
        "\x1b[2J\x1b[31mevil\n\x1b]52;c;ZWNobw==\x07\nfe80::1%\x1b[2J\n", encoding="utf-8"
    )
    report = tmp_path / "r.txt"
    assert main(["lookup", "--no-color", "-i", str(src)]) == 1
    assert main(["lookup", "-i", str(src), "-o", str(report)]) == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out
    assert "\x1b" not in report.read_text(encoding="utf-8")
    assert "\\x1b" in captured.out  # shown escaped instead


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_non_utf8_stdout_does_not_crash(monkeypatch, no_stdin, fmt):
    # Windows uses the ANSI code page (e.g. cp1252) for redirected stdout.
    raw = io.BytesIO()
    wrapper = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr("sys.stdout", wrapper)
    assert main(["lookup", "-f", fmt, "--no-color", "৮.৮.৮.৮"]) == 0
    wrapper.flush()
    output = raw.getvalue()
    assert b"8.8.8.8" in output
    if fmt == "text":
        assert b"\\u09ee" in output  # Bengali digit shown as an escape, not a crash


@pytest.mark.parametrize("value", ["𝟖.𝟖.𝟖.𝟖", "x😀", "\u009b2J"])
def test_json_on_non_utf8_stdout_is_valid_json(monkeypatch, no_stdin, value):
    raw = io.BytesIO()
    wrapper = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr("sys.stdout", wrapper)
    main(["lookup", "-f", "json", value])
    wrapper.flush()
    doc = json.loads(raw.getvalue().decode("cp1252"))
    assert doc["reports"] or doc["errors"]


def test_json_escapes_c1_controls(capsys, no_stdin):
    main(["lookup", "-f", "json", "\u009b2J\u009b31mRED"])
    out = capsys.readouterr().out
    assert "\u009b" not in out  # raw CSI never written
    assert "\\u009b" in out
    json.loads(out)


def test_failed_write_keeps_existing_report(tmp_path, capsys, no_stdin):
    target = tmp_path / "keep.json"
    target.write_text("PREVIOUS", encoding="utf-8")
    # A lone surrogate (what undecodable argv bytes become) must not truncate the file.
    assert main(["lookup", "-f", "json", "-o", str(target), "8.8.8.8", "\udcff"]) == 1
    doc = json.loads(target.read_text(encoding="utf-8"))
    assert doc["reports"][0]["ip"] == "8.8.8.8"
    assert not list(tmp_path.glob(".keep.json.*.tmp"))


def test_closed_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", None)
    assert main([]) == 2
    assert "No IP address given" in capsys.readouterr().err
