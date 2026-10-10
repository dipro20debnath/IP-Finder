"""Phase 10: the demo script. Every command must be valid, and the offline demo
must run from start to finish without the network."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ipfinder.analysis.offline import analyze as offline_analyze
from ipfinder.cli import _build_parser, _command_first
from ipfinder.core.validator import InvalidIPError, parse_ip

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("ipfinder_demo", ROOT / "scripts" / "demo.py")
demo = importlib.util.module_from_spec(_spec)
sys.modules["ipfinder_demo"] = demo  # dataclasses look the module up while it loads
_spec.loader.exec_module(demo)


def commands(offline):
    for _n, step, cmds in demo.steps_for(offline):
        for cmd in cmds or ():
            if step.kind != "pytest":
                yield step, cmd


@pytest.mark.parametrize("offline", [False, True])
def test_every_demo_command_is_valid(offline):
    parser = _build_parser()
    for _step, cmd in commands(offline):
        parser.parse_args(_command_first(list(cmd)))  # exits on a bad option


def test_offline_commands_cannot_reach_the_network():
    parser = _build_parser()
    for step, cmd in commands(True):
        args = parser.parse_args(_command_first(list(cmd)))
        if getattr(args, "offline", False):
            continue
        for raw in getattr(args, "ips", []):  # no --offline: only addresses with no lookup
            try:
                target = offline_analyze(parse_ip(raw))["lookup"]["target"]
            except InvalidIPError:
                continue
            assert target is None, (step.title, raw)


def test_offline_demo_runs_end_to_end(tmp_path):
    dead_proxy = "http://127.0.0.1:9"  # any HTTP attempt would fail and show "cannot reach"
    env = dict(os.environ, HTTP_PROXY=dead_proxy, HTTPS_PROXY=dead_proxy, NO_PROXY="")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "demo.py"), "--offline", "--yes",
         "--no-browser", "--to", "10"],
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300,
    )  # fmt: skip
    out = result.stdout + result.stderr
    assert result.returncode == 0, out[-3000:]
    assert "All steps ran." in out and "cannot reach" not in out
    for expected in ("London", "Anycast service", "40000", "00:1a:2b:3c:4d:5e",
                     "Shared Address Space", "CVE-2021-29921", "Dashboard answered",
                     "Nothing was sent"):  # fmt: skip
        assert expected in out, expected
    report = tmp_path / "demo-output" / "report.html"
    assert report.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert (tmp_path / "demo-output" / "report.csv").read_bytes().startswith(b"\xef\xbb\xbf")


def test_list_and_check(capsys):
    assert demo.main(["--list"]) == 0
    listing = capsys.readouterr().out
    assert listing.count("look at:") == len(demo.STEPS) and "ipfinder serve --open" in listing
    assert demo.main(["--check", "--offline"]) == 0
    assert "MaxMind test databases" in capsys.readouterr().out
