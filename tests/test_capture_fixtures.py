import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "capture_fixtures", ROOT / "scripts" / "capture_fixtures.py"
)
cf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cf  # dataclasses look the module up while loading
spec.loader.exec_module(cf)

SECRET = "s3cr3t-token-value"


def _source(name):
    return next(s for s in cf.SOURCES if s.name == name)


def test_key_in_query_is_redacted():
    url, headers, redacted = cf.build_request(
        _source("ipinfo-lite"), "8.8.8.8", {"IPINFO_TOKEN": SECRET}
    )
    assert SECRET in url
    assert SECRET not in redacted
    assert redacted.endswith("token=REDACTED")


def test_key_in_header():
    url, headers, redacted = cf.build_request(
        _source("virustotal"), "8.8.8.8", {"VIRUSTOTAL_API_KEY": SECRET}
    )
    assert headers["x-apikey"] == SECRET
    assert SECRET not in url


def test_required_key_missing_returns_none():
    assert cf.build_request(_source("abuseipdb"), "8.8.8.8", {}) is None


def test_optional_key_missing_still_builds():
    url, headers, _ = cf.build_request(_source("greynoise"), "8.8.8.8", {})
    assert url == "https://api.greynoise.io/v3/community/8.8.8.8"
    assert "key" not in headers


def test_fixture_path_is_filesystem_safe(tmp_path):
    path = cf.fixture_path(tmp_path, "rdap", "2001:4860:4860::8888")
    assert path.name == "2001_4860_4860__8888.json"


def test_lookup_targets():
    targets, problems = cf.lookup_targets(["8.8.8.8", "2002:808:808::1", "10.0.0.1", "bad"])
    assert targets == ["8.8.8.8"]  # the 6to4 address maps to the same IPv4, so no duplicate
    assert any("10.0.0.1" in p for p in problems)
    assert any("bad" in p for p in problems)


def test_capture_saves_redacted_records(tmp_path):
    calls = []

    def fake_fetch(url, headers):
        calls.append((url, headers))
        return (
            200,
            {"Content-Type": "application/json", "X-Rl": "44", "Set-Cookie": "x"},
            '{"ok": 1}',
        )

    sources = (_source("ipinfo-lite"), _source("abuseipdb"))
    summary = cf.capture(
        ["8.8.8.8"],
        {"IPINFO_TOKEN": SECRET},
        tmp_path,
        sources,
        fetch=fake_fetch,
        sleep=lambda s: None,
    )
    assert len(calls) == 1
    assert summary[1] == ("abuseipdb", "8.8.8.8", "skipped (set ABUSEIPDB_API_KEY)")
    saved = (tmp_path / "ipinfo-lite" / "8.8.8.8.json").read_text(encoding="utf-8")
    assert SECRET not in saved
    record = json.loads(saved)
    assert record["status"] == 200
    assert record["body"] == {"ok": 1}
    assert record["headers"] == {"content-type": "application/json", "x-rl": "44"}


def test_capture_records_http_errors_and_survives_network_errors(tmp_path):
    def fake_fetch(url, headers):
        if "internetdb" in url:
            return 404, {}, '{"detail": "No information available"}'
        raise OSError("connection refused")

    sources = (_source("internetdb"), _source("rdap"))
    summary = cf.capture(["8.8.8.8"], {}, tmp_path, sources, fetch=fake_fetch, sleep=lambda s: None)
    assert summary[0][2].startswith("HTTP 404")
    assert summary[1][2] == "error: OSError: connection refused"
    assert json.loads((tmp_path / "internetdb" / "8.8.8.8.json").read_text())["status"] == 404


def test_ip_api_rate_limit_header_triggers_wait(tmp_path):
    sleeps = []

    def fake_fetch(url, headers):
        return 200, {"X-Rl": "0", "X-Ttl": "37"}, "{}"

    cf.capture(
        ["8.8.8.8"], {}, tmp_path, (_source("ip-api"),), fetch=fake_fetch, sleep=sleeps.append
    )
    assert 38 in sleeps


def test_ipv4_only_source_skips_ipv6(tmp_path):
    summary = cf.capture(
        ["2001:4860:4860::8888"],
        {},
        tmp_path,
        (_source("greynoise"),),
        fetch=lambda u, h: pytest.fail("should not fetch"),
        sleep=lambda s: None,
    )
    assert summary == [("greynoise", "2001:4860:4860::8888", "skipped (IPv4 only)")]


def test_list_command(capsys):
    assert cf.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "ip-api" in out and "no key needed" in out


def test_unknown_source_is_rejected():
    with pytest.raises(SystemExit):
        cf.main(["--only", "nonexistent"])
