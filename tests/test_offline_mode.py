"""--offline: only local sources run, and nothing about the address leaves the
computer (no HTTP request, no DNS query)."""

import dataclasses

from ipfinder.cli import main
from ipfinder.providers import default_providers
from tests.conftest import ASN_DB, CITY_DB, analyze_many_with

LOCAL = {
    "offline",
    "maxmind",
    "tor",
    "private-relay",
    "cloud-ranges",
    "vpn-lists",
    "feodo",
    "spamhaus-drop",
}


def test_only_file_based_sources_are_local():
    assert {p.name for p in default_providers() if p.local} == LOCAL
    assert not any(p.local and p.active for p in default_providers())


def test_offline_lookups_send_nothing(config, fake_api, fake_dns):
    offline = dataclasses.replace(
        config, offline=True, profile="full", maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB
    )
    reports, errors = analyze_many_with(["81.2.69.142", "89.160.20.112", "8.8.8.8"], offline)
    assert not errors and len(reports) == 3
    assert fake_api.requests == [] and fake_dns.queries == []  # not even the ip-api batch
    london = reports[0]
    assert london.result("maxmind").ok
    assert london.verdict["location"]["city"] == "London"
    for result in london.results:
        if result.provider not in LOCAL:
            assert result.skipped.startswith("offline mode"), result.provider


def test_offline_cli(capsys, monkeypatch, fake_api, fake_dns):
    monkeypatch.setenv("IPFINDER_MAXMIND_CITY_DB", str(CITY_DB))
    assert main(["--offline", "--no-color", "81.2.69.142"]) == 0
    out = capsys.readouterr().out
    assert "London" in out and "offline mode: this source would send" in out
    assert fake_api.requests == [] and fake_dns.queries == []

    assert main(["--offline", "--active", "--authorized", "8.8.8.8"]) == 2
    assert "cannot be used with --offline" in capsys.readouterr().err
    assert main(["me", "--offline"]) == 2
    assert "cannot run --offline" in capsys.readouterr().err
    assert fake_api.requests == []
