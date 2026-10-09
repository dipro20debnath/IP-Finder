import asyncio
import dataclasses

import pytest

from ipfinder.core.orchestrator import analyze, analyze_many
from ipfinder.core.validator import InvalidIPError
from ipfinder.providers import default_providers
from ipfinder.providers.base import Provider, ProviderError
from tests.conftest import run


class Recorder(Provider):
    name = "recorder"
    layer = "L9"

    def __init__(self):
        self.targets = []

    async def lookup(self, ctx):
        self.targets.append(ctx.target)
        return {"seen": ctx.target}


class Broken(Provider):
    name = "broken"
    layer = "L2"

    async def lookup(self, ctx):
        raise RuntimeError("bug in provider")


class Refusing(Provider):
    name = "refusing"
    layer = "L2"

    async def lookup(self, ctx):
        raise ProviderError("HTTP 429: quota exceeded")


class Slow(Provider):
    name = "slow"
    layer = "L2"

    async def lookup(self, ctx):
        await asyncio.sleep(5)
        return {}


class NeedsKey(Provider):
    name = "needs-key"
    layer = "L9"
    requires_key = "ABUSEIPDB_API_KEY"

    async def lookup(self, ctx):
        return {"key_used": ctx.config.key_for(self.requires_key)}


class Active(Provider):
    name = "active"
    layer = "L10"
    active = True

    async def lookup(self, ctx):
        return {"pinged": True}


def test_offline_only_report(config):
    report = run(analyze("8.8.8.8", config))
    assert report.ip == "8.8.8.8"
    assert report.version == 4
    assert report.lookup["eligible"] is True
    assert [r.provider for r in report.results] == ["offline"]
    assert report.result("offline").ok
    assert report.result("missing") is None


def test_invalid_input_raises(config):
    with pytest.raises(InvalidIPError):
        run(analyze("999.1.1.1", config))


def test_remote_provider_gets_embedded_ipv4_target(config):
    rec = Recorder()
    report = run(analyze("2002:808:808::1", config, default_providers() + [rec]))
    assert rec.targets == ["8.8.8.8"]
    assert report.result("recorder").data == {"seen": "8.8.8.8"}


def test_remote_provider_skipped_for_private_address(config):
    rec = Recorder()
    report = run(analyze("192.168.1.1", config, default_providers() + [rec]))
    assert rec.targets == []
    result = report.result("recorder")
    assert result.ok is False
    assert result.skipped == "address is not globally reachable"


def test_failures_are_isolated(config):
    providers = default_providers() + [Broken(), Refusing(), Recorder()]
    report = run(analyze("1.1.1.1", config, providers))
    assert report.result("broken").error == "unexpected RuntimeError: bug in provider"
    assert report.result("refusing").error == "HTTP 429: quota exceeded"
    assert report.result("recorder").ok is True


def test_timeout(config):
    fast = dataclasses.replace(config, timeout=0.05)
    report = run(analyze("1.1.1.1", fast, default_providers() + [Slow()]))
    assert report.result("slow").error == "timed out after 0.05s"


def test_missing_key_skips_and_present_key_runs(config):
    report = run(analyze("1.1.1.1", config, default_providers() + [NeedsKey()]))
    assert report.result("needs-key").skipped == "no API key (ABUSEIPDB_API_KEY in .env)"

    keyed = dataclasses.replace(config, api_keys={"ABUSEIPDB_API_KEY": "k"})
    report = run(analyze("1.1.1.1", keyed, default_providers() + [NeedsKey()]))
    assert report.result("needs-key").data == {"key_used": "k"}


def test_active_provider_needs_opt_in(config):
    report = run(analyze("1.1.1.1", config, default_providers() + [Active()]))
    assert "active probing is off" in report.result("active").skipped

    opted_in = dataclasses.replace(config, active_mode=True)
    report = run(analyze("1.1.1.1", opted_in, default_providers() + [Active()]))
    assert report.result("active").data == {"pinged": True}


def test_offline_failure_is_fatal(config):
    class BadOffline(Provider):
        name = "offline"
        layer = "L1"
        needs_public_ip = False

        async def lookup(self, ctx):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="Offline analysis failed"):
        run(analyze("1.1.1.1", config, [BadOffline()]))


def test_analyze_many_collects_errors(config):
    reports, errors = run(analyze_many(["8.8.8.8", "nope!", "::1"], config))
    assert [r.ip for r in reports] == ["8.8.8.8", "::1"]
    assert errors == [
        {"input": "nope!", "error": "'nope!' is not a valid IPv4 or IPv6 address", "hint": None}
    ]


def test_report_to_dict_round_trips_through_json(config):
    import json

    report = run(analyze("৮.৮.৮.৮", config))
    data = json.loads(json.dumps(report.to_dict()))
    assert data["ip"] == "8.8.8.8"
    assert data["notes"] and "Normalised" in data["notes"][0]
    assert data["results"][0]["provider"] == "offline"
