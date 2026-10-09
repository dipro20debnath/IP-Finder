import asyncio
import dataclasses
import json

import pytest

from ipfinder.core.cache import Cache
from ipfinder.core.orchestrator import analyze
from ipfinder.core.session import Session
from ipfinder.core.validator import InvalidIPError
from ipfinder.providers.base import Provider, ProviderError
from ipfinder.providers.offline import OfflineProvider
from tests.conftest import analyze_many_with, analyze_with, run


def offline_plus(*extra):
    return [OfflineProvider(), *extra]


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


class Counting(Provider):
    """Cacheable provider that counts real lookups."""

    name = "counting"
    layer = "L2"
    cache_ttl = 3600

    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    async def lookup(self, ctx):
        self.calls += 1
        if self.fail:
            raise ProviderError("upstream said no")
        return {"network": {"asn": 64500}}


class SeesEarlierStages(Provider):
    name = "stage-two"
    layer = "L3"
    stage = 2

    async def lookup(self, ctx):
        return {"saw": sorted(ctx.results)}


def test_offline_only_report(config):
    report = analyze_with("8.8.8.8", config, offline_plus())
    assert report.ip == "8.8.8.8"
    assert report.version == 4
    assert report.lookup["eligible"] is True
    assert [r.provider for r in report.results] == ["offline"]
    assert report.result("offline").ok
    assert report.result("missing") is None


def test_invalid_input_raises(config):
    with pytest.raises(InvalidIPError):
        analyze_with("999.1.1.1", config, offline_plus())


def test_remote_provider_gets_embedded_ipv4_target(config):
    rec = Recorder()
    report = analyze_with("2002:808:808::1", config, offline_plus(rec))
    assert rec.targets == ["8.8.8.8"]
    assert report.result("recorder").data == {"seen": "8.8.8.8"}


def test_remote_provider_skipped_for_private_address(config):
    rec = Recorder()
    report = analyze_with("192.168.1.1", config, offline_plus(rec))
    assert rec.targets == []
    result = report.result("recorder")
    assert result.ok is False
    assert result.skipped == "address is not globally reachable"


def test_failures_are_isolated(config):
    report = analyze_with("1.1.1.1", config, offline_plus(Broken(), Refusing(), Recorder()))
    assert report.result("broken").error == "unexpected RuntimeError: bug in provider"
    assert report.result("refusing").error == "HTTP 429: quota exceeded"
    assert report.result("recorder").ok is True


def test_timeout(config):
    fast = dataclasses.replace(config, timeout=0.05)
    report = analyze_with("1.1.1.1", fast, offline_plus(Slow()))
    assert report.result("slow").error == "timed out after 0.05s"


def test_missing_key_skips_and_present_key_runs(config):
    report = analyze_with("1.1.1.1", config, offline_plus(NeedsKey()))
    assert report.result("needs-key").skipped == "no API key (ABUSEIPDB_API_KEY in .env)"

    keyed = dataclasses.replace(config, api_keys={"ABUSEIPDB_API_KEY": "k"})
    report = analyze_with("1.1.1.1", keyed, offline_plus(NeedsKey()))
    assert report.result("needs-key").data == {"key_used": "k"}


def test_active_provider_needs_opt_in(config):
    report = analyze_with("1.1.1.1", config, offline_plus(Active()))
    assert "active probing is off" in report.result("active").skipped

    opted_in = dataclasses.replace(config, active_mode=True)
    report = analyze_with("1.1.1.1", opted_in, offline_plus(Active()))
    assert report.result("active").data == {"pinged": True}


def test_profile_filters_providers(config):
    quick = dataclasses.replace(config, profile="quick")
    report = analyze_with("1.1.1.1", quick, offline_plus(Recorder()))
    assert report.result("recorder").skipped == "not part of the 'quick' profile"


def test_offline_failure_is_fatal(config):
    class BadOffline(Provider):
        name = "offline"
        layer = "L1"
        needs_public_ip = False
        stage = 0
        profiles = ("quick", "standard", "full")

        async def lookup(self, ctx):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="Offline analysis failed"):
        analyze_with("1.1.1.1", config, [BadOffline()])


def test_stage_two_sees_stage_one_results(config):
    report = analyze_with("1.1.1.1", config, offline_plus(Recorder(), SeesEarlierStages()))
    assert report.result("stage-two").data == {"saw": ["offline", "recorder"]}


def test_results_are_cached_between_lookups(config):
    counting = Counting()

    async def go():
        async with Session(config, cache=Cache(None)) as session:
            first = await analyze("1.1.1.1", session, offline_plus(counting))
            second = await analyze("1.1.1.1", session, offline_plus(counting))
            return first, second

    first, second = run(go())
    assert counting.calls == 1
    assert first.result("counting").cached is False
    assert second.result("counting").cached is True
    assert second.result("counting").data == {"network": {"asn": 64500}}


def test_persistent_cache_survives_sessions(config, tmp_path):
    path = tmp_path / "cache.sqlite"
    counting = Counting()
    analyze_with("1.1.1.1", config, offline_plus(counting), cache=Cache(path))
    report = analyze_with("1.1.1.1", config, offline_plus(counting), cache=Cache(path))
    assert counting.calls == 1
    assert report.result("counting").cached is True


def test_failures_are_remembered_for_the_run_only(config, tmp_path):
    path = tmp_path / "cache.sqlite"
    counting = Counting(fail=True)

    async def go():
        async with Session(config, cache=Cache(path)) as session:
            await analyze("1.1.1.1", session, offline_plus(counting))
            return await analyze("1.1.1.1", session, offline_plus(counting))

    report = run(go())
    assert counting.calls == 1
    assert report.result("counting").error == "upstream said no"
    analyze_with("1.1.1.1", config, offline_plus(counting), cache=Cache(path))
    assert counting.calls == 2  # not persisted: a new run tries again


def test_rate_limit_wait_does_not_count_against_timeout(config):
    class Limited(Recorder):
        name = "limited"
        rate_limit = (1, 60.0)

    async def go():
        async with Session(dataclasses.replace(config, timeout=0.05)) as session:
            limiter = session.limiter("limited", 1, 60.0)
            waits = []

            async def fake_sleep(seconds):
                waits.append(seconds)
                limiter._blocked_until = 0.0
                limiter._stamps.clear()

            limiter._sleep = fake_sleep
            limiter.block_for(30)
            report = await analyze("1.1.1.1", session, offline_plus(Limited()))
            return report, waits

    report, waits = run(go())
    assert report.result("limited").ok is True
    assert waits and waits[0] == pytest.approx(30, abs=1)


def test_analyze_many_collects_errors(config):
    reports, errors = analyze_many_with(["8.8.8.8", "nope!", "::1"], config, offline_plus())
    assert [r.ip for r in reports] == ["8.8.8.8", "::1"]
    assert errors == [
        {"input": "nope!", "error": "'nope!' is not a valid IPv4 or IPv6 address", "hint": None}
    ]


def test_report_to_dict_round_trips_through_json(config):
    report = analyze_with("৮.৮.৮.৮", config, offline_plus())
    data = json.loads(json.dumps(report.to_dict()))
    assert data["ip"] == "8.8.8.8"
    assert data["notes"] and "Normalised" in data["notes"][0]
    assert data["results"][0]["provider"] == "offline"
    assert "summary" in data


def test_analyze_many_survives_unexpected_value_error(config, monkeypatch):
    import ipfinder.core.orchestrator as orch

    real = orch.parse_ip

    def flaky(raw):
        if raw == "boom":
            raise ValueError("Exceeds the limit (4300 digits)")
        return real(raw)

    monkeypatch.setattr(orch, "parse_ip", flaky)
    reports, errors = analyze_many_with(["8.8.8.8", "boom", "1.1.1.1"], config, offline_plus())
    assert [r.ip for r in reports] == ["8.8.8.8", "1.1.1.1"]
    assert errors[0]["input"] == "boom"
    assert "4300 digits" in errors[0]["error"]


def test_batch_failure_is_noted_and_lookups_continue(config):
    class FailingBatch(Recorder):
        name = "batchy"

        async def prefetch(self, targets, session):
            raise ProviderError("batch endpoint down")

    reports, _ = analyze_many_with(["8.8.8.8", "1.1.1.1"], config, offline_plus(FailingBatch()))
    assert all(r.result("batchy").ok for r in reports)
    assert "batchy batch lookup failed (batch endpoint down)" in reports[0].notes[0]
