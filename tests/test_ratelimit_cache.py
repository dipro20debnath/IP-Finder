import pytest

from ipfinder.core.cache import Cache
from ipfinder.core.ratelimit import RateLimiter
from tests.conftest import run


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start
        self.sleeps = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def limiter(calls, period, clock, margin=0.5):
    return RateLimiter(calls, period, clock=clock, sleep=clock.sleep, margin=margin)


def test_allows_burst_then_waits_for_window():
    clock = FakeClock()
    lim = limiter(3, 60.0, clock)

    async def go():
        for _ in range(4):
            await lim.acquire()

    run(go())
    assert clock.sleeps == [60.5]  # 60 s window + 0.5 s safety margin


def test_ip_api_limit_is_never_exceeded():
    # Definition of done for Phase 2: 45 requests/minute is never broken.
    clock = FakeClock()
    lim = limiter(45, 60.0, clock)
    stamps = []

    async def go():
        for i in range(200):
            await lim.acquire()
            stamps.append(clock.now)
            clock.now += 0.1 * (i % 3)  # irregular gaps between requests

    run(go())
    for i, start in enumerate(stamps):
        in_window = [t for t in stamps[i:] if t - start < 60.0]
        assert len(in_window) <= 45


def test_server_pause_blocks_everyone():
    clock = FakeClock()
    lim = limiter(45, 60.0, clock)
    lim.block_for(37)

    async def go():
        return await lim.acquire()

    assert run(go()) == pytest.approx(37)


def test_invalid_limits_rejected():
    with pytest.raises(ValueError):
        RateLimiter(0, 60)


def test_cache_memory_and_ttl():
    clock = FakeClock()
    cache = Cache(None, clock=clock)
    cache.put("ip-api", "8.8.8.8", {"a": 1}, ttl=60)
    assert cache.get("ip-api", "8.8.8.8") == {"a": 1}
    clock.now += 61
    assert cache.get("ip-api", "8.8.8.8") is None
    cache.put("ip-api", "x", {"b": 2}, ttl=0)  # ttl 0 = do not cache
    assert cache.get("ip-api", "x") is None
    assert cache.persistent is False


def test_cache_persists_and_expires(tmp_path):
    clock = FakeClock()
    path = tmp_path / "sub" / "cache.sqlite"
    first = Cache(path, clock=clock)
    first.put("ip-api", "8.8.8.8", {"city": "Ashburn"}, ttl=100)
    first.put_error("ip-api", "1.1.1.1", "boom")
    first.close()

    second = Cache(path, clock=clock)
    assert second.persistent
    assert second.get("ip-api", "8.8.8.8") == {"city": "Ashburn"}
    assert second.get_error("ip-api", "1.1.1.1") is None  # errors are never persisted
    stats = second.stats()
    assert stats["providers"]["ip-api"] == {"entries": 1, "fresh": 1}
    clock.now += 101
    assert second.get("ip-api", "8.8.8.8") is None
    assert second.clear() == 1
    second.close()


def test_unusable_cache_path_falls_back_to_memory(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    cache = Cache(blocker / "cache.sqlite")
    assert cache.persistent is False
    assert "cache disabled" in cache.warning
    cache.put("p", "k", {"ok": True}, ttl=10)
    assert cache.get("p", "k") == {"ok": True}
