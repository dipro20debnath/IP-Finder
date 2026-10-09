"""Client-side rate limiting, so IP Finder never breaks a provider's free-tier limit.

Two mechanisms work together:
  * a sliding window: at most ``calls`` requests in any ``period`` seconds
    (e.g. ip-api's documented 45 requests/minute);
  * server-driven pauses: when a provider says "stop" (ip-api's X-Rl: 0 with
    X-Ttl, or HTTP 429 with Retry-After) nobody calls it until the pause ends.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    def __init__(
        self,
        calls: int,
        period: float,
        clock=time.monotonic,
        sleep=asyncio.sleep,
        margin: float = 0.5,
    ):
        if calls < 1 or period <= 0 or margin < 0:
            raise ValueError("calls must be >= 1, period > 0 and margin >= 0")
        self.calls = calls
        # The provider measures its window with its own clock, and requests take time
        # to arrive; a small margin keeps us safely inside the limit.
        self.period = period + margin
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()
        self._blocked_until = 0.0
        self._lock = asyncio.Lock()

    def _wait_time(self, now: float) -> float:
        # Use one expression (stamp + period vs now) for both expiry and waiting;
        # "now - stamp >= period" can round differently and let one call too many in.
        while self._stamps and self._stamps[0] + self.period <= now:
            self._stamps.popleft()
        wait = self._blocked_until - now
        if len(self._stamps) >= self.calls:
            wait = max(wait, self._stamps[0] + self.period - now)
        return max(wait, 0.0)

    async def acquire(self) -> float:
        """Wait for a free slot; returns the seconds spent waiting."""
        waited = 0.0
        async with self._lock:
            while True:
                wait = self._wait_time(self._clock())
                if wait <= 0:
                    self._stamps.append(self._clock())
                    return waited
                await self._sleep(wait)
                waited += wait

    def block_for(self, seconds: float) -> None:
        """Pause every caller for ``seconds`` (server asked us to back off)."""
        self._blocked_until = max(self._blocked_until, self._clock() + max(seconds, 0.0))
