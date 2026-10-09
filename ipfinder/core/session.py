"""Everything shared by the lookups of one run: settings, HTTP client, DNS resolver,
cache, rate limiters and opened databases."""

from __future__ import annotations

from typing import Any

import httpx

from ipfinder import __version__
from ipfinder.core.cache import Cache
from ipfinder.core.config import Config
from ipfinder.core.dns import resolve_txt as default_dns_resolve
from ipfinder.core.ratelimit import RateLimiter

USER_AGENT = f"ip-finder/{__version__} (+https://github.com/dipro20debnath/IP-Finder)"


def make_http_client(config: Config) -> httpx.AsyncClient:
    """One HTTP client per run (connection reuse, proxy settings from the environment)."""
    return httpx.AsyncClient(
        timeout=config.timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


class Session:
    def __init__(
        self,
        config: Config,
        http: httpx.AsyncClient | None = None,
        cache: Cache | None = None,
        dns_resolve=None,
    ):
        self.config = config
        self._own_http = http is None
        self.http = http
        self.cache = (
            cache if cache is not None else Cache(config.cache_path if config.use_cache else None)
        )
        self.dns_resolve = dns_resolve or default_dns_resolve
        self.resources: dict[str, Any] = {}  # e.g. opened MaxMind readers
        self._limiters: dict[str, RateLimiter] = {}

    async def __aenter__(self) -> Session:
        if self.http is None:
            self.http = make_http_client(self.config)
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        if self._own_http and self.http is not None:
            await self.http.aclose()
            self.http = None
        for resource in self.resources.values():
            close = getattr(resource, "close", None)
            if close:
                close()
        self.resources.clear()
        self.cache.close()

    def limiter(self, name: str, calls: int, period: float) -> RateLimiter:
        """One shared limiter per name for the whole run."""
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(calls, period)
        return self._limiters[name]
