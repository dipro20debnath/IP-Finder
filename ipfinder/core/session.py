"""Everything shared by the lookups of one run: settings, HTTP client, DNS resolver,
cache, rate limiters, opened databases and downloaded lists."""

from __future__ import annotations

from typing import Any

import httpx

from ipfinder import __version__
from ipfinder.core.cache import Cache
from ipfinder.core.config import Config
from ipfinder.core.dns import resolve_records as default_dns_resolve
from ipfinder.core.ratelimit import RateLimiter
from ipfinder.lists.store import ListStore

USER_AGENT = f"ip-finder/{__version__} (+https://github.com/dipro20debnath/IP-Finder)"


def make_http_client(config: Config) -> httpx.AsyncClient:
    """One HTTP client per run (connection reuse, proxy settings from the environment)."""
    return httpx.AsyncClient(
        timeout=config.timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


async def _view_close() -> None:
    """Closing a view must not close the shared client, cache or databases."""


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
        self.lists = ListStore(config.lists_dir)  # downloaded lists, parsed on first use
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

    def with_config(self, config: Config) -> Session:
        """This session's HTTP client, cache, lists, databases and rate limiters with
        other settings (profile, active mode). The web dashboard runs every request
        through one shared session this way, so a rate limit holds across browser
        tabs. The view owns nothing: close the original session, never the view."""
        view = object.__new__(Session)
        view.__dict__.update(self.__dict__)
        view.config = config
        view._own_http = False
        view.close = _view_close
        return view

    def limiter(self, name: str, calls: int, period: float) -> RateLimiter:
        """One shared limiter per name for the whole run."""
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(calls, period)
        return self._limiters[name]
