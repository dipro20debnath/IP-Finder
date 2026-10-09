"""The interface every data source implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ipfinder.core.config import Config
from ipfinder.core.validator import ParsedInput

HOUR = 3600
DAY = 24 * HOUR


class ProviderError(Exception):
    """A provider could not produce data (network error, bad response, quota...)."""


@dataclass
class LookupContext:
    parsed: ParsedInput
    config: Config
    target: str | None = None  # address online providers should query (from the L1 decision)
    session: Any = None  # ipfinder.core.session.Session
    results: dict[str, Any] = field(default_factory=dict)  # earlier stages, by provider name


class Provider(ABC):
    name: str = "provider"
    layer: str = "L?"
    description: str = ""
    stage: int = 1  # 0 = local analysis, 1 = independent lookups, 2 = needs stage-1 data
    profiles: tuple[str, ...] = ("standard", "full")
    requires_key: str | None = None  # environment variable name, e.g. "ABUSEIPDB_API_KEY"
    needs_public_ip: bool = True  # skip when the address is private/reserved
    active: bool = False  # sends packets to the target; runs only in --active mode
    cache_ttl: int = 0  # seconds; 0 = never cache
    rate_limit: tuple[int, float] | None = None  # (calls, per seconds), client-side

    def required_files(self, config: Config) -> list[Path]:
        """Local files this provider needs; it is skipped if none of them exist."""
        return []

    def unavailable_reason(self, config: Config) -> str | None:
        """Reasons that depend only on settings (profile, key, files)."""
        if config.profile not in self.profiles:
            return f"not part of the '{config.profile}' profile"
        if self.active and not config.active_mode:
            return "active probing is off (use --active on systems you are authorised to test)"
        if self.requires_key and not config.key_for(self.requires_key):
            return f"no API key ({self.requires_key} in .env)"
        files = self.required_files(config)
        if files and not any(path.is_file() for path in files):
            names = ", ".join(str(p) for p in files)
            return f"database not found ({names}; see data/README.md)"
        return None

    def skip_reason(self, ctx: LookupContext) -> str | None:
        """Why this provider must not run for ``ctx``, or None if it may run."""
        reason = self.unavailable_reason(ctx.config)
        if reason:
            return reason
        if self.needs_public_ip and ctx.target is None:
            return "address is not globally reachable"
        return None

    def cache_key(self, ctx: LookupContext) -> str | None:
        return ctx.target

    async def wait_turn(self, ctx: LookupContext) -> None:
        """Wait for a free rate-limit slot. Runs before ``lookup`` and outside its timeout;
        must not raise ProviderError (``lookup`` reports problems)."""
        if self.rate_limit:
            await ctx.session.limiter(self.name, *self.rate_limit).acquire()

    async def prefetch(self, targets: list[str], session) -> None:
        """Optionally fetch many targets at once into the session cache."""
        return None

    @abstractmethod
    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        """Return this provider's data, or raise ProviderError."""
