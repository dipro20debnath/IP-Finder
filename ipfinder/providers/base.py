"""The interface every data source implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ipfinder.core.config import Config
from ipfinder.core.validator import ParsedInput


class ProviderError(Exception):
    """A provider could not produce data (network error, bad response, quota...)."""


@dataclass
class LookupContext:
    parsed: ParsedInput
    config: Config
    target: str | None = None  # address online providers should query (from the L1 decision)
    http: Any = None  # shared HTTP client, added in Phase 2


class Provider(ABC):
    name: str = "provider"
    layer: str = "L?"
    description: str = ""
    requires_key: str | None = None  # environment variable name, e.g. "ABUSEIPDB_API_KEY"
    needs_public_ip: bool = True  # skip when the address is private/reserved
    active: bool = False  # sends packets to the target; runs only in --active mode

    def skip_reason(self, ctx: LookupContext) -> str | None:
        """Why this provider must not run for ``ctx``, or None if it may run."""
        if self.active and not ctx.config.active_mode:
            return "active probing is off (use --active on systems you are authorised to test)"
        if self.requires_key and not ctx.config.key_for(self.requires_key):
            return f"no API key ({self.requires_key} in .env)"
        if self.needs_public_ip and ctx.target is None:
            return "address is not globally reachable"
        return None

    @abstractmethod
    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        """Return this provider's data, or raise ProviderError."""
