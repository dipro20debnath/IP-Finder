from __future__ import annotations

from typing import Any

from ipfinder.analysis import offline
from ipfinder.analysis.oui import make_lookup
from ipfinder.providers.base import LookupContext, Provider


class OfflineProvider(Provider):
    name = "offline"
    layer = "L1"
    description = "Address type, RFC, representations, IPv6 insights (no network)"
    needs_public_ip = False

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        oui_lookup = make_lookup(ctx.config.oui_db_path)
        data = offline.analyze(ctx.parsed, oui_lookup)
        data["oui_database"] = "loaded" if oui_lookup else "not found"
        return data
