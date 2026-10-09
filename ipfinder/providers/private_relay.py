"""iCloud Private Relay: Apple publishes its egress ranges, with the approximate
region each range represents (RFC 8805 format). An address in this list is shared
by many Apple users of that region. It is a privacy relay, not a VPN service.
"""

from __future__ import annotations

from typing import Any

from ipfinder.providers.base import LookupContext, ProviderError
from ipfinder.providers.common import compact
from ipfinder.providers.list_base import ListProvider


class PrivateRelayProvider(ListProvider):
    name = "private-relay"
    layer = "L7"
    description = "iCloud Private Relay egress check (Apple's list, offline)"
    lists = ("private-relay",)

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {}
        dataset = await self.load(ctx, "private-relay", report)
        if dataset is None:
            raise ProviderError("; ".join(report.get("problems", [])) or "list not available")
        hit = dataset.index.longest(ctx.target)
        report["is_relay"] = hit is not None
        if hit:
            country, region, city = hit[1][0]
            report["prefix"] = hit[0]
            report["location"] = compact(
                {"country_code": country, "region_code": region, "city": city}
            )
        return report
