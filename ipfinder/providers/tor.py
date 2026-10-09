"""Is the address a Tor exit relay? Checked against the Tor Project's own lists:

  torbulkexitlist   exits whose policy lets them reach the check server
  exit-addresses    addresses actually seen exiting in the Tor Project's tests,
                    with the relay fingerprint and the test time
Both are downloaded by "ipfinder update-lists" (they change every hour).
Being a Tor exit says who relays the traffic, not who sent it.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.lists.specs import TOR_LISTS
from ipfinder.providers.base import LookupContext, ProviderError
from ipfinder.providers.list_base import ListProvider

RELAY_SEARCH = "https://metrics.torproject.org/rs.html#details/{}"


class TorProvider(ListProvider):
    name = "tor"
    layer = "L7"
    description = "Tor exit relay check (Tor Project exit lists, offline)"
    lists = TOR_LISTS

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {"matched": []}
        relays: dict[str, dict] = {}
        ipv6_listed = False
        for name in self.lists:
            dataset = await self.load(ctx, name, report)
            if dataset is None:
                continue
            ipv6_listed = ipv6_listed or 6 in dataset.index.versions
            hit = dataset.index.longest(ctx.target)
            if hit:
                report["matched"].append(name)
                for value in hit[1]:
                    if isinstance(value, dict) and value.get("fingerprint"):
                        relay = dict(value)
                        relay["relay_search"] = RELAY_SEARCH.format(value["fingerprint"])
                        relays.setdefault(value["fingerprint"], relay)
        if not report.get("lists"):
            raise ProviderError("; ".join(report.get("problems", [])) or "no Tor list available")
        report["is_exit"] = bool(report["matched"])
        report["relays"] = list(relays.values())[:5]
        if ipaddress.ip_address(ctx.target).version == 6 and not ipv6_listed:
            report["note"] = (
                "the Tor Project's exit lists hold no IPv6 addresses, so an IPv6 Tor exit "
                "cannot be recognised"
            )
        return report
