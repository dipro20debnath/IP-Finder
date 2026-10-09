"""Known VPN-provider and datacenter networks, from X4BNet lists_vpn (MIT licence,
github.com/X4BNet/lists_vpn): IPv4 blocks, plus ASN lists that also cover IPv6.

These are community lists: a match means "this network is listed as VPN /
datacenter", not proof that a given connection used a VPN, and VPNs that are not
listed are not caught. Runs after the ASN is known (stage 2).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.providers.base import LookupContext, ProviderError
from ipfinder.providers.list_base import ListProvider
from ipfinder.providers.peeringdb import known_asn

KINDS = (
    ("vpn", "vpn-networks", "vpn-asns"),
    ("datacenter", "datacenter-networks", "datacenter-asns"),
)


class VPNListsProvider(ListProvider):
    name = "vpn-lists"
    layer = "L7"
    description = "Known VPN / datacenter network check (X4BNet lists, offline)"
    stage = 2
    lists = tuple(name for _, nets, asns in KINDS for name in (nets, asns))

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {}
        asn = known_asn(ctx)
        for kind, nets_name, asns_name in KINDS:
            evidence = []
            nets = await self.load(ctx, nets_name, report)
            if nets is not None:
                hit = nets.index.longest(ctx.target)
                if hit:
                    evidence.append({"type": "prefix", "value": hit[0]})
            asns = await self.load(ctx, asns_name, report)
            if asns is not None and asn is not None and asn in asns.asns:
                evidence.append({"type": "asn", "value": f"AS{asn}", "name": asns.asns[asn]})
            report[kind] = {"listed": bool(evidence), "evidence": evidence}
        if not report.get("lists"):
            raise ProviderError("; ".join(report.get("problems", [])) or "no VPN list available")
        if asn is not None:
            report["asn"] = asn
        if ipaddress.ip_address(ctx.target).version == 6 and asn is None:
            report["note"] = (
                "the block lists are IPv4-only and no ASN was found, so IPv6 was not checked"
            )
        return report
