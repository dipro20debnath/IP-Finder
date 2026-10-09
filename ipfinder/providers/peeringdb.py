"""PeeringDB: what kind of network owns the address (ISP, content, education...).

Runs after the ASN is known (stage 2). Anonymous reads are allowed; an API key
(header "Authorization: Api-Key <key>") is optional.
Request: https://www.peeringdb.com/api/net?asn=15169
"""

from __future__ import annotations

from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import DAY, LookupContext, Provider
from ipfinder.providers.common import compact

URL = "https://www.peeringdb.com/api/net"
ASN_SOURCES = ("team-cymru", "maxmind", "ipinfo-lite", "ip-api")


def known_asn(ctx: LookupContext) -> int | None:
    for name in ASN_SOURCES:
        result = ctx.results.get(name)
        if result is not None and result.ok:
            asn = (result.data.get("network") or {}).get("asn")
            if isinstance(asn, int):
                return asn
    return None


class PeeringDBProvider(Provider):
    name = "peeringdb"
    layer = "L3"
    description = "Network type, scope and peering policy for the ASN"
    stage = 2
    cache_ttl = 7 * DAY
    # PeeringDB throttles anonymous clients; this local limit is deliberately polite.
    rate_limit = (10, 60.0)

    def skip_reason(self, ctx: LookupContext) -> str | None:
        reason = super().skip_reason(ctx)
        if reason:
            return reason
        if known_asn(ctx) is None:
            return "no ASN found by the other sources"
        return None

    def cache_key(self, ctx: LookupContext) -> str | None:
        asn = known_asn(ctx)
        return f"AS{asn}" if asn is not None else None

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        asn = known_asn(ctx)
        key = ctx.config.key_for("PEERINGDB_API_KEY")
        headers = {"Authorization": f"Api-Key {key}"} if key else None
        _, data = await request_json(
            ctx.session,
            "GET",
            URL,
            params={"asn": asn},
            headers=headers,
            limiter=ctx.session.limiter(self.name, *self.rate_limit),
        )
        rows = data.get("data") if isinstance(data, dict) else None
        if not rows:
            return {"asn": asn, "network_info": None, "note": "AS not registered in PeeringDB"}
        net = rows[0]
        types = net.get("info_types") or ([net["info_type"]] if net.get("info_type") else [])
        info = compact(
            {
                "name": net.get("name"),
                "aka": net.get("aka"),
                "website": net.get("website"),
                "scope": net.get("info_scope"),
                "traffic": net.get("info_traffic"),
                "ratio": net.get("info_ratio"),
                "prefixes4": net.get("info_prefixes4"),
                "prefixes6": net.get("info_prefixes6"),
                "policy": net.get("policy_general"),
                "irr_as_set": net.get("irr_as_set"),
            }
        )
        info["types"] = [t for t in types if t]
        if net.get("id") is not None:
            info["url"] = f"https://www.peeringdb.com/net/{net['id']}"
        return {"asn": asn, "network_info": info, "raw": net}
