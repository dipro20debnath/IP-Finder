"""Team Cymru IP-to-ASN mapping over DNS (free, no key, BGP data from 50+ peers).

  dig +short TXT 8.8.8.8.origin.asn.cymru.com
  "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
     ASN(s) | announced prefix | registry country | RIR | allocation date
  IPv6: reversed nibbles + .origin6.asn.cymru.com
  AS name: dig +short TXT AS15169.asn.cymru.com
  "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
An address with no BGP announcement has no record (NXDOMAIN).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.core.dns import DNSLookupError
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError


def origin_query(target: str) -> str:
    ip = ipaddress.ip_address(target)
    if ip.version == 4:
        return ip.reverse_pointer.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
    return ip.reverse_pointer.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"


def _fields(record: str) -> list[str]:
    return [part.strip() for part in record.strip().strip('"').split("|")]


def parse_origin(records: list[str]) -> dict[str, Any]:
    """Pick the most specific announced prefix when several are returned."""
    best = None
    for record in records:
        fields = _fields(record)
        if len(fields) < 4:
            continue
        try:
            asns = [int(a) for a in fields[0].split()]
            prefix = ipaddress.ip_network(fields[1], strict=False)
        except ValueError:
            continue
        if not asns:
            continue
        candidate = {
            "asn": asns[0],
            "origin_asns": asns,
            "prefix": str(prefix),
            "country_code": fields[2] or None,
            "rir": fields[3].upper() or None,
            "allocated": fields[4] if len(fields) > 4 and fields[4] else None,
        }
        if best is None or prefix.prefixlen > ipaddress.ip_network(best["prefix"]).prefixlen:
            best = candidate
    if best is None:
        raise ProviderError("Team Cymru returned no usable origin record")
    return best


def parse_as_name(records: list[str]) -> str | None:
    for record in records:
        fields = _fields(record)
        if len(fields) >= 5 and fields[4]:
            return fields[4]
    return None


# Google's AS name record; it always exists, so a failure means DNS is blocked.
CANARY = "AS15169.asn.cymru.com"


class TeamCymruProvider(Provider):
    name = "team-cymru"
    layer = "L3"
    description = "BGP origin ASN, announced prefix, RIR, allocation date (DNS, no key)"
    cache_ttl = DAY

    async def _dns_reaches_cymru(self, session) -> bool:
        """Some networks (and sandboxes) answer NXDOMAIN for every name. Check a
        record that always exists before concluding "not announced"."""
        key = "team-cymru-dns-check"
        if key not in session.resources:
            try:
                session.resources[key] = bool(await session.dns_resolve(CANARY))
            except DNSLookupError:
                session.resources[key] = False
        return session.resources[key]

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        resolve = ctx.session.dns_resolve
        try:
            records = await resolve(origin_query(ctx.target))
        except DNSLookupError as exc:
            if not exc.nxdomain:
                raise ProviderError(str(exc)) from None
            if await self._dns_reaches_cymru(ctx.session):
                raise ProviderError("no BGP origin record (address not announced)") from None
            raise ProviderError(
                "your DNS resolver cannot reach asn.cymru.com (blocked or filtered), "
                "so BGP origin is unknown"
            ) from None
        network = parse_origin(records)
        try:
            network["as_name"] = parse_as_name(await resolve(f"AS{network['asn']}.asn.cymru.com"))
        except DNSLookupError:
            network["as_name"] = None
        network = {k: v for k, v in network.items() if v is not None}
        return {"network": network, "raw": records}
