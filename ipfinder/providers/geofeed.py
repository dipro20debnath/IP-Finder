"""Geofeed: the location the network operator itself publishes for its prefixes.

Format (RFC 8805), one CSV line per prefix, '#' starts a comment:
  ip_prefix,alpha2code,region,city,postal_code
  192.0.2.0/24,US,US-CA,Mountain View,
The file is found through the registry record (RFC 9632; the URL comes from RDAP).
RFC 9632 rules applied here: the file is fetched over HTTPS only, and an entry is
used only if its prefix lies inside the registered network that points to the file
(otherwise anyone could publish locations for other people's addresses).
Optional RPKI signatures ("# RPKI Signature:") are reported but not verified.
"""

from __future__ import annotations

import csv
import ipaddress
from typing import Any

from ipfinder.core.http import fetch_text
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import compact

MAX_BYTES = 10_000_000
MAX_URLS = 2


def parse_geofeed(text: str) -> tuple[list[tuple[Any, dict]], bool]:
    """-> ([(network, location)], has_signature). Malformed lines are skipped."""
    entries = []
    signed = False
    for line in text.lstrip("﻿").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            signed = signed or line.lower().startswith("# rpki signature:")
            continue
        row = next(csv.reader([line]), [])
        if not row:
            continue
        try:
            network = ipaddress.ip_network(row[0].strip())  # host bits set = malformed
        except ValueError:
            continue
        fields = [field.strip() for field in row[1:5]] + [""] * 4
        entries.append(
            (
                network,
                compact(
                    {
                        "country_code": fields[0].upper(),
                        "region_code": fields[1].upper(),
                        "city": fields[2],
                        "postal_code": fields[3],
                    }
                ),
            )
        )
    return entries, signed


def best_entry(entries, target: str, allowed: list) -> tuple[Any, dict, int]:
    """Longest matching prefix inside ``allowed``; also counts matches outside it."""
    ip = ipaddress.ip_address(target)
    best, outside = None, 0
    for network, location in entries:
        if network.version != ip.version or ip not in network:
            continue
        if not any(network.version == a.version and network.subnet_of(a) for a in allowed):
            outside += 1
            continue
        if best is None or network.prefixlen > best[0].prefixlen:
            best = (network, location)
    return (best[0], best[1], outside) if best else (None, None, outside)


def _rdap(ctx: LookupContext) -> dict | None:
    result = ctx.results.get("rdap")
    return result.data if result is not None and result.ok else None


class GeofeedProvider(Provider):
    name = "geofeed"
    layer = "L2"
    description = "Location published by the network operator itself (RFC 8805 / 9632)"
    stage = 2
    cache_ttl = DAY

    def skip_reason(self, ctx: LookupContext) -> str | None:
        reason = super().skip_reason(ctx)
        if reason:
            return reason
        rdap = _rdap(ctx)
        if rdap is None:
            return "needs the RDAP registration record"
        if not rdap.get("geofeed_urls"):
            return "the registration record names no geofeed file"
        return None

    def cache_key(self, ctx: LookupContext) -> str | None:
        rdap = _rdap(ctx) or {}
        urls = rdap.get("geofeed_urls") or []
        return f"{urls[0]}|{ctx.target}" if urls else None

    async def _load(self, session, url: str) -> tuple[list, bool]:
        key = f"geofeed:{url}"
        if key not in session.resources:
            text = await fetch_text(session, url, max_bytes=MAX_BYTES)
            session.resources[key] = parse_geofeed(text)
        return session.resources[key]

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        rdap = _rdap(ctx)
        allowed = []
        for cidr in rdap.get("registration", {}).get("cidrs", []):
            try:
                allowed.append(ipaddress.ip_network(cidr))
            except ValueError:
                continue
        if not allowed:
            raise ProviderError("the registration record has no usable address range")

        errors, first_miss = [], None
        for url in rdap["geofeed_urls"][:MAX_URLS]:
            try:
                entries, signed = await self._load(ctx.session, url)
            except ProviderError as exc:
                errors.append(str(exc))
                continue
            network, location, outside = best_entry(entries, ctx.target, allowed)
            result: dict[str, Any] = {"url": url, "entries": len(entries), "signed": signed}
            if network is not None:
                result["prefix"] = str(network)
                result["location"] = location
                return result
            result["note"] = (
                f"the file lists this address only outside the registered range "
                f"({outside} entr{'y' if outside == 1 else 'ies'} ignored, RFC 9632)"
                if outside
                else "the file has no entry for this address"
            )
            first_miss = first_miss or result
        if first_miss is not None:
            return first_miss
        raise ProviderError(f"geofeed download failed: {errors[0]}")
