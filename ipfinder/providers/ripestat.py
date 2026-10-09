"""RIPEstat Data API (RIPE NCC, free, no key; covers every RIR's address space):
BGP announcement, RPKI route-origin validation, visibility, neighbours, abuse contact.

  https://stat.ripe.net/data/<call>/data.json?resource=...&sourceapp=ip-finder
  prefix-overview       announced?, covering prefix, origin AS(es) and holder name
  rpki-validation       resource=AS<n>&prefix=<p> -> valid / invalid_asn /
                        invalid_length / unknown (no ROA covers the route)
  routing-status        first/last seen in BGP, how many RIS peers see the prefix
  asn-neighbours        ASes adjacent to the origin in observed AS paths
  abuse-contact-finder  abuse e-mail from the RIR database
Every answer is wrapped as {"status": "ok", "data": {...}, "messages": [...]}.
Usage limit: at most 8 concurrent requests per client IP; IP Finder sends at most
5 at once and sets sourceapp, as the RIPEstat documentation asks.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

URL = "https://stat.ripe.net/data/{}/data.json"
SOURCEAPP = "ip-finder"
MAX_ORIGINS = 3  # validate at most this many origin ASes of one prefix (MOAS)
TOP_NEIGHBOURS = 5


def unwrap(call: str, payload: Any) -> dict:
    """The "data" member of a RIPEstat answer, or ProviderError with its message."""
    if isinstance(payload, dict) and payload.get("status") == "ok":
        if isinstance(payload.get("data"), dict):
            return payload["data"]
    detail = None
    if isinstance(payload, dict):
        for message in payload.get("messages") or []:
            if isinstance(message, list) and len(message) == 2 and message[0] == "error":
                detail = clean(str(message[1]))
                break
    raise ProviderError(f"RIPEstat {call}: {detail or 'unexpected response'}")


def _int(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().removeprefix("AS").isdigit():
        return int(value.strip().removeprefix("AS"))
    return None


def parse_overview(data: dict) -> dict[str, Any]:
    origins = []
    for entry in data.get("asns") or []:
        asn = _int(entry.get("asn")) if isinstance(entry, dict) else None
        if asn is not None:
            origins.append({"asn": asn, "holder": clean(entry.get("holder"))})
    announced = bool(data.get("announced")) and bool(origins)
    out: dict[str, Any] = {"announced": announced}
    if announced:
        out["prefix"] = clean(data.get("resource"))
        out["origins"] = origins
    return out


def parse_rpki(asn: int, data: dict) -> dict[str, Any]:
    roas = []
    for roa in data.get("validating_roas") or []:
        if not isinstance(roa, dict):
            continue
        roas.append(
            {
                "origin": _int(roa.get("origin")),
                "prefix": clean(roa.get("prefix")),
                "max_length": _int(roa.get("max_length")),
                "validity": clean(roa.get("validity")),
            }
        )
    return {"origin": asn, "status": clean(data.get("status")) or "unknown", "roas": roas[:10]}


def parse_routing(data: dict, version: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("first_seen", "last_seen"):
        seen = data.get(key)
        if isinstance(seen, dict) and seen.get("time"):
            out[key] = compact_seen(seen)
    visibility = (data.get("visibility") or {}).get(f"v{version}")
    if isinstance(visibility, dict):
        seeing = _int(visibility.get("ris_peers_seeing"))
        total = _int(visibility.get("total_ris_peers"))
        if seeing is not None and total:
            out["visibility"] = {"ris_peers_seeing": seeing, "total_ris_peers": total}
    return out


def compact_seen(seen: dict) -> dict[str, Any]:
    out = {"time": str(seen["time"])}
    if seen.get("prefix"):
        out["prefix"] = str(seen["prefix"])
    origin = _int(seen.get("origin"))
    if origin is not None:
        out["origin"] = origin
    return out


def parse_neighbours(data: dict) -> dict[str, Any]:
    counts = data.get("neighbour_counts") or {}
    by_side: dict[str, list] = {"left": [], "right": []}
    for entry in data.get("neighbours") or []:
        if not isinstance(entry, dict) or entry.get("type") not in by_side:
            continue
        asn = _int(entry.get("asn"))
        if asn is not None:
            by_side[entry["type"]].append((_int(entry.get("power")) or 0, asn))
    out: dict[str, Any] = {
        "upstream_side": _int(counts.get("left")),
        "downstream_side": _int(counts.get("right")),
    }
    for side, key in (("left", "top_upstream_side"), ("right", "top_downstream_side")):
        ranked = sorted(by_side[side], key=lambda pair: (-pair[0], pair[1]))
        out[key] = [asn for _, asn in ranked[:TOP_NEIGHBOURS]]
    return {k: v for k, v in out.items() if v not in (None, [])}


class RIPEstatProvider(Provider):
    name = "ripestat"
    layer = "L5"
    description = "BGP prefix and origin, RPKI validity, visibility, neighbours, abuse e-mail"
    cache_ttl = 6 * HOUR  # routing changes; registration data (RDAP) is cached longer

    async def _call(self, session, call: str, **params) -> dict:
        params["sourceapp"] = SOURCEAPP
        _, payload = await request_json(session, "GET", URL.format(call), params=params)
        return unwrap(call, payload)

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        session, target = ctx.session, ctx.target
        version = ipaddress.ip_address(target).version
        errors: dict[str, str] = {}

        async def attempt(label: str, coro):
            try:
                return await coro
            except ProviderError as exc:
                errors[label] = str(exc)
                return None

        overview_data, abuse_data = await asyncio.gather(
            attempt("prefix-overview", self._call(session, "prefix-overview", resource=target)),
            attempt(
                "abuse-contact-finder",
                self._call(session, "abuse-contact-finder", resource=target),
            ),
        )
        if overview_data is None:
            raise ProviderError(errors["prefix-overview"])
        overview = parse_overview(overview_data)
        result: dict[str, Any] = {"announced": overview["announced"]}

        origins = overview.get("origins", [])
        prefix = overview.get("prefix")
        jobs = {"routing-status": self._call(session, "routing-status", resource=prefix or target)}
        if origins and prefix:
            for origin in origins[:MAX_ORIGINS]:
                asn = origin["asn"]
                jobs[f"rpki-validation AS{asn}"] = self._call(
                    session, "rpki-validation", resource=f"AS{asn}", prefix=prefix
                )
            jobs["asn-neighbours"] = self._call(
                session, "asn-neighbours", resource=f"AS{origins[0]['asn']}"
            )
        answers = dict(
            zip(
                jobs,
                await asyncio.gather(*(attempt(label, job) for label, job in jobs.items())),
                strict=True,
            )
        )

        if origins and prefix:
            first = origins[0]
            network = {"asn": first["asn"], "prefix": prefix}
            if first.get("holder"):
                network["as_name"] = first["holder"]
            if len(origins) > 1:
                network["origin_asns"] = [o["asn"] for o in origins]
            result["network"] = network
            result["origins"] = origins
            result["rpki"] = [
                parse_rpki(o["asn"], answers[f"rpki-validation AS{o['asn']}"])
                for o in origins[:MAX_ORIGINS]
                if answers.get(f"rpki-validation AS{o['asn']}") is not None
            ]
            if answers.get("asn-neighbours") is not None:
                result["neighbours"] = parse_neighbours(answers["asn-neighbours"])
        if answers.get("routing-status") is not None:
            result["routing"] = parse_routing(answers["routing-status"], version)

        if abuse_data is not None:
            contacts = abuse_data.get("abuse_contacts") or []
            result["abuse_contacts"] = list(
                dict.fromkeys(c.strip() for c in contacts if isinstance(c, str) and c.strip())
            )
            rir = clean(abuse_data.get("authoritative_rir"))
            if rir:
                result["authoritative_rir"] = rir.upper()
                if "network" in result:
                    result["network"]["rir"] = rir.upper()
        if errors:
            result["partial_errors"] = errors
        return result
