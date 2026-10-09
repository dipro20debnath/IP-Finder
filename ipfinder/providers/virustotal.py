"""VirusTotal: what ~90 security vendors' engines last said about the address.

  GET https://www.virustotal.com/api/v3/ip_addresses/<ip>    header  x-apikey: <key>
  {"data": {"attributes": {"last_analysis_stats": {"malicious", "suspicious",
   "harmless", "undetected", "timeout"}, "last_analysis_results": {engine: {"category",
   "result"}}, "reputation", "total_votes": {"harmless", "malicious"},
   "last_analysis_date", "tags", "as_owner", "network"}}}
Public API: 4 requests a minute and 500 a day, non-commercial use only. One or two
engines flagging an address is common noise; look at which engines and why.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ipfinder.core.http import decode_json, send
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def parse_ip_object(data: Any) -> dict[str, Any]:
    attrs = ((data or {}).get("data") or {}).get("attributes") if isinstance(data, dict) else None
    if not isinstance(attrs, dict):
        raise ProviderError("VirusTotal returned an unexpected response")
    stats = attrs.get("last_analysis_stats") or {}
    counts = {k: stats.get(k, 0) for k in STAT_KEYS if isinstance(stats.get(k, 0), int)}
    flagged = []
    for engine, verdict in (attrs.get("last_analysis_results") or {}).items():
        if isinstance(verdict, dict) and verdict.get("category") in ("malicious", "suspicious"):
            flagged.append(
                {
                    "engine": engine,
                    "category": verdict["category"],
                    "result": clean(verdict.get("result")),
                }
            )
    flagged.sort(key=lambda f: (f["category"] != "malicious", f["engine"].lower()))
    analysed = attrs.get("last_analysis_date")
    votes = attrs.get("total_votes") or {}
    result = {
        "stats": counts,
        "engines": sum(counts.values()),
        "flagged": flagged[:10],
        "reputation": attrs.get("reputation"),
        "votes": {k: votes[k] for k in ("harmless", "malicious") if isinstance(votes.get(k), int)},
        "tags": [t for t in attrs.get("tags") or [] if isinstance(t, str)],
        "as_owner": clean(attrs.get("as_owner")),
        "last_analysis": (
            datetime.fromtimestamp(analysed, timezone.utc).strftime("%Y-%m-%d")
            if isinstance(analysed, (int, float))
            else None
        ),
    }
    return {k: v for k, v in result.items() if v is not None}


class VirusTotalProvider(Provider):
    name = "virustotal"
    layer = "L9"
    description = "Security vendors' verdicts on the address (VirusTotal)"
    profiles = ("full",)
    requires_key = "VIRUSTOTAL_API_KEY"
    cache_ttl = DAY  # 500 lookups a day on the public API
    rate_limit = (4, 60.0)  # public API: 4 requests a minute

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        response = await send(
            ctx.session,
            "GET",
            URL.format(ctx.target),
            headers={"x-apikey": ctx.config.key_for(self.requires_key)},
            limiter=ctx.session.limiter(self.name, *self.rate_limit),
            ok_statuses=(200, 404),
        )
        if response.status_code == 404:
            return {"found": False, "note": "VirusTotal has no record of this address"}
        result = parse_ip_object(decode_json(response))
        result["found"] = True
        result["link"] = f"https://www.virustotal.com/gui/ip-address/{ctx.target}"
        return result
