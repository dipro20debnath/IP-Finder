"""AlienVault OTX (LevelBlue Open Threat Exchange): community threat "pulses" that
mention the address.

  GET https://otx.alienvault.com/api/v1/indicators/IPv4/<ip>/general   (IPv6/ for IPv6)
  header  X-OTX-API-KEY: <key>
  {"pulse_info": {"count", "pulses": [{"name", "created", "modified", "tags",
   "malware_families": [{"display_name"}], "adversary"}]}, "reputation",
   "validation": [{"source", "message"}]}
Pulses are written by OTX users; "validation" lists allow-lists (for example a
well-known DNS resolver) that make a pulse less meaningful.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

URL = "https://otx.alienvault.com/api/v1/indicators/{}/{}/general"


def parse_general(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("pulse_info"), dict):
        raise ProviderError("OTX returned an unexpected response")
    info = data["pulse_info"]
    pulses = []
    for pulse in info.get("pulses") or []:
        if not isinstance(pulse, dict):
            continue
        families = [
            clean(f.get("display_name"))
            for f in pulse.get("malware_families") or []
            if isinstance(f, dict) and clean(f.get("display_name"))
        ]
        entry = {
            "name": clean(pulse.get("name")),
            "created": clean(pulse.get("created")),
            "modified": clean(pulse.get("modified")),
            "tags": [t for t in pulse.get("tags") or [] if isinstance(t, str)][:6],
            "malware_families": families[:5],
            "adversary": clean(pulse.get("adversary")),
        }
        pulses.append({k: v for k, v in entry.items() if v not in (None, [])})
    pulses.sort(key=lambda p: p.get("modified") or "", reverse=True)
    validation = [
        clean(v.get("message")) or clean(v.get("name"))
        for v in data.get("validation") or []
        if isinstance(v, dict) and (clean(v.get("message")) or clean(v.get("name")))
    ]
    count = info.get("count")
    return {
        "pulse_count": count if isinstance(count, int) else len(pulses),
        "pulses": pulses[:5],
        "validation": validation,
        "reputation": data.get("reputation"),
    }


class OTXProvider(Provider):
    name = "otx"
    layer = "L9"
    description = "Threat pulses mentioning the address (AlienVault OTX)"
    profiles = ("full",)
    requires_key = "OTX_API_KEY"
    cache_ttl = 6 * HOUR

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        kind = "IPv4" if ipaddress.ip_address(ctx.target).version == 4 else "IPv6"
        _, data = await request_json(
            ctx.session,
            "GET",
            URL.format(kind, ctx.target),
            headers={"X-OTX-API-KEY": ctx.config.key_for(self.requires_key)},
        )
        result = parse_general(data)
        result["link"] = f"https://otx.alienvault.com/indicator/ip/{ctx.target}"
        return result
