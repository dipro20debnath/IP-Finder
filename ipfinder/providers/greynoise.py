"""GreyNoise Community API: is the address mass-scanning the internet ("noise"),
or a known benign business service such as a public DNS resolver ("RIOT")?

  GET https://api.greynoise.io/v3/community/<ip>    optional header  key: <API key>
  {"ip", "noise", "riot", "classification": "benign|malicious|unknown", "name",
   "link", "last_seen", "message"}
  404 = never observed by GreyNoise. IPv4 only (GreyNoise's own SDK rejects IPv6).
Without a key a few lookups a day are allowed; a free account gives 50 a week.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.core.http import decode_json, send
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

URL = "https://api.greynoise.io/v3/community/{}"


class GreyNoiseProvider(Provider):
    name = "greynoise"
    layer = "L9"
    description = "Internet scanner or known benign service? (GreyNoise Community)"
    profiles = ("full",)
    optional_key = "GREYNOISE_API_KEY"
    cache_ttl = DAY  # the free quota is small

    def skip_reason(self, ctx: LookupContext) -> str | None:
        reason = super().skip_reason(ctx)
        if reason is None and ipaddress.ip_address(ctx.target).version == 6:
            return "GreyNoise covers IPv4 only"
        return reason

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        key = ctx.config.key_for(self.optional_key)
        response = await send(
            ctx.session,
            "GET",
            URL.format(ctx.target),
            headers={"key": key} if key else None,
            ok_statuses=(200, 404),
        )
        try:
            data = decode_json(response)
        except ProviderError:
            if response.status_code == 404:
                data = {}
            else:
                raise
        if not isinstance(data, dict):
            raise ProviderError("GreyNoise returned an unexpected response")
        result = {
            "observed": response.status_code == 200,
            "noise": bool(data.get("noise")),
            "riot": bool(data.get("riot")),
            "classification": clean(data.get("classification")),
            "name": clean(data.get("name")),
            "last_seen": clean(data.get("last_seen")),
            "link": clean(data.get("link")) or f"https://viz.greynoise.io/ip/{ctx.target}",
            "message": clean(data.get("message")),
        }
        return {k: v for k, v in result.items() if v is not None}
