"""IPinfo Lite: country and ASN, free and unlimited with a token (launched May 2025).

Request: https://api.ipinfo.io/lite/{ip}?token=TOKEN
Fields:  ip, asn ("AS15169"), as_name, as_domain, country_code, country,
         continent_code, continent. ASN fields are absent for unannounced space.
The token travels in the URL, so error messages never include the URL.
"""

from __future__ import annotations

from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import compact, parse_asn

URL = "https://api.ipinfo.io/lite/"


class IpinfoLiteProvider(Provider):
    name = "ipinfo-lite"
    layer = "L2/L3"
    description = "Country + ASN (free token, unlimited)"
    requires_key = "IPINFO_TOKEN"
    cache_ttl = DAY

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        token = ctx.config.key_for(self.requires_key)
        _, data = await request_json(ctx.session, "GET", URL + ctx.target, params={"token": token})
        if not isinstance(data, dict):
            raise ProviderError("IPinfo returned an unexpected response")
        if data.get("bogon"):
            raise ProviderError("IPinfo: bogon (not a public, routed address)")
        asn, _ = parse_asn(data.get("asn"))
        return {
            "location": compact(
                {
                    "continent": data.get("continent"),
                    "continent_code": data.get("continent_code"),
                    "country": data.get("country"),
                    "country_code": data.get("country_code"),
                }
            ),
            "network": compact(
                {"asn": asn, "as_name": data.get("as_name"), "as_domain": data.get("as_domain")}
            ),
            "raw": data,
        }
