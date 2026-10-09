"""ip-api.com (free endpoint): location, ISP, ASN and mobile/proxy/hosting flags.

Facts from https://ip-api.com/docs (checked 2026-10):
  * free single lookups: http://ip-api.com/json/{ip}, 45 requests/minute per IP
  * batch: POST http://ip-api.com/batch with a JSON array of up to 100 IPs,
    15 requests/minute; more than 100 entries gives HTTP 422
  * headers X-Rl (requests left in this window) and X-Ttl (seconds until reset);
    going over gives HTTP 429, and repeatedly doing so bans the IP for an hour
  * the free tier has no HTTPS and is for non-commercial use only
"""

from __future__ import annotations

from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import compact, parse_asn

URL = "http://ip-api.com/json/"
BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
SINGLE_LIMIT = (45, 60.0)
BATCH_LIMIT = (15, 60.0)
FIELDS = (
    "status,message,continent,continentCode,country,countryCode,region,regionName,city,"
    "district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,"
    "hosting,query"
)


def respect_headers(response, limiter) -> None:
    """X-Rl: 0 means the window is used up; wait X-Ttl seconds (+1 for safety)."""
    remaining = response.headers.get("x-rl", "").strip()
    ttl = response.headers.get("x-ttl", "").strip()
    if remaining == "0" and ttl.isdigit():
        limiter.block_for(int(ttl) + 1)


def normalize(data: dict) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProviderError("ip-api returned an unexpected response")
    if data.get("status") != "success":
        raise ProviderError(f"ip-api: {data.get('message') or 'lookup failed'}")
    asn, as_name = parse_asn(data.get("as"))
    return {
        "location": compact(
            {
                "continent": data.get("continent"),
                "continent_code": data.get("continentCode"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "region_code": data.get("region"),
                "city": data.get("city"),
                "district": data.get("district"),
                "postal_code": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "utc_offset_seconds": data.get("offset"),
            }
        ),
        "network": compact(
            {
                "asn": asn,
                "as_name": as_name,
                "as_short_name": data.get("asname"),
                "isp": data.get("isp"),
                "org": data.get("org"),
            }
        ),
        "flags": {
            k: data[k] for k in ("mobile", "proxy", "hosting") if isinstance(data.get(k), bool)
        },
        "reverse_dns": data.get("reverse") or None,
        "currency": data.get("currency") or None,
        "transport": "plain HTTP (the free ip-api endpoint has no HTTPS)",
        "raw": data,
    }


class IpApiProvider(Provider):
    name = "ip-api"
    layer = "L2/L3/L7"
    description = "Location, ISP, ASN, mobile/proxy/hosting flags (free, no key, HTTP only)"
    profiles = ("quick", "standard", "full")
    cache_ttl = DAY
    rate_limit = SINGLE_LIMIT

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        limiter = ctx.session.limiter(self.name, *SINGLE_LIMIT)
        response, data = await request_json(
            ctx.session, "GET", URL + ctx.target, params={"fields": FIELDS}, limiter=limiter
        )
        respect_headers(response, limiter)
        return normalize(data)

    async def prefetch(self, targets: list[str], session) -> None:
        """Fetch up to 100 addresses per request through the batch endpoint."""
        todo = [t for t in targets if session.cache.get(self.name, t) is None]
        if len(todo) < 2:
            return  # a single lookup is just as cheap
        limiter = session.limiter("ip-api-batch", *BATCH_LIMIT)
        for start in range(0, len(todo), BATCH_SIZE):
            chunk = todo[start : start + BATCH_SIZE]
            await limiter.acquire()
            response, data = await request_json(
                session, "POST", BATCH_URL, params={"fields": FIELDS}, json=chunk, limiter=limiter
            )
            respect_headers(response, limiter)
            if not isinstance(data, list) or len(data) != len(chunk):
                raise ProviderError("ip-api batch returned an unexpected response")
            for target, item in zip(chunk, data, strict=True):
                try:
                    session.cache.put(self.name, target, normalize(item), self.cache_ttl)
                except ProviderError as exc:
                    session.cache.put_error(self.name, target, str(exc))


async def public_ip(session) -> str:
    """The caller's own public IP, as seen by ip-api."""
    limiter = session.limiter(IpApiProvider.name, *SINGLE_LIMIT)
    await limiter.acquire()
    response, data = await request_json(
        session, "GET", URL, params={"fields": "status,message,query"}, limiter=limiter
    )
    respect_headers(response, limiter)
    if not isinstance(data, dict) or data.get("status") != "success" or not data.get("query"):
        raise ProviderError(f"ip-api: {(data or {}).get('message') or 'no address returned'}")
    return data["query"]
