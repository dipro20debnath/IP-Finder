"""abuse.ch ThreatFox and URLhaus (free Auth-Key from https://auth.abuse.ch/,
required since 30 June 2025).

ThreatFox  POST https://threatfox-api.abuse.ch/api/v1/  {"query": "search_ioc", "search_term": ip}
           {"query_status": "ok" | "no_result", "data": [{"id", "ioc" ("ip:port"),
            "threat_type", "malware_printable", "confidence_level", "first_seen",
            "last_seen", "tags", "reference"}]}
URLhaus    POST https://urlhaus-api.abuse.ch/v1/host/  form: host=<ip>
           {"query_status": "ok" | "no_results", "urlhaus_reference", "firstseen",
            "url_count", "blacklists", "urls": [{"url", "url_status", "date_added",
            "threat", "tags"}]}
Both send the key in the "Auth-Key" header; an unknown key gives HTTP 403.
Malware URLs are shown "defanged" (hxxp://) so they cannot be clicked by accident.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
KEY = "ABUSECH_AUTH_KEY"


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://", 1).replace("https://", "hxxps://", 1)


def ioc_host(ioc: str) -> str:
    """'1.2.3.4:443' -> '1.2.3.4'; '[2001:db8::1]:443' -> '2001:db8::1'."""
    ioc = ioc.strip()
    if ioc.startswith("[") and "]" in ioc:
        return ioc[1 : ioc.index("]")]
    if ioc.count(":") == 1:
        return ioc.rsplit(":", 1)[0]
    return ioc


def _same_address(ioc: Any, target: str) -> bool:
    if not isinstance(ioc, str):
        return False
    try:
        return ipaddress.ip_address(ioc_host(ioc)) == ipaddress.ip_address(target)
    except ValueError:
        return False


def _status(service: str, payload: Any) -> str:
    if not isinstance(payload, dict):
        raise ProviderError(f"{service} returned an unexpected response")
    return str(payload.get("query_status") or "")


class ThreatFoxProvider(Provider):
    name = "threatfox"
    layer = "L9"
    description = "Malware command-and-control IOCs (abuse.ch ThreatFox)"
    profiles = ("full",)
    requires_key = KEY
    cache_ttl = 6 * HOUR

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        _, payload = await request_json(
            ctx.session,
            "POST",
            THREATFOX_URL,
            json={"query": "search_ioc", "search_term": ctx.target},
            headers={"Auth-Key": ctx.config.key_for(KEY)},
        )
        status = _status("ThreatFox", payload)
        if status == "no_result":
            return {"found": False}
        if status != "ok":
            raise ProviderError(f"ThreatFox: {status or 'unexpected response'}")
        iocs = []
        for entry in payload.get("data") or []:
            if not isinstance(entry, dict) or not _same_address(entry.get("ioc"), ctx.target):
                continue
            item = {
                "ioc": clean(entry.get("ioc")),
                "threat_type": clean(entry.get("threat_type_desc"))
                or clean(entry.get("threat_type")),
                "malware": clean(entry.get("malware_printable")) or clean(entry.get("malware")),
                "confidence": entry.get("confidence_level"),
                "first_seen": clean(entry.get("first_seen")),
                "last_seen": clean(entry.get("last_seen")),
                "tags": [t for t in entry.get("tags") or [] if isinstance(t, str)],
            }
            if entry.get("id") is not None:
                item["link"] = f"https://threatfox.abuse.ch/ioc/{entry['id']}/"
            iocs.append({k: v for k, v in item.items() if v not in (None, [])})
        return {"found": bool(iocs), "iocs": iocs[:10], "total": len(iocs)}


class URLhausProvider(Provider):
    name = "urlhaus"
    layer = "L9"
    description = "Malware download URLs hosted on the address (abuse.ch URLhaus)"
    profiles = ("full",)
    requires_key = KEY
    cache_ttl = 6 * HOUR

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        _, payload = await request_json(
            ctx.session,
            "POST",
            URLHAUS_URL,
            data={"host": ctx.target},
            headers={"Auth-Key": ctx.config.key_for(KEY)},
        )
        status = _status("URLhaus", payload)
        if status == "no_results":
            return {"found": False}
        if status == "invalid_host":
            return {"found": False, "note": "URLhaus does not accept this address form"}
        if status != "ok":
            raise ProviderError(f"URLhaus: {status or 'unexpected response'}")
        urls = []
        for entry in payload.get("urls") or []:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                item = {
                    "url": defang(entry["url"]),
                    "status": clean(entry.get("url_status")),
                    "added": clean(entry.get("date_added")),
                    "threat": clean(entry.get("threat")),
                    "tags": [t for t in entry.get("tags") or [] if isinstance(t, str)],
                }
                urls.append({k: v for k, v in item.items() if v not in (None, [])})
        count = payload.get("url_count")
        result = {
            "found": True,
            "url_count": int(count) if str(count).isdigit() else len(urls),
            "online": sum(1 for u in urls if u.get("status") == "online"),
            "first_seen": clean(payload.get("firstseen")),
            "urls": urls[:5],
            "link": clean(payload.get("urlhaus_reference")),
        }
        blacklists = payload.get("blacklists")
        if isinstance(blacklists, dict):
            result["blacklists"] = {k: v for k, v in blacklists.items() if isinstance(v, str)}
        return {k: v for k, v in result.items() if v is not None}
