"""Shodan InternetDB: open ports, software (CPE), possible CVEs and tags seen by
Shodan's internet-wide scans. Free, no key, non-commercial use only.

  GET https://internetdb.shodan.io/{ip}
  {"ip", "ports": [..], "hostnames": [..], "cpes": [..], "tags": [..], "vulns": [..]}
  404 = Shodan has no data for the address.
Facts from Shodan's documentation: the database is updated weekly; "vulns" mixes
verified and unverified vulnerabilities (inferred from software versions); bursts
of up to 10,000 requests per second are allowed. This is a passive lookup: no
packet is sent to the address itself.
"""

from __future__ import annotations

from typing import Any

from ipfinder.core.http import decode_json, send
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError

URL = "https://internetdb.shodan.io/{}"

# Services that are frequently attacked when reachable from the whole internet.
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MS SQL",
    2375: "Docker API (no TLS)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def _strings(values) -> list[str]:
    return [v.strip() for v in values or [] if isinstance(v, str) and v.strip()]


class InternetDBProvider(Provider):
    name = "internetdb"
    layer = "L8"
    description = "Open ports, software and possible CVEs from Shodan scans (no key)"
    cache_ttl = DAY  # the database itself changes weekly

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        response = await send(ctx.session, "GET", URL.format(ctx.target), ok_statuses=(200, 404))
        if response.status_code == 404:
            return {"found": False, "note": "Shodan has no scan data for this address"}
        data = decode_json(response)
        if not isinstance(data, dict):
            raise ProviderError("InternetDB returned an unexpected response")
        ports = sorted({p for p in data.get("ports") or [] if isinstance(p, int)})
        return {
            "found": True,
            "ports": ports,
            # a list, not a dict: JSON (and so the cache) would turn int keys into strings
            "risky_ports": [
                {"port": p, "service": RISKY_PORTS[p]} for p in ports if p in RISKY_PORTS
            ],
            "hostnames": _strings(data.get("hostnames")),
            "cpes": _strings(data.get("cpes")),
            "tags": _strings(data.get("tags")),
            "vulns": sorted(_strings(data.get("vulns"))),
            "raw": data,
        }
