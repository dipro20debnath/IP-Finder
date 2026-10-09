"""RDAP (RFC 9082 / 9083), the JSON successor of WHOIS: who the address block is
registered to, the registered range, dates and the abuse contact.

Which server to ask comes from IANA's bootstrap files (RFC 9224):
  https://data.iana.org/rdap/ipv4.json  (and ipv6.json)
  {"services": [[["8.0.0.0/8", ...], ["https://rdap.arin.net/registry/", ...]], ...]}
If they cannot be fetched, https://rdap.org/ip/{ip} redirects to the right RIR.
Request: GET {server}ip/8.8.8.8 with "Accept: application/rdap+json"; 404 = no record.

Rate limits: LACNIC documents 10 queries/minute (and 1,000/hour) per client; the
other RIRs publish no number, so IP Finder stays at a polite 30/minute per server.

A geofeed URL (RFC 9632) is read from a link with rel "geo" or type
"application/geofeed+csv" (draft-ietf-regext-rdap-geofeed) or from a remark
"Geofeed https://...".
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from ipfinder.core.http import decode_json, request_json, send
from ipfinder.providers.base import DAY, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean, compact

BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv{}.json"
FALLBACK_SERVER = "https://rdap.org/"
HEADERS = {"Accept": "application/rdap+json"}

RIR_BY_HOST = {
    "rdap.arin.net": "ARIN",
    "rdap.db.ripe.net": "RIPE NCC",
    "rdap.apnic.net": "APNIC",
    "rdap.lacnic.net": "LACNIC",
    "rdap.afrinic.net": "AFRINIC",
}
RIR_BY_PORT43 = {
    "whois.arin.net": "ARIN",
    "whois.ripe.net": "RIPE NCC",
    "whois.apnic.net": "APNIC",
    "whois.lacnic.net": "LACNIC",
    "whois.afrinic.net": "AFRINIC",
}
HOST_LIMITS = {"rdap.lacnic.net": (10, 60.0)}
DEFAULT_LIMIT = (30, 60.0)

_GEOFEED_REMARK = re.compile(r"\bgeofeed:?\s+(https://\S+)", re.IGNORECASE)
_MAX_DEPTH = 6  # entities nest (network -> org -> abuse role); stop runaway nesting


def parse_bootstrap(data: Any) -> list[tuple[Any, str]]:
    """IANA bootstrap -> [(network, server base URL)], preferring HTTPS URLs."""
    entries = []
    services = data.get("services") if isinstance(data, dict) else None
    for service in services or []:
        if not (isinstance(service, list) and len(service) >= 2):
            continue
        prefixes, urls = service[0], service[1]
        urls = [
            u for u in urls or [] if isinstance(u, str) and u.startswith(("https://", "http://"))
        ]
        if not urls:
            continue
        base = next((u for u in urls if u.startswith("https://")), urls[0])
        base = base if base.endswith("/") else base + "/"
        for prefix in prefixes or []:
            try:
                entries.append((ipaddress.ip_network(prefix, strict=False), base))
            except (TypeError, ValueError):
                continue
    return entries


def find_server(entries: list[tuple[Any, str]], target: str) -> str | None:
    """Server for the longest bootstrap prefix that contains ``target``."""
    ip = ipaddress.ip_address(target)
    best = None
    for network, base in entries:
        if network.version == ip.version and ip in network:
            if best is None or network.prefixlen > best[0].prefixlen:
                best = (network, base)
    return best[1] if best else None


def _walk(entities, depth: int = 0):
    for entity in entities if isinstance(entities, list) else []:
        if isinstance(entity, dict):
            yield entity
            if depth < _MAX_DEPTH:
                yield from _walk(entity.get("entities"), depth + 1)


def parse_vcard(entity: dict) -> dict[str, Any]:
    """The few jCard (RFC 7095) properties IP Finder uses: fn, kind, email, tel."""
    out: dict[str, Any] = {"emails": [], "phones": []}
    card = entity.get("vcardArray")
    props = card[1] if isinstance(card, list) and len(card) == 2 else None
    for prop in props if isinstance(props, list) else []:
        if not (isinstance(prop, list) and len(prop) >= 4 and isinstance(prop[3], str)):
            continue
        name, value = str(prop[0]).lower(), clean(prop[3])
        if not value:
            continue
        if name == "fn":
            out["name"] = value
        elif name == "kind":
            out["kind"] = value
        elif name == "email" and value not in out["emails"]:
            out["emails"].append(value)
        elif name == "tel":
            phone = value.removeprefix("tel:")
            if phone not in out["phones"]:
                out["phones"].append(phone)
    return out


def _roles(entity: dict) -> list[str]:
    roles = entity.get("roles")
    return [str(r).lower() for r in roles] if isinstance(roles, list) else []


def registrant(entities) -> dict[str, Any] | None:
    for entity in _walk(entities):
        if "registrant" in _roles(entity):
            card = parse_vcard(entity)
            return compact(
                {"name": card.get("name"), "handle": entity.get("handle"), "kind": card.get("kind")}
            )
    return None


def abuse_contacts(entities) -> list[dict[str, Any]]:
    contacts, seen = [], set()
    for entity in _walk(entities):
        if "abuse" not in _roles(entity):
            continue
        card = parse_vcard(entity)
        key = entity.get("handle") or tuple(card["emails"])
        if key in seen:
            continue
        seen.add(key)
        contact = compact({"handle": entity.get("handle"), "name": card.get("name")})
        contact["emails"] = card["emails"]
        if card["phones"]:
            contact["phones"] = card["phones"]
        contacts.append(contact)
    return contacts


def geofeed_urls(obj: dict) -> list[str]:
    urls = []
    for link in obj.get("links") or []:
        if not isinstance(link, dict) or not isinstance(link.get("href"), str):
            continue
        rel = str(link.get("rel", "")).lower()
        kind = str(link.get("type", "")).lower()
        if rel == "geo" or kind == "application/geofeed+csv":
            urls.append(link["href"].strip())
    for remark in obj.get("remarks") or []:
        lines = remark.get("description") if isinstance(remark, dict) else None
        for line in lines if isinstance(lines, list) else []:
            if isinstance(line, str):
                urls += [m.rstrip(".,;)>\"'") for m in _GEOFEED_REMARK.findall(line)]
    # RFC 9632 section 3: geofeed files must be fetched over HTTPS.
    return list(dict.fromkeys(u for u in urls if u.lower().startswith("https://")))


def _description(obj: dict) -> list[str]:
    """Free-text description lines (RIPE/APNIC "descr"), from untitled or
    "description" remarks."""
    for remark in obj.get("remarks") or []:
        if not isinstance(remark, dict):
            continue
        title = str(remark.get("title") or "description").lower()
        lines = remark.get("description")
        if title == "description" and isinstance(lines, list):
            text = [clean(line) for line in lines if isinstance(line, str) and clean(line)]
            if text:
                return text[:5]
    return []


def _cidrs(obj: dict, start, end) -> list[str]:
    cidrs = []
    for entry in obj.get("cidr0_cidrs") or []:
        if not isinstance(entry, dict):
            continue
        prefix = entry.get("v4prefix") or entry.get("v6prefix")
        try:
            cidrs.append(str(ipaddress.ip_network(f"{prefix}/{entry.get('length')}", strict=False)))
        except (TypeError, ValueError):
            continue
    if not cidrs and start is not None and end is not None and start.version == end.version:
        try:
            cidrs = [str(n) for n in ipaddress.summarize_address_range(start, end)]
        except (TypeError, ValueError):
            cidrs = []
    return cidrs


def _address(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def parse_network(obj: dict, server_host: str | None) -> dict[str, Any]:
    if not isinstance(obj, dict) or obj.get("objectClassName", "ip network") != "ip network":
        raise ProviderError("RDAP server returned something other than an IP network")
    start, end = _address(obj.get("startAddress")), _address(obj.get("endAddress"))
    events = {}
    for event in obj.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            events.setdefault(str(event["eventAction"]).lower(), str(event["eventDate"]))
    origin = obj.get("arin_originas0_originautnums")
    registration = compact(
        {
            "handle": obj.get("handle"),
            "name": obj.get("name"),
            "type": obj.get("type"),
            "range": f"{start} - {end}" if start and end else None,
            "country_code": obj.get("country"),
            "parent_handle": obj.get("parentHandle"),
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
            "port43": obj.get("port43"),
        }
    )
    registration["cidrs"] = _cidrs(obj, start, end)
    registration["status"] = [s for s in obj.get("status") or [] if isinstance(s, str)]
    if isinstance(origin, list) and all(isinstance(a, int) for a in origin) and origin:
        registration["origin_asns"] = origin
    holder = registrant(obj.get("entities"))
    if holder:
        registration["registrant"] = holder
    description = _description(obj)
    if description:
        registration["description"] = description
    rir = RIR_BY_HOST.get(server_host or "")
    if rir is None and isinstance(obj.get("port43"), str):
        rir = RIR_BY_PORT43.get(obj["port43"].strip().lower())
    return {
        "registration": registration,
        "abuse_contacts": abuse_contacts(obj.get("entities")),
        "geofeed_urls": geofeed_urls(obj),
        "rir": rir,
        "server": server_host,
    }


class RDAPProvider(Provider):
    name = "rdap"
    layer = "L4"
    description = "Registered owner, net range, dates and abuse contact (RDAP, no key)"
    cache_ttl = 7 * DAY

    async def _bootstrap(self, session, version: int) -> list | None:
        """IANA bootstrap entries (cached 7 days), or None if they cannot be fetched."""
        key = f"rdap-bootstrap-v{version}"
        if key not in session.resources:
            data = session.cache.get("rdap-bootstrap", f"ipv{version}")
            if data is None:
                try:
                    _, data = await request_json(session, "GET", BOOTSTRAP_URL.format(version))
                except ProviderError:
                    data = None
                if isinstance(data, dict) and parse_bootstrap(data):
                    session.cache.put("rdap-bootstrap", f"ipv{version}", data, 7 * DAY)
            session.resources[key] = parse_bootstrap(data) or None
        return session.resources[key]

    async def server_for(self, ctx: LookupContext) -> str:
        version = ipaddress.ip_address(ctx.target).version
        entries = await self._bootstrap(ctx.session, version)
        if entries is None:
            return FALLBACK_SERVER
        server = find_server(entries, ctx.target)
        if server is None:
            raise ProviderError("IANA has not delegated this range to any RIR (RDAP bootstrap)")
        return server

    def _limiter(self, session, server: str):
        host = urlsplit(server).hostname or server
        return session.limiter(f"rdap:{host}", *HOST_LIMITS.get(host, DEFAULT_LIMIT))

    async def wait_turn(self, ctx: LookupContext) -> None:
        try:
            server = await self.server_for(ctx)
        except ProviderError:
            return  # lookup() reports it
        await self._limiter(ctx.session, server).acquire()

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        server = await self.server_for(ctx)
        response = await send(
            ctx.session,
            "GET",
            f"{server}ip/{ctx.target}",
            headers=HEADERS,
            limiter=self._limiter(ctx.session, server),
            ok_statuses=(200, 404),
        )
        if response.status_code == 404:
            raise ProviderError(f"{response.url.host} has no RDAP record for this address")
        data = decode_json(response)
        result = parse_network(data, response.url.host)
        result["url"] = str(response.url)
        result["raw"] = data
        return result
