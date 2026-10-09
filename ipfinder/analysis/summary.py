"""Combine what the providers found into a short summary.

Every source is shown side by side and only disagreements are flagged; the
weighted consensus and confidence score arrive in Phase 6.
"""

from __future__ import annotations

from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - Python < 3.9 is not supported anyway
    ZoneInfo = None

# Operator-published locations come first (the network's own geofeed, Apple's
# Private Relay list); they have no coordinates, so the map pin comes from MaxMind
# (which gives an accuracy radius) or the next source.
LOCATION_PRIORITY = ("geofeed", "private-relay", "maxmind", "ip-api", "ipinfo-lite")
# BGP-derived sources first: they see the live routing table.
ASN_PRIORITY = ("team-cymru", "ripestat", "maxmind", "ipinfo-lite", "ip-api")


def _ok_data(results: dict, name: str) -> dict:
    result = results.get(name)
    return result.data if result is not None and result.ok else {}


def _local_time(tz_name: str, now: datetime) -> dict | None:
    if ZoneInfo is None:
        return None
    try:
        local = now.astimezone(ZoneInfo(tz_name))
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        return None
    offset = local.utcoffset()
    minutes = int(offset.total_seconds() // 60) if offset is not None else 0
    sign = "+" if minutes >= 0 else "-"
    return {
        "timezone": tz_name,
        "time": local.strftime("%Y-%m-%d %H:%M"),
        "utc_offset": f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}",
    }


def build_summary(results: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    summary: dict = {}

    countries = {}
    for name in LOCATION_PRIORITY:
        code = (_ok_data(results, name).get("location") or {}).get("country_code")
        if code:
            countries[name] = code.upper()
    if countries:
        summary["country_by_source"] = countries
        summary["countries_agree"] = len(set(countries.values())) == 1

    for name in LOCATION_PRIORITY:
        location = _ok_data(results, name).get("location") or {}
        lat, lon = location.get("latitude"), location.get("longitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            summary["map_source"] = name
            summary["coordinates"] = {"latitude": lat, "longitude": lon}
            if location.get("accuracy_radius_km") is not None:
                summary["coordinates"]["accuracy_radius_km"] = location["accuracy_radius_km"]
            summary["map_links"] = {
                "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=11/{lat}/{lon}",
                "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
            }
            break

    for name in LOCATION_PRIORITY:
        tz_name = (_ok_data(results, name).get("location") or {}).get("timezone")
        if tz_name:
            local = _local_time(tz_name, now)
            if local:
                summary["local_time"] = local
                break

    asns = {}
    for name in ASN_PRIORITY:
        asn = (_ok_data(results, name).get("network") or {}).get("asn")
        if isinstance(asn, int):
            asns[name] = asn
    if asns:
        summary["asn_by_source"] = asns
        summary["asns_agree"] = len(set(asns.values())) == 1

    abuse: dict[str, list[str]] = {}
    for contact in _ok_data(results, "rdap").get("abuse_contacts") or []:
        for email in contact.get("emails") or []:
            abuse.setdefault(email.lower(), []).append("rdap")
    for email in _ok_data(results, "ripestat").get("abuse_contacts") or []:
        abuse.setdefault(email.lower(), []).append("ripestat")
    if abuse:
        summary["abuse_contacts"] = [
            {"email": email, "sources": list(dict.fromkeys(sources))}
            for email, sources in abuse.items()
        ]

    ripestat = _ok_data(results, "ripestat")
    if ripestat:
        summary["announced"] = ripestat.get("announced")
        if ripestat.get("rpki"):
            summary["rpki"] = [
                {"origin": r["origin"], "status": r["status"]} for r in ripestat["rpki"]
            ]

    anonymity = _anonymity(results)
    if anonymity:
        summary["anonymity"] = anonymity
    return summary


def _anonymity(results: dict) -> dict:
    """Plain facts from the L7 sources; the combined verdict comes in Phase 6."""
    out: dict = {}
    tor = _ok_data(results, "tor")
    if tor:
        out["tor_exit"] = tor.get("is_exit")
    relay = _ok_data(results, "private-relay")
    if relay:
        out["icloud_private_relay"] = relay.get("is_relay")
    cloud = _ok_data(results, "cloud-ranges")
    if cloud:
        out["cloud_or_cdn"] = list(dict.fromkeys(m["provider"] for m in cloud.get("matches", [])))
    vpn = _ok_data(results, "vpn-lists")
    if vpn:
        out["listed_vpn_network"] = vpn.get("vpn", {}).get("listed")
        out["listed_datacenter_network"] = vpn.get("datacenter", {}).get("listed")
    flags = _ok_data(results, "ip-api").get("flags") or {}
    for key in ("proxy", "hosting", "mobile"):
        if key in flags:
            out[f"ip_api_{key}"] = flags[key]
    return out
