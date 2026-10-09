"""Combine what the providers found into a short summary.

Phase 2 shows every source side by side and only flags disagreements; the
weighted consensus and confidence score arrive in Phase 6.
"""

from __future__ import annotations

from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - Python < 3.9 is not supported anyway
    ZoneInfo = None

# MaxMind gives an accuracy radius, so it is preferred for the map pin.
LOCATION_PRIORITY = ("maxmind", "ip-api", "ipinfo-lite")
ASN_PRIORITY = ("team-cymru", "maxmind", "ipinfo-lite", "ip-api")


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

    return summary
