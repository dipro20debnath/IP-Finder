"""Speed-of-light check (ADVANCED_PLAN.md 5.6).

Light in optical fibre covers about 200 km per millisecond (2/3 of its speed in
vacuum). A round trip of R ms therefore puts the address at most R / 2 * 200 km
away from you. Routes are longer than straight lines and routers add delay, so
this is a hard upper bound, never an estimate: if the claimed location is
farther away than that, the geolocation is wrong, or the address is anycast and
answered from a nearer site.
"""

from __future__ import annotations

from ipfinder.analysis.geo import haversine_km

FIBRE_KM_PER_MS = 200.0


def rtt_check(rtt: dict | None, consensus: dict | None) -> dict | None:
    """None when there is no measurement; otherwise the bound and the verdict."""
    if not rtt or rtt.get("min_rtt_ms") is None:
        return None
    rtt_ms = rtt["min_rtt_ms"]
    max_km = round(rtt_ms / 2 * FIBRE_KM_PER_MS, 1)
    result: dict = {"rtt_ms": rtt_ms, "max_distance_km": max_km}
    vantage = rtt.get("vantage") or {}
    if "latitude" not in vantage:
        result["checked"] = False
        result["reason"] = vantage.get("error") or "your own location is unknown"
        return result
    if not consensus or "latitude" not in consensus:
        result["checked"] = False
        result["reason"] = "no source gave coordinates for the address"
        return result
    distance = haversine_km(
        vantage["latitude"], vantage["longitude"], consensus["latitude"], consensus["longitude"]
    )
    slack = vantage.get("uncertainty_km", 0) + (consensus.get("uncertainty_km") or 0)
    result.update(
        checked=True,
        distance_km=round(distance, 1),
        slack_km=round(slack, 1),
        plausible=distance <= max_km + slack,
    )
    return result
