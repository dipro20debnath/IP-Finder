"""Location consensus: one answer from several geolocation sources, and how far
apart they are.

* Country: weighted vote. Locations the network operator publishes itself (its
  geofeed, Apple's Private Relay list) count 3, databases count 1; a tie goes to
  the source listed first in SOURCES.
* City: the city most sources name inside the winning country; ties go the same way.
* Point: the median of the sources' coordinates.
* Uncertainty: the largest distance between any two sources, or MaxMind's own
  accuracy radius if that is larger (a single database can be far off too).
"""

from __future__ import annotations

from itertools import combinations
from math import asin, cos, radians, sin, sqrt
from statistics import median

EARTH_RADIUS_KM = 6371.0

# (provider, weight), in tie-break order
SOURCES = (
    ("geofeed", 3),
    ("private-relay", 3),
    ("maxmind", 1),
    ("ip-api", 1),
    ("ipinfo-lite", 1),
)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance on a spherical Earth (error well under 1%)."""
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_KM * asin(min(1.0, sqrt(a)))


def _locations(results: dict) -> list[tuple[str, int, dict]]:
    out = []
    for name, weight in SOURCES:
        result = results.get(name)
        if result is not None and result.ok:
            location = (result.data or {}).get("location") or {}
            if location:
                out.append((name, weight, location))
    return out


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def location_consensus(results: dict) -> dict | None:
    """None when no source gave a location."""
    locations = _locations(results)
    if not locations:
        return None

    votes: dict[str, list[str]] = {}
    weights: dict[str, int] = {}
    for name, weight, loc in locations:
        code = (loc.get("country_code") or "").upper()
        if code:
            votes.setdefault(code, []).append(name)
            weights[code] = weights.get(code, 0) + weight
    country = None
    if votes:
        order = {code: i for i, code in enumerate(votes)}  # first source wins a tie
        country = max(votes, key=lambda code: (weights[code], -order[code]))

    cities: dict[str, list[str]] = {}
    shown: dict[str, str] = {}
    for name, _, loc in locations:
        city = loc.get("city")
        same_country = not country or (loc.get("country_code") or "").upper() in ("", country)
        if city and same_country:
            key = city.casefold()
            cities.setdefault(key, []).append(name)
            shown.setdefault(key, city)
    city = None
    if cities:
        order = {key: i for i, key in enumerate(cities)}
        city = shown[max(cities, key=lambda key: (len(cities[key]), -order[key]))]

    points = [
        (name, loc["latitude"], loc["longitude"])
        for name, _, loc in locations
        if _number(loc.get("latitude")) and _number(loc.get("longitude"))
    ]
    result: dict = {
        "country_code": country,
        "country_votes": votes,
        "countries_agree": len(votes) <= 1,
        "city": city,
        "city_sources": cities.get(city.casefold(), []) if city else [],
        "coordinate_sources": [p[0] for p in points],
    }
    if points:
        result["latitude"] = round(median(p[1] for p in points), 4)
        result["longitude"] = round(median(p[2] for p in points), 4)
        spread = max(
            (haversine_km(a[1], a[2], b[1], b[2]) for a, b in combinations(points, 2)),
            default=0.0,
        )
        result["spread_km"] = round(spread, 1)
        radius = next(
            (
                loc.get("accuracy_radius_km")
                for name, _, loc in locations
                if name == "maxmind" and _number(loc.get("accuracy_radius_km"))
            ),
            None,
        )
        if radius is not None:
            result["maxmind_radius_km"] = radius
        result["uncertainty_km"] = round(max(spread, radius or 0), 1)
    return result
