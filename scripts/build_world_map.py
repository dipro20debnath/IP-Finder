"""Build ipfinder/output/assets/world-110m.json from Natural Earth GeoJSON
(public domain): country outlines with names only, and populated places.

    python scripts/build_world_map.py ne_110m_admin_0_countries.geojson \\
        ne_110m_populated_places_simple.geojson ipfinder/output/assets/world-110m.json 2

The source files are in github.com/nvkelso/natural-earth-vector (geojson/).
The last argument is how many decimals to keep (2 = about 1 km).
"""

from __future__ import annotations

import json
import sys

SOURCE = (
    "Natural Earth 1:110m admin 0 countries and populated places (public domain), "
    "naturalearthdata.com"
)


def _round(coords, digits: int):
    if isinstance(coords[0], (int, float)):
        return [round(coords[0], digits), round(coords[1], digits)]
    return [_round(c, digits) for c in coords]


def _dedupe(ring: list) -> list:
    out = []
    for point in ring:
        if not out or out[-1] != point:
            out.append(point)
    return out


def _geometry(geom: dict, digits: int) -> dict:
    coords = _round(geom["coordinates"], digits)
    if geom["type"] == "Polygon":
        coords = [_dedupe(ring) for ring in coords]
    elif geom["type"] == "MultiPolygon":
        coords = [[_dedupe(ring) for ring in poly] for poly in coords]
    return {"type": geom["type"], "coordinates": coords}


def build(countries_path: str, places_path: str, digits: int) -> dict:
    with open(countries_path, encoding="utf-8") as handle:
        countries = json.load(handle)
    with open(places_path, encoding="utf-8") as handle:
        places = json.load(handle)
    features = [
        {
            "type": "Feature",
            "properties": {"n": f["properties"].get("NAME") or f["properties"].get("ADMIN")},
            "geometry": _geometry(f["geometry"], digits),
        }
        for f in countries["features"]
    ]
    cities = sorted(
        [
            p["properties"]["name"],
            round(p["geometry"]["coordinates"][1], digits),
            round(p["geometry"]["coordinates"][0], digits),
        ]
        for p in places["features"]
    )
    return {
        "countries": {"type": "FeatureCollection", "features": features},
        "cities": cities,
        "source": SOURCE,
    }


def main(argv: list[str]) -> int:
    countries_path, places_path, out, digits = argv[0], argv[1], argv[2], int(argv[3])
    data = build(countries_path, places_path, digits)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(data, handle, separators=(",", ":"), ensure_ascii=False)
    print(f"{out}: {len(data['countries']['features'])} countries, {len(data['cities'])} places")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
