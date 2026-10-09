"""MaxMind GeoLite2 City and ASN databases, read offline from .mmdb files.

Download them (free MaxMind account) from the MaxMind website or with MaxMind's
``geoipupdate`` tool, and place them at data/GeoLite2-City.mmdb and
data/GeoLite2-ASN.mmdb (or set IPFINDER_MAXMIND_CITY_DB / IPFINDER_MAXMIND_ASN_DB).
MaxMind's accuracy_radius (km) says how far off the coordinates may be.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import maxminddb

from ipfinder.providers.base import LookupContext, Provider, ProviderError
from ipfinder.providers.common import compact


def _en(node: dict | None) -> str | None:
    return ((node or {}).get("names") or {}).get("en")


def _open(session, key: str, path: Path):
    """Open a database once per run and keep it in the session."""
    if key not in session.resources:
        if not path.is_file():
            session.resources[key] = None
        else:
            try:
                session.resources[key] = maxminddb.open_database(str(path))
            except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
                raise ProviderError(f"cannot read {path}: {type(exc).__name__}") from None
    return session.resources[key]


def _build_date(reader) -> str:
    epoch = reader.metadata().build_epoch
    return datetime.fromtimestamp(epoch, tz=timezone.utc).date().isoformat()


def _prefix(target: str, prefix_len: int) -> str:
    return str(ipaddress.ip_network(f"{target}/{prefix_len}", strict=False))


class MaxMindProvider(Provider):
    name = "maxmind"
    layer = "L2/L3"
    description = "GeoLite2 City + ASN databases (offline; free MaxMind account)"
    cache_ttl = 0  # local file: no need to cache

    def required_files(self, config) -> list[Path]:
        return [config.maxmind_city_db, config.maxmind_asn_db]

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        city_db = _open(ctx.session, "maxmind-city", ctx.config.maxmind_city_db)
        asn_db = _open(ctx.session, "maxmind-asn", ctx.config.maxmind_asn_db)
        result: dict[str, Any] = {"databases": {}, "raw": {}}

        if city_db is not None:
            record, prefix_len = city_db.get_with_prefix_len(ctx.target)
            result["databases"]["city"] = {
                "type": city_db.metadata().database_type,
                "build_date": _build_date(city_db),
            }
            if record:
                location = record.get("location") or {}
                subdivision = (record.get("subdivisions") or [{}])[0]
                result["location"] = compact(
                    {
                        "continent": _en(record.get("continent")),
                        "continent_code": (record.get("continent") or {}).get("code"),
                        "country": _en(record.get("country")),
                        "country_code": (record.get("country") or {}).get("iso_code"),
                        "region": _en(subdivision),
                        "region_code": subdivision.get("iso_code"),
                        "city": _en(record.get("city")),
                        "postal_code": (record.get("postal") or {}).get("code"),
                        "latitude": location.get("latitude"),
                        "longitude": location.get("longitude"),
                        "accuracy_radius_km": location.get("accuracy_radius"),
                        "timezone": location.get("time_zone"),
                    }
                )
                result["registered_country"] = (
                    compact(
                        {
                            "country": _en(record.get("registered_country")),
                            "country_code": (record.get("registered_country") or {}).get(
                                "iso_code"
                            ),
                        }
                    )
                    or None
                )
                result["traits"] = record.get("traits") or None
                result["city_prefix"] = _prefix(ctx.target, prefix_len)
                result["raw"]["city"] = record

        if asn_db is not None:
            record, prefix_len = asn_db.get_with_prefix_len(ctx.target)
            result["databases"]["asn"] = {
                "type": asn_db.metadata().database_type,
                "build_date": _build_date(asn_db),
            }
            if record:
                result["network"] = compact(
                    {
                        "asn": record.get("autonomous_system_number"),
                        "as_name": record.get("autonomous_system_organization"),
                        "prefix": _prefix(ctx.target, prefix_len),
                    }
                )
                result["raw"]["asn"] = record

        if "location" not in result and "network" not in result:
            raise ProviderError("address not found in the GeoLite2 database(s)")
        return result
