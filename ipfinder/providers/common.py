"""Helpers shared by providers: turning each API's own format into one layout.

Every online provider returns a dict with any of these keys:
  location: continent, continent_code, country, country_code, region, region_code,
            city, district, postal_code, latitude, longitude, accuracy_radius_km,
            timezone, utc_offset_seconds
  network:  asn (int), as_name, as_domain, isp, org, prefix, rir, allocated,
            country_code (registration country)
  flags:    mobile, proxy, hosting (booleans)
  raw:      the provider's original response, for transparency
"""

from __future__ import annotations

import re

_ASN = re.compile(r"^\s*(?:AS)?(\d{1,10})\b\s*(.*)$", re.IGNORECASE)


def clean(value):
    """Empty strings and whitespace-only strings become None."""
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


def parse_asn(text) -> tuple[int | None, str | None]:
    """'AS15169 Google LLC' -> (15169, 'Google LLC'); 'AS15169' -> (15169, None)."""
    if isinstance(text, int):
        return text, None
    if not isinstance(text, str):
        return None, None
    match = _ASN.match(text)
    if not match:
        return None, clean(text)
    return int(match.group(1)), clean(match.group(2))


def compact(mapping: dict) -> dict:
    """Clean every value and drop keys whose value is None."""
    out = {}
    for key, value in mapping.items():
        value = clean(value)
        if value is not None:
            out[key] = value
    return out
