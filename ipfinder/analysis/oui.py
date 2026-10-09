"""Look up the manufacturer behind a MAC address using the IEEE OUI (MA-L) list.

The list is not bundled; download it once into ``data/oui.csv``:
    curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
Columns: Registry, Assignment (6 hex digits), Organization Name, Organization Address.
"""

from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=4)
def _load(path: str, mtime_ns: int) -> dict[str, str]:
    table: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            assignment = (row.get("Assignment") or "").strip().upper()
            name = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and name:
                table[assignment] = name
    return table


def load_oui_db(path: str | Path) -> dict[str, str] | None:
    """Return {"001A2B": "Vendor"} or None when the file is missing/unreadable."""
    p = Path(path)
    try:
        return _load(str(p.resolve()), p.stat().st_mtime_ns)
    except (OSError, csv.Error):
        return None


def make_lookup(path: str | Path):
    """A ``mac -> vendor | None`` function, or None when no OUI database is available."""
    db = load_oui_db(path)
    if not db:
        return None

    def lookup(mac: str) -> str | None:
        key = mac.replace(":", "").replace("-", "").upper()[:6]
        return db.get(key)

    return lookup
