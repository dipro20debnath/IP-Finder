from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from ipfinder import DISCLAIMER, __version__
from ipfinder.core.models import IPReport


def build_document(reports: list[IPReport], errors: list[dict]) -> dict:
    return {
        "tool": "ip-finder",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": DISCLAIMER,
        "reports": [r.to_dict() for r in reports],
        "errors": errors,
    }


# Characters JSON may legally carry raw but a terminal could act on: DEL and the C1
# controls (U+0080-U+009F, e.g. U+009B is CSI) plus invisible format characters
# (zero-width, bidi overrides, BOM). They are written as \uXXXX escapes instead.
_UNSAFE = re.compile("[\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


def render(reports: list[IPReport], errors: list[dict], ascii_only: bool = False) -> str:
    """JSON text. ``ascii_only`` escapes every non-ASCII character, for output
    streams whose encoding (e.g. Windows cp1252) cannot hold them."""
    text = json.dumps(build_document(reports, errors), indent=2, ensure_ascii=ascii_only)
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
