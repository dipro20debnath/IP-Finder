from __future__ import annotations

import json
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


def render(reports: list[IPReport], errors: list[dict]) -> str:
    return json.dumps(build_document(reports, errors), indent=2, ensure_ascii=False)
