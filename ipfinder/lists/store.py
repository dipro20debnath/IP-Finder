"""Local copies of the downloaded lists (``data/lists/`` by default).

Each list is stored as downloaded (``<filename>``) next to a small metadata file
(``<name>.meta.json``: when it was fetched, from where, how many entries). A new
download replaces the old file only after it parsed successfully, so a broken
download (an error page, a cut-off transfer) never destroys a working list.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ipfinder.core.errors import ProviderError
from ipfinder.core.http import fetch_bytes, fetch_text
from ipfinder.lists.specs import MB, Dataset, ListSpec


class ListError(Exception):
    """A list is missing or its file cannot be read."""

    def __init__(self, message: str, missing: bool = False):
        super().__init__(message)
        self.missing = missing


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()


class ListStore:
    def __init__(self, directory: str | Path, clock=time.time):
        self.directory = Path(directory)
        self._clock = clock
        self._loaded: dict[str, tuple[int, Dataset]] = {}

    def path(self, spec: ListSpec) -> Path:
        return self.directory / spec.filename

    def _meta_path(self, spec: ListSpec) -> Path:
        return self.directory / f"{spec.name}.meta.json"

    def has(self, spec: ListSpec) -> bool:
        return self.path(spec).is_file()

    def info(self, spec: ListSpec) -> dict[str, Any] | None:
        """When the local copy was fetched, its age, and whether it is stale."""
        try:
            stat = self.path(spec).stat()
        except OSError:
            return None
        try:
            meta = json.loads(self._meta_path(spec).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
        meta = meta if isinstance(meta, dict) else {}
        fetched = meta.get("fetched_at")
        if not isinstance(fetched, (int, float)):
            fetched = stat.st_mtime
        age = max(0.0, self._clock() - fetched)
        info = {
            "fetched": _utc(fetched),
            "age_hours": round(age / 3600, 1),
            "stale": age > spec.stale_after,
        }
        for key in ("entries", "published", "url"):
            if meta.get(key) is not None:
                info[key] = meta[key]
        return info

    def age(self, spec: ListSpec) -> float | None:
        info = self.info(spec)
        return None if info is None else info["age_hours"] * 3600

    def load(self, spec: ListSpec) -> Dataset:
        """The parsed list, read once per run. Raises ListError if missing or unreadable."""
        path = self.path(spec)
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            raise ListError(f"{spec.name} is not downloaded", missing=True) from None
        cached = self._loaded.get(spec.name)
        if cached is not None and cached[0] == mtime:
            return cached[1]
        try:
            dataset = spec.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            raise ListError(
                f"{path} cannot be read ({exc}); run: ipfinder update-lists --force {spec.name}"
            ) from None
        self._loaded[spec.name] = (mtime, dataset)
        return dataset

    async def update(self, spec: ListSpec, session, force: bool = False) -> dict[str, Any]:
        """Download ``spec`` unless the local copy is younger than ``spec.refresh``."""
        age = self.age(spec)
        if age is not None and age < spec.refresh and not force:
            return {"name": spec.name, "status": "fresh", **(self.info(spec) or {})}
        try:
            url = spec.url
            if spec.page_pattern:
                page = await fetch_text(session, spec.url, max_bytes=5 * MB)
                match = re.search(spec.page_pattern, page)
                if not match:
                    raise ProviderError(
                        "download link not found on the page (its layout may have changed)"
                    )
                url = match.group(0)
            headers = None
            if spec.key_header and session.config.key_for(spec.key_header[0]):
                headers = {spec.key_header[1]: session.config.key_for(spec.key_header[0])}
            data, _ = await fetch_bytes(session, url, max_bytes=spec.max_bytes, headers=headers)
            try:
                dataset = spec.parse(data.decode("utf-8", "replace"))
            except ValueError as exc:
                raise ProviderError(f"the download is not a valid list ({exc})") from None
            self.directory.mkdir(parents=True, exist_ok=True)
            _write_atomic(self.path(spec), data)
            meta = {
                "name": spec.name,
                "url": url,
                "fetched_at": self._clock(),
                "entries": dataset.entries,
                "published": dataset.published,
                "bytes": len(data),
            }
            _write_atomic(self._meta_path(spec), json.dumps(meta, indent=1).encode("utf-8"))
        except (ProviderError, OSError) as exc:
            return {"name": spec.name, "status": "failed", "error": str(exc)}
        self._loaded[spec.name] = (self.path(spec).stat().st_mtime_ns, dataset)
        return {"name": spec.name, "status": "updated", **(self.info(spec) or {})}
