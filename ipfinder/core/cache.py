"""Two-level lookup cache.

* Memory (per run): always on. Shares results between an ip-api batch request and
  the per-IP step, and stops the same address being fetched twice in one run.
  Failures are remembered here too, but never written to disk.
* SQLite file (``data/cache.sqlite`` by default): optional, survives between runs,
  saves free-tier quota. Each provider sets its own time-to-live.

The cache lives on your machine only; delete it with ``ipfinder cache clear``.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 1  # bump when provider data layout changes, old entries are ignored


class Cache:
    def __init__(self, path: str | Path | None = None, clock=time.time):
        self._clock = clock
        self._memory: dict[tuple[str, str], tuple[float, dict]] = {}
        self._errors: dict[tuple[str, str], str] = {}
        self._db: sqlite3.Connection | None = None
        self.path = Path(path) if path else None
        self.warning: str | None = None
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._db = sqlite3.connect(self.path)
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS cache (provider TEXT NOT NULL, key TEXT NOT NULL,"
                    " expires REAL NOT NULL, data TEXT NOT NULL, PRIMARY KEY (provider, key))"
                )
                self._db.commit()
            except (OSError, sqlite3.Error) as exc:
                self._db = None
                self.warning = f"cache disabled ({self.path}: {exc})"

    @staticmethod
    def _name(provider: str) -> str:
        return f"{provider}@v{SCHEMA_VERSION}"

    @property
    def persistent(self) -> bool:
        return self._db is not None

    def get(self, provider: str, key: str) -> dict | None:
        now = self._clock()
        hit = self._memory.get((provider, key))
        if hit and hit[0] > now:
            return hit[1]
        if self._db is None:
            return None
        try:
            row = self._db.execute(
                "SELECT expires, data FROM cache WHERE provider = ? AND key = ?",
                (self._name(provider), key),
            ).fetchone()
        except sqlite3.Error:
            return None
        if not row or row[0] <= now:
            return None
        try:
            data = json.loads(row[1])
        except ValueError:
            return None
        self._memory[(provider, key)] = (row[0], data)
        return data

    def put(self, provider: str, key: str, data: dict, ttl: float) -> None:
        if ttl <= 0:
            return
        expires = self._clock() + ttl
        self._memory[(provider, key)] = (expires, data)
        self._errors.pop((provider, key), None)
        if self._db is None:
            return
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO cache (provider, key, expires, data) VALUES (?, ?, ?, ?)",
                (self._name(provider), key, expires, json.dumps(data, ensure_ascii=False)),
            )
            self._db.commit()
        except sqlite3.Error:
            pass  # caching is an optimisation; never fail a lookup because of it

    def put_error(self, provider: str, key: str, message: str) -> None:
        """Remember a failure for this run only (memory, never persisted)."""
        self._errors[(provider, key)] = message

    def get_error(self, provider: str, key: str) -> str | None:
        return self._errors.get((provider, key))

    def stats(self) -> dict:
        info = {"path": str(self.path) if self.path else None, "persistent": self.persistent}
        if self._db is not None:
            now = self._clock()
            rows = self._db.execute(
                "SELECT provider, COUNT(*), SUM(expires > ?) FROM cache GROUP BY provider", (now,)
            ).fetchall()
            info["providers"] = {
                p.split("@")[0]: {"entries": n, "fresh": f or 0} for p, n, f in rows
            }
        return info

    def clear(self) -> int:
        self._memory.clear()
        self._errors.clear()
        if self._db is None:
            return 0
        removed = self._db.execute("DELETE FROM cache").rowcount
        self._db.commit()
        return removed

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
