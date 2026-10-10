"""Base for providers that answer from downloaded lists (no network at lookup time)."""

from __future__ import annotations

import asyncio
from typing import Any

from ipfinder.core.config import Config
from ipfinder.lists.specs import SPECS, Dataset
from ipfinder.lists.store import ListError, ListStore
from ipfinder.providers.base import LookupContext, Provider

NOT_DOWNLOADED = "list not downloaded (run: ipfinder update-lists)"


class ListProvider(Provider):
    lists: tuple[str, ...] = ()  # names in ipfinder.lists.specs.SPECS
    local = True  # the lists were downloaded beforehand by "update-lists"

    def unavailable_reason(self, config: Config) -> str | None:
        reason = super().unavailable_reason(config)
        if reason:
            return reason
        store = ListStore(config.lists_dir)
        if not any(store.has(SPECS[name]) for name in self.lists):
            return NOT_DOWNLOADED
        return None

    async def load(self, ctx: LookupContext, name: str, report: dict[str, Any]) -> Dataset | None:
        """The parsed list, or None (recorded in ``report``) when it is missing or unreadable.
        Parsing runs in a thread so slow-to-parse lists do not hold up network lookups."""
        spec = SPECS[name]
        store = ctx.session.lists
        if not store.has(spec):
            report.setdefault("not_downloaded", []).append(name)
            return None
        try:
            dataset = await asyncio.to_thread(store.load, spec)
        except ListError as exc:
            report.setdefault("problems", []).append(str(exc))
            return None
        info = store.info(spec) or {}
        report.setdefault("lists", {})[name] = info
        if info.get("stale"):
            report.setdefault("stale", []).append(name)
        return dataset
