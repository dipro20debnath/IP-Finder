"""Does the address belong to a cloud, hosting or CDN company? Checked against the
ranges they publish themselves (AWS, Google, Azure, Oracle, Cloudflare, Fastly),
downloaded by "ipfinder update-lists".

A match says who operates the address (a rented server, a CDN edge), not who is
behind a connection from it.
"""

from __future__ import annotations

from typing import Any

from ipfinder.lists.specs import CLOUD_LISTS, SPECS
from ipfinder.providers.base import LookupContext, ProviderError
from ipfinder.providers.list_base import ListProvider


def _unique(values) -> list[str]:
    return sorted({v for v in values if isinstance(v, str) and v})


def describe(name: str, hits: list[tuple[str, list]]) -> dict[str, Any]:
    """Turn every matching block of one list into one report entry."""
    spec = SPECS[name]
    prefix, values = hits[0]
    every = [v for _, vs in hits for v in vs]
    match: dict[str, Any] = {"provider": spec.label, "list": name, "prefix": prefix}
    if name == "aws":
        region, _, border_group = values[0]
        services = _unique(v[1] for v in every)
        if len(services) > 1 and "AMAZON" in services:
            services.remove("AMAZON")  # AMAZON is the umbrella; the others are specific
        match.update(region=region, services=services)
        if border_group and border_group != region:
            match["network_border_group"] = border_group
    elif name == "google-cloud":
        service, scope = values[0]
        match.update(region=scope, services=_unique([service]))
    elif name == "azure":
        match["region"] = next((v[1] for v in every if v[1]), None)
        match["services"] = _unique(v[2] for v in every)
        match["service_tags"] = _unique(v[0] for v in every)[:8]
    elif name == "oracle":
        region, tags = values[0]
        match.update(region=region, services=_unique(tags))
    return {k: v for k, v in match.items() if v not in (None, [], {})}


class CloudRangesProvider(ListProvider):
    name = "cloud-ranges"
    layer = "L7"
    description = "Cloud / hosting / CDN range check (providers' own lists, offline)"
    lists = CLOUD_LISTS

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {"matches": []}
        for name in self.lists:
            dataset = await self.load(ctx, name, report)
            if dataset is None:
                continue
            hits = dataset.index.lookup(ctx.target)
            if hits:
                report["matches"].append(describe(name, hits))
        if not report.get("lists"):
            raise ProviderError("; ".join(report.get("problems", [])) or "no cloud list available")

        names = [m["list"] for m in report["matches"]]
        if "google" in names:
            google = report["matches"][names.index("google")]
            if "google-cloud" in names:
                report["matches"].remove(google)  # cloud.json is a part of goog.json
            elif "google-cloud" in report["lists"]:
                google["note"] = (
                    "Google's own services and APIs (not a Google Cloud customer range)"
                )
        report["checked"] = list(report["lists"])
        return report
