"""Threat lists checked offline (downloaded by "ipfinder update-lists"), so no
third party learns which address you looked up:

  feodo          abuse.ch Feodo Tracker: botnet command-and-control servers
                 (Dridex, Emotet, QakBot ...), with port, malware and last online time
  spamhaus-drop  Spamhaus DROP / DROPv6 (netblocks hijacked or run by criminals)
                 and ASN-DROP (whole networks), matched by prefix and by ASN
"""

from __future__ import annotations

from typing import Any

from ipfinder.providers.base import LookupContext, ProviderError
from ipfinder.providers.list_base import ListProvider
from ipfinder.providers.peeringdb import known_asn


class FeodoProvider(ListProvider):
    name = "feodo"
    layer = "L9"
    description = "Botnet C2 server check (abuse.ch Feodo Tracker list, offline)"
    lists = ("feodo",)

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {}
        dataset = await self.load(ctx, "feodo", report)
        if dataset is None:
            raise ProviderError("; ".join(report.get("problems", [])) or "list not available")
        hit = dataset.index.longest(ctx.target)
        report["listed"] = hit is not None
        report["entries"] = [v for v in hit[1] if isinstance(v, dict)] if hit else []
        return report


class SpamhausDropProvider(ListProvider):
    name = "spamhaus-drop"
    layer = "L9"
    description = "Hijacked / criminal network check (Spamhaus DROP lists, offline)"
    stage = 2  # ASN-DROP needs the ASN from stage 1
    lists = ("spamhaus-drop-v4", "spamhaus-drop-v6", "spamhaus-asndrop")

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        report: dict[str, Any] = {"evidence": []}
        for name in ("spamhaus-drop-v4", "spamhaus-drop-v6"):
            dataset = await self.load(ctx, name, report)
            hit = dataset.index.longest(ctx.target) if dataset is not None else None
            if hit:
                sbl = next((v for v in hit[1] if v), None)
                report["evidence"].append({"type": "prefix", "value": hit[0], "sblid": sbl})
        asn = known_asn(ctx)
        asns = await self.load(ctx, "spamhaus-asndrop", report)
        if asns is not None and asn is not None and asn in asns.asns:
            report["evidence"].append(
                {"type": "asn", "value": f"AS{asn}", "name": asns.asns[asn] or None}
            )
        if not report.get("lists"):
            raise ProviderError("; ".join(report.get("problems", [])) or "no DROP list available")
        report["listed"] = bool(report["evidence"])
        return report
