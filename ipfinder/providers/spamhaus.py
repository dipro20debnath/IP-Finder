"""Spamhaus ZEN DNS blocklist (SBL + CSS + XBL + DROP + PBL in one query).

  query:  <reversed ip>.zen.spamhaus.org          (public mirrors)
          <reversed ip>.<DQS key>.zen.dq.spamhaus.net   (free Data Query Service key)
  answer: NXDOMAIN = not listed; 127.0.0.x = listed (codes below)
Return codes and the DQS zone format are taken from Spamhaus's own SpamAssassin
rules (github.com/spamhaus/spamassassin-dqs). Error answers 127.255.255.x mean the
query was refused (e.g. 127.255.255.254: sent through a public resolver such as
8.8.8.8), never a listing. Before trusting "not listed", the RFC 5782 test entry
2.0.0.127.<zone> must answer; if it does not, the resolver cannot reach Spamhaus.
Free use is for low-volume, non-commercial queries.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ipfinder.core.dns import DNSLookupError
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError

PUBLIC_ZONE = "zen.spamhaus.org"
DQS_ZONE = "{key}.zen.dq.spamhaus.net"
TEST_ENTRY = "2.0.0.127"

PBL_NOTE = (
    "Policy Block List: an end-user (often dynamic) range that should not send mail "
    "directly; this is not a sign of abuse"
)
XBL_NOTE = "Exploits Block List: an infected or hijacked device (bot, open proxy)"
CODES = {
    "127.0.0.2": ("SBL", "Spamhaus Block List: a known spam source or spam operation", True),
    "127.0.0.3": ("SBL CSS", "low-reputation bulk mail sender (snowshoe spam)", True),
    "127.0.0.4": ("XBL", XBL_NOTE, True),
    "127.0.0.5": ("XBL", XBL_NOTE, True),
    "127.0.0.6": ("XBL", XBL_NOTE, True),
    "127.0.0.7": ("XBL", XBL_NOTE, True),
    "127.0.0.9": ("SBL DROP", "netblock hijacked or run by criminals (DROP)", True),
    "127.0.0.10": ("PBL (ISP)", PBL_NOTE, False),
    "127.0.0.11": ("PBL (Spamhaus)", PBL_NOTE, False),
}
ERRORS = {
    "127.255.255.252": "Spamhaus says the blocklist name was mistyped (check SPAMHAUS_DQS_KEY)",
    "127.255.255.254": (
        "Spamhaus refuses queries sent through public DNS resolvers (8.8.8.8, 1.1.1.1 ...); "
        "use your ISP's resolver or set a free SPAMHAUS_DQS_KEY"
    ),
    "127.255.255.255": (
        "Spamhaus refused the query (too many queries from your resolver); "
        "a free SPAMHAUS_DQS_KEY avoids this"
    ),
}


def reversed_name(target: str) -> str:
    ip = ipaddress.ip_address(target)
    suffix = ".in-addr.arpa" if ip.version == 4 else ".ip6.arpa"
    return ip.reverse_pointer.removesuffix(suffix)


def _numeric(code: str) -> tuple:
    """Sort 127.0.0.4 before 127.0.0.11 (text order would not)."""
    try:
        return (0, int(ipaddress.ip_address(code)))
    except ValueError:
        return (1, code)


def refusal(answers: list[str]) -> str | None:
    for answer in answers:
        if answer.startswith("127.255.255."):
            return ERRORS.get(answer, f"Spamhaus refused the query (code {answer})")
    return None


class SpamhausProvider(Provider):
    name = "spamhaus"
    layer = "L9"
    description = "Spamhaus ZEN listing: spam source, infected host, DROP, PBL (DNS)"
    profiles = ("full",)
    optional_key = "SPAMHAUS_DQS_KEY"
    cache_ttl = HOUR

    def _zone(self, ctx: LookupContext) -> tuple[str, str]:
        key = ctx.config.key_for(self.optional_key)
        return (DQS_ZONE.format(key=key), "DQS") if key else (PUBLIC_ZONE, "public mirror")

    async def _zone_problem(self, ctx: LookupContext, zone: str, timeout: float) -> str | None:
        """Query the RFC 5782 test entry once per run. Messages never contain the
        query name, because it holds the DQS key."""
        cache_key = f"spamhaus-test:{zone}"
        if cache_key not in ctx.session.resources:
            try:
                answers = await ctx.session.dns_resolve(f"{TEST_ENTRY}.{zone}", "A", timeout)
                problem = refusal(answers)
            except DNSLookupError as exc:
                problem = (
                    "your DNS resolver does not reach Spamhaus (its test entry is missing), "
                    "so a listing cannot be checked"
                    if exc.nxdomain
                    else "DNS query to Spamhaus failed or timed out"
                )
            ctx.session.resources[cache_key] = problem
        return ctx.session.resources[cache_key]

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        zone, mode = self._zone(ctx)
        timeout = max(1.0, min(5.0, ctx.config.timeout / 2))
        problem = await self._zone_problem(ctx, zone, timeout)
        if problem:
            raise ProviderError(problem)
        try:
            answers = await ctx.session.dns_resolve(
                f"{reversed_name(ctx.target)}.{zone}", "A", timeout
            )
        except DNSLookupError as exc:
            if exc.nxdomain:
                return {"listed": False, "abuse_listed": False, "lists": [], "zone": mode}
            raise ProviderError("DNS query to Spamhaus failed or timed out") from None
        problem = refusal(answers)
        if problem:
            raise ProviderError(problem)
        lists = []
        for code in sorted(set(answers), key=_numeric):
            name, meaning, abuse = CODES.get(code, (f"code {code}", "unknown Spamhaus code", True))
            lists.append({"code": code, "list": name, "meaning": meaning, "abuse": abuse})
        return {
            "listed": bool(lists),
            "abuse_listed": any(entry["abuse"] for entry in lists),
            "lists": lists,
            "zone": mode,
            "link": f"https://check.spamhaus.org/results/?query={ctx.target}",
        }
