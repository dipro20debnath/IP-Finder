"""Reverse DNS: the PTR hostname, and whether it is forward-confirmed (FCrDNS).

  8.8.8.8 -> PTR 8.8.8.8.in-addr.arpa -> "dns.google"
  dns.google -> A -> 8.8.8.8, 8.8.4.4   (contains the address: forward-confirmed)
Whoever controls the reverse zone can publish any name, so a PTR name that does not
resolve back to the address proves nothing (FCrDNS is what mail servers check).
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from ipfinder.analysis.hostname import hostname_hints
from ipfinder.core.dns import DNSLookupError
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError

MAX_NAMES = 5  # an address may have several PTR records; check at most this many
# A PTR record that always exists; if it "does not exist" too, the resolver is filtered.
CANARY = "8.8.8.8.in-addr.arpa"


class ReverseDNSProvider(Provider):
    name = "reverse-dns"
    layer = "L6"
    description = "PTR hostname, forward-confirmed reverse DNS, hostname hints"
    cache_ttl = HOUR

    async def _dns_works(self, session, timeout: float) -> bool:
        key = "reverse-dns-check"
        if key not in session.resources:
            try:
                session.resources[key] = bool(await session.dns_resolve(CANARY, "PTR", timeout))
            except DNSLookupError:
                session.resources[key] = False
        return session.resources[key]

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        resolve = ctx.session.dns_resolve
        timeout = max(1.0, min(5.0, ctx.config.timeout / 2))
        ip = ipaddress.ip_address(ctx.target)
        try:
            names = await resolve(ip.reverse_pointer, "PTR", timeout)
        except DNSLookupError as exc:
            if not exc.nxdomain:
                raise ProviderError(str(exc)) from None
            if not await self._dns_works(ctx.session, timeout):
                raise ProviderError(
                    "your DNS resolver says every reverse name is missing (blocked or "
                    "filtered), so reverse DNS is unknown"
                ) from None
            return {"ptr": [], "note": "no PTR record (the operator set no reverse DNS name)"}

        names = list(dict.fromkeys(n.strip().rstrip(".").lower() for n in names if n.strip()))
        names = names[:MAX_NAMES]
        if not names:
            return {"ptr": [], "note": "no PTR record (the operator set no reverse DNS name)"}
        rdtype = "A" if ip.version == 4 else "AAAA"

        async def forward(name: str) -> tuple[list[str], str | None]:
            try:
                return await resolve(name, rdtype, timeout), None
            except DNSLookupError as exc:
                return [], str(exc)

        answers = await asyncio.gather(*(forward(name) for name in names))
        checks = []
        for name, (addresses, error) in zip(names, answers, strict=True):
            found = set()
            for address in addresses:
                try:
                    found.add(ipaddress.ip_address(address))
                except ValueError:
                    continue
            check: dict[str, Any] = {
                "hostname": name,
                "forward": [str(a) for a in sorted(found)],
                "confirmed": ip in found,
            }
            if error:
                check["forward_error"] = error
            checks.append(check)

        confirmed = [c["hostname"] for c in checks if c["confirmed"]]
        best = confirmed[0] if confirmed else names[0]
        return {
            "ptr": names,
            "hostname": best,
            "forward_confirmed": bool(confirmed),
            "fcrdns": checks,
            "hints": hostname_hints(best, ctx.target),
        }
