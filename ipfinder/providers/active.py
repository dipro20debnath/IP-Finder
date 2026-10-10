"""Active probes as providers (L10, stage 3). They run only with --active, after
the user has confirmed they may test the target, and only for public addresses.

  rtt         round-trip time: TCP handshakes (443, then 80) and the system ping;
              also where you are, for the speed-of-light check in the verdict
  traceroute  the network path, each hop labelled with its network (Team Cymru)
  tls-cert    the certificate on port 443: names it covers, issuer, validity
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from ipfinder.active import probes
from ipfinder.core.dns import DNSLookupError
from ipfinder.core.http import request_json
from ipfinder.providers.base import LookupContext, Provider, ProviderError
from ipfinder.providers.cymru import origin_query, parse_origin

ALL_PROFILES = ("quick", "standard", "full")
VANTAGE_URL = "http://ip-api.com/json/"


def parse_location_setting(text: str) -> tuple[float, float] | None:
    """IPFINDER_LOCATION="23.8103,90.4125" -> (23.8103, 90.4125)."""
    try:
        lat, lon = (float(part) for part in text.split(","))
    except ValueError:
        return None
    if -90 <= lat <= 90 and -180 <= lon <= 180:
        return lat, lon
    return None


async def vantage_point(ctx: LookupContext) -> dict[str, Any]:
    """Where this computer is: IPFINDER_LOCATION if set, otherwise the location of
    your own public IP from ip-api (city level, so 100 km of slack is allowed)."""
    session = ctx.session
    if "vantage" in session.resources:
        return session.resources["vantage"]
    configured = ctx.config.my_location
    if configured:
        point = parse_location_setting(configured)
        if point is None:
            result = {"error": "IPFINDER_LOCATION must look like 23.8103,90.4125"}
        else:
            result = {
                "latitude": point[0],
                "longitude": point[1],
                "source": "IPFINDER_LOCATION",
                "uncertainty_km": 10,
            }
    else:
        try:
            _, data = await request_json(
                session,
                "GET",
                VANTAGE_URL,
                params={"fields": "status,message,lat,lon,city,countryCode"},
                limiter=session.limiter("ip-api", 45, 60.0),
            )
        except ProviderError as exc:
            data = {"status": "fail", "message": str(exc)}
        if isinstance(data, dict) and data.get("status") == "success":
            result = {
                "latitude": round(float(data["lat"]), 2),
                "longitude": round(float(data["lon"]), 2),
                "city": data.get("city"),
                "country_code": data.get("countryCode"),
                "source": "ip-api (your public IP)",
                "uncertainty_km": 100,
            }
        else:
            message = data.get("message") if isinstance(data, dict) else None
            result = {"error": f"your own location is unknown ({message or 'ip-api failed'})"}
    session.resources["vantage"] = result
    return result


INTERCEPTED = (
    "a proxy or firewall on your network answers TCP port {port} itself (it even answers "
    "for 192.0.2.1, an address that cannot exist)"
)


async def intercepted(ctx: LookupContext, port: int) -> bool:
    key = f"interception:{port}"
    if key not in ctx.session.resources:
        ctx.session.resources[key] = await probes.interception_check(port)
    return ctx.session.resources[key]


class ActiveProvider(Provider):
    layer = "L10"
    active = True
    stage = 3
    profiles = ALL_PROFILES


class RTTProvider(ActiveProvider):
    name = "rtt"
    description = "Round-trip time (TCP handshake and ping), for the speed-of-light check"
    timeout = 30.0

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        tcp, ping_out = await asyncio.gather(
            probes.tcp_rtt(ctx.target),
            probes.run_command(probes.ping_command(ctx.target), timeout=15.0),
        )
        result: dict[str, Any] = {}
        if tcp and await intercepted(ctx, tcp["port"]):
            result["tcp"] = {
                "port": tcp["port"],
                "error": INTERCEPTED.format(port=tcp["port"])
                + ", so TCP timings are not the target's",
            }
        elif tcp:
            result["tcp"] = tcp
        if ping_out is None:
            result["icmp"] = {"error": "the ping command is not installed"}
        else:
            times = probes.parse_ping(ping_out[1])
            if times:
                result["icmp"] = {
                    "samples_ms": times,
                    "min_ms": min(times),
                    "sent": probes.SAMPLES,
                    "received": len(times),
                }
            else:
                result["icmp"] = {"error": "no ping reply (ICMP is often filtered)"}
        candidates = [
            x["min_ms"] for x in (result.get("tcp"), result.get("icmp")) if x and "min_ms" in x
        ]
        if not candidates:
            if "error" in result.get("tcp", {}):
                ping = result["icmp"].get("error", "no answer")
                raise ProviderError(
                    INTERCEPTED.format(port=result["tcp"]["port"])
                    + f"; ping: {ping}; so the round trip cannot be measured"
                )
            raise ProviderError("no reply to TCP ports 443/80 or to ping")
        result["min_rtt_ms"] = min(candidates)
        result["vantage"] = await vantage_point(ctx)
        return result


async def annotate(ctx: LookupContext, hops: list[dict]) -> None:
    """Add the network (ASN, prefix, registry country) of each public hop."""
    limit = asyncio.Semaphore(8)

    async def one(hop: dict) -> None:
        address = hop.get("ip")
        if not address:
            return
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            hop["network"] = "private / reserved"
            return
        async with limit:
            try:
                records = await ctx.session.dns_resolve(origin_query(address), "TXT", 2.0)
                origin = parse_origin(records)
            except (DNSLookupError, ProviderError):
                return
        hop["asn"] = origin["asn"]
        hop["prefix"] = origin["prefix"]
        if origin.get("country_code"):
            hop["country_code"] = origin["country_code"]

    await asyncio.gather(*(one(hop) for hop in hops))


class TracerouteProvider(ActiveProvider):
    name = "traceroute"
    description = "Network path to the address, hop by hop (system traceroute)"
    timeout = 60.0

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        for command in probes.traceroute_commands(ctx.target):
            output = await probes.run_command(command, timeout=50.0)
            if output is None:
                continue
            hops = probes.parse_traceroute(output[1])
            if not hops:
                raise ProviderError(f"{command[0]} produced no hops")
            await annotate(ctx, hops)
            reached = any(h.get("ip") == ctx.target for h in hops)
            return {"tool": command[0], "hops": hops, "reached": reached}
        names = " / ".join(c[0] for c in probes.traceroute_commands(ctx.target))
        raise ProviderError(f"{names} is not installed")


class TLSCertProvider(ActiveProvider):
    name = "tls-cert"
    description = "TLS certificate on port 443: domain names, issuer, validity"
    timeout = 15.0

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        if await intercepted(ctx, 443):
            raise ProviderError(
                INTERCEPTED.format(port=443)
                + ", so any certificate would be the proxy's, not the target's"
            )
        try:
            cert = await probes.tls_certificate(ctx.target, timeout=5.0)
        except asyncio.TimeoutError:
            raise ProviderError("no TLS answer on port 443 (timed out)") from None
        except ConnectionRefusedError:
            raise ProviderError("port 443 is closed") from None
        except (OSError, ValueError) as exc:
            raise ProviderError(f"TLS on port 443 failed: {type(exc).__name__}: {exc}") from None
        cert["crt_sh"] = f"https://crt.sh/?q={cert['sha256']}"
        return cert
