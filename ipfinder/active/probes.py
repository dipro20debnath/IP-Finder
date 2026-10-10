"""The probes themselves. Each one sends a small, bounded number of packets:

  tcp_rtt         up to 4 TCP handshakes on port 443 (then 80); a refused
                  connection also measures the round trip (SYN -> RST)
  interception    one handshake to 192.0.2.1, an address that cannot exist, to
                  detect a proxy that answers for everyone (then TCP and TLS
                  results describe the proxy, not the target)
  system ping     4 ICMP echo requests via the operating system's ping command
  traceroute      the system traceroute / tracert / tracepath, at most 30 hops
  tls_certificate one TLS handshake on port 443 to read the certificate, and one
                  more to see whether your system trusts it

Commands run without a shell, with the address as a separate argument (it is a
validated IP address in any case).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import os
import re
import shutil
import ssl
import sys
import time

from ipfinder.active.x509 import parse_certificate

SAMPLES = 4
MAX_HOPS = 30
_MS = re.compile(r"(<)?\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)
_PING_TIME = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)
_HOP = re.compile(r"^\s*(\d+)\??:?\s")


# ------------------------------------------------------------------ commands


async def run_command(args: list[str], timeout: float) -> tuple[int, str] | None:
    """Run a command; None if it is not installed. Output is decoded leniently."""
    if shutil.which(args[0]) is None:
        return None
    env = dict(os.environ)
    if sys.platform != "win32":
        env["LC_ALL"] = "C"  # English output, so it can be parsed
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    chunks: list[bytes] = []

    async def pump() -> None:
        async for line in process.stdout:
            chunks.append(line)

    try:
        await asyncio.wait_for(asyncio.gather(pump(), process.wait()), timeout)
    except asyncio.TimeoutError:  # keep what arrived (e.g. the first traceroute hops)
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
    code = process.returncode if process.returncode is not None else -1
    return code, b"".join(chunks).decode("utf-8", "replace")


def ping_command(target: str, platform: str = sys.platform) -> list[str]:
    version = ipaddress.ip_address(target).version
    if platform == "win32":
        return ["ping", "-n", str(SAMPLES), "-w", "2000", target]
    if platform == "darwin":
        if version == 6:
            return ["ping6", "-n", "-c", str(SAMPLES), target]
        return ["ping", "-n", "-c", str(SAMPLES), "-W", "2000", target]  # macOS: -W in ms
    return ["ping", "-n", "-c", str(SAMPLES), "-W", "2", target]  # Linux: -W in seconds


def parse_ping(output: str) -> list[float]:
    """Round-trip times from reply lines (every OS prints "ttl" on them; Windows
    may localise the rest, so only the number before "ms" is used)."""
    times = []
    for line in output.splitlines():
        if "ttl" not in line.lower():
            continue
        match = _PING_TIME.search(line)
        if match:
            times.append(float(match.group(1).replace(",", ".")))
    return times


def traceroute_commands(target: str, platform: str = sys.platform) -> list[list[str]]:
    """Candidates in order of preference; the first one installed is used."""
    version = ipaddress.ip_address(target).version
    hops = str(MAX_HOPS)
    if platform == "win32":
        return [["tracert", "-d", "-h", hops, "-w", "1000", target]]
    if platform == "darwin" and version == 6:
        return [["traceroute6", "-n", "-q", "1", "-w", "1", "-m", hops, target]]
    return [
        ["traceroute", "-n", "-q", "1", "-w", "1", "-m", hops, target],
        ["tracepath", "-n", "-m", hops, target],  # Linux, needs no privileges
    ]


def _address(token: str) -> str | None:
    token = token.strip("()[],")
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def parse_traceroute(output: str) -> list[dict]:
    """Hops from traceroute, tracert or tracepath output: [{"hop", "ip", "rtt_ms"}].
    A hop that did not answer has ip None."""
    hops: dict[int, dict] = {}
    for line in output.splitlines():
        match = _HOP.match(line)
        if not match:
            continue
        number = int(match.group(1))
        if not 1 <= number <= MAX_HOPS:
            continue
        rest = line[match.end() :]
        address = next((a for a in map(_address, rest.split()) if a), None)
        times = [float(m.group(2).replace(",", ".")) for m in _MS.finditer(rest)]
        hop = {"hop": number, "ip": address, "rtt_ms": min(times) if times else None}
        current = hops.get(number)
        if current is None or (current["ip"] is None and address):
            hops[number] = hop  # tracepath repeats hops; keep the one with an answer
    return [hops[n] for n in sorted(hops)]


# ------------------------------------------------------------------ TCP round trip


async def tcp_rtt(target: str, ports=(443, 80), samples: int = SAMPLES, timeout: float = 2.0):
    """Time TCP handshakes. Returns None when no port answered at all."""
    for port in ports:
        times, state = [], None
        for _ in range(samples):
            start = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout)
            except ConnectionRefusedError:
                state = state or "refused"
                # Windows retries a refused connection for about a second, so its
                # timing is not a round trip there.
                if sys.platform != "win32":
                    times.append((time.perf_counter() - start) * 1000)
                continue
            except (asyncio.TimeoutError, OSError):
                continue
            times.append((time.perf_counter() - start) * 1000)
            state = "open"
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1.0)
        if times:
            return {
                "port": port,
                "state": state,
                "samples_ms": [round(t, 2) for t in times],
                "min_ms": round(min(times), 2),
            }
    return None


# ------------------------------------------------------------------ interception


# TEST-NET-1 (RFC 5737): documentation only, never routed on the internet. If a
# handshake to it succeeds (or is refused), something on your own network is
# answering connections on behalf of every address.
CANARY = "192.0.2.1"


async def interception_check(port: int, timeout: float = 2.0, host: str = CANARY) -> bool:
    """True when a transparent proxy or firewall answers TCP connections itself
    (corporate TLS inspection, antivirus HTTPS scanning, captive portals, some
    cloud sandboxes). Its answers would look like the target's but are not."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return True  # a non-existent host cannot refuse; a local box did
    except (asyncio.TimeoutError, OSError):
        return False  # normal: the packet went nowhere
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    return True


# ------------------------------------------------------------------ TLS


async def _handshake(target: str, port: int, context: ssl.SSLContext, timeout: float):
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(target, port, ssl=context, server_hostname=""), timeout
    )
    try:
        tls = writer.get_extra_info("ssl_object")
        return tls.getpeercert(binary_form=True), tls.version(), (tls.cipher() or ("?",))[0]
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def tls_certificate(target: str, port: int = 443, timeout: float = 5.0, cafile=None) -> dict:
    """Read the certificate the server presents to a client that sends no name
    (SNI), as anyone connecting by IP would see it."""
    reader = ssl.create_default_context()
    reader.check_hostname = False
    reader.verify_mode = ssl.CERT_NONE
    der, version, cipher = await _handshake(target, port, reader, timeout)
    if not der:
        raise ValueError("the server sent no certificate")
    result = parse_certificate(der)
    result.update(port=port, tls_version=version, cipher=cipher)
    result["sha256"] = hashlib.sha256(der).hexdigest()

    verifier = ssl.create_default_context(cafile=cafile)
    verifier.check_hostname = False  # an IP address rarely appears in the certificate
    try:
        await _handshake(target, port, verifier, timeout)
        result["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        result["trusted"] = False
        result["trust_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        result["trusted"] = None
    return result
