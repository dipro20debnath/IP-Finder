#!/usr/bin/env python3
"""Phase 0: record real API responses into tests/fixtures/ so later phases can be
developed and tested offline against what each provider *actually* returns.

Usage (from the project root, inside the virtual environment):
    python scripts/capture_fixtures.py                   # default IPs
    python scripts/capture_fixtures.py 8.8.8.8 1.1.1.1   # your own IPs
    python scripts/capture_fixtures.py --list            # sources and key status
    python scripts/capture_fixtures.py 8.8.8.8 --only ip-api rdap   # IPs before --only

API keys come from .env or the environment (see .env.example). Keys are never
written into fixture files: URLs are redacted and request headers are not saved.
Sources that need a key you have not set are skipped.

Only standard-library modules are used, so this runs before any provider exists.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipfinder.analysis.offline import analyze  # noqa: E402
from ipfinder.core.config import Config  # noqa: E402
from ipfinder.core.validator import parse_ip  # noqa: E402

DEFAULT_IPS = ("8.8.8.8", "1.1.1.1", "2001:4860:4860::8888")
USER_AGENT = "ip-finder-fixture-capture/2.0 (+https://github.com/dipro20debnath/IP-Finder)"
REDACTED = "REDACTED"
KEPT_RESPONSE_HEADERS = ("content-type", "x-rl", "x-ttl", "retry-after")

IP_API_FIELDS = (
    "status,message,continent,continentCode,country,countryCode,region,regionName,city,"
    "district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,"
    "hosting,query"
)


@dataclass(frozen=True)
class Source:
    name: str
    url: str  # template with {ip} and optionally {key}
    key_env: str | None = None
    key_required: bool = True
    key_header: str | None = None  # send the key in this header instead of the URL
    headers: tuple[tuple[str, str], ...] = ()
    min_interval: float = 1.0  # seconds between requests to this source
    ipv4_only: bool = False


SOURCES = (
    # Free endpoint is HTTP only and allows 45 requests/minute.
    Source("ip-api", "http://ip-api.com/json/{ip}?fields=" + IP_API_FIELDS, min_interval=1.5),
    Source("ipinfo-lite", "https://api.ipinfo.io/lite/{ip}?token={key}", key_env="IPINFO_TOKEN"),
    Source("rdap", "https://rdap.org/ip/{ip}", headers=(("Accept", "application/rdap+json"),)),
    Source(
        "ripestat-prefix-overview",
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=ip-finder",
    ),
    Source(
        "ripestat-routing-status",
        "https://stat.ripe.net/data/routing-status/data.json?resource={ip}&sourceapp=ip-finder",
    ),
    Source(
        "ripestat-abuse-contact",
        "https://stat.ripe.net/data/abuse-contact-finder/data.json"
        "?resource={ip}&sourceapp=ip-finder",
    ),
    Source("internetdb", "https://internetdb.shodan.io/{ip}"),
    Source(
        "greynoise",
        "https://api.greynoise.io/v3/community/{ip}",
        key_env="GREYNOISE_API_KEY",
        key_required=False,
        key_header="key",
        ipv4_only=True,
    ),
    Source(
        "abuseipdb",
        "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        key_env="ABUSEIPDB_API_KEY",
        key_header="Key",
        headers=(("Accept", "application/json"),),
    ),
    # Public API: 4 requests/minute.
    Source(
        "virustotal",
        "https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        key_env="VIRUSTOTAL_API_KEY",
        key_header="x-apikey",
        min_interval=15.5,
    ),
)


def build_request(source: Source, ip: str, keys: dict[str, str]):
    """Return (url, headers, redacted_url), or None when a required key is missing."""
    key = keys.get(source.key_env) if source.key_env else None
    if source.key_env and source.key_required and not key:
        return None
    url = source.url.format(ip=quote(ip, safe=":."), key=quote(key or "", safe=""))
    redacted = source.url.format(ip=quote(ip, safe=":."), key=REDACTED)
    headers = {"User-Agent": USER_AGENT, **dict(source.headers)}
    if key and source.key_header:
        headers[source.key_header] = key
    return url, headers, redacted


def fixture_path(out_dir: Path, source: str, ip: str) -> Path:
    return out_dir / source / (ip.replace(":", "_") + ".json")


def http_get(url: str, headers: dict[str, str], timeout: float = 20.0):
    """Return (status, headers_dict, body_text). HTTP errors are data, not exceptions."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, body


def _parse_body(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def lookup_targets(inputs) -> tuple[list[str], list[str]]:
    """Validate inputs and map each to the address online sources should query."""
    targets, problems = [], []
    for raw in inputs:
        try:
            decision = analyze(parse_ip(raw))["lookup"]
        except ValueError as exc:  # InvalidIPError is a ValueError subclass
            problems.append(f"{raw!r}: {exc}")
            continue
        if decision["eligible"]:
            if decision["target"] not in targets:
                targets.append(decision["target"])
        else:
            problems.append(f"{raw}: {decision['reason']}")
    return targets, problems


def capture(ips, keys, out_dir: Path, sources=SOURCES, fetch=http_get, sleep=time.sleep):
    """Fetch every (source, ip) pair and save it. Returns a list of summary rows."""
    summary = []
    last_call: dict[str, float] = {}
    for source in sources:
        for ip in ips:
            if source.ipv4_only and ":" in ip:
                summary.append((source.name, ip, "skipped (IPv4 only)"))
                continue
            built = build_request(source, ip, keys)
            if built is None:
                summary.append((source.name, ip, f"skipped (set {source.key_env})"))
                continue
            url, headers, redacted = built
            wait = source.min_interval - (time.monotonic() - last_call.get(source.name, -1e9))
            if wait > 0:
                sleep(wait)
            try:
                status, resp_headers, body = fetch(url, headers)
            except Exception as exc:  # one failing source must not stop the capture
                summary.append((source.name, ip, f"error: {type(exc).__name__}: {exc}"))
                continue
            finally:
                last_call[source.name] = time.monotonic()
            lower = {k.lower(): v for k, v in resp_headers.items()}
            kept = {
                k: v
                for k, v in lower.items()
                if k in KEPT_RESPONSE_HEADERS or k.startswith("x-ratelimit")
            }
            record = {
                "source": source.name,
                "ip": ip,
                "url": redacted,
                "status": status,
                "headers": kept,
                "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "body": _parse_body(body),
            }
            path = fixture_path(out_dir, source.name, ip)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", "utf-8")
            summary.append((source.name, ip, f"HTTP {status} -> {path.relative_to(out_dir)}"))
            # ip-api tells us how many requests are left in this minute.
            if lower.get("x-rl") == "0" and lower.get("x-ttl", "").isdigit():
                sleep(int(lower["x-ttl"]) + 1)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("ips", nargs="*", help=f"IPs to capture (default: {DEFAULT_IPS})")
    parser.add_argument("--list", action="store_true", help="list sources and exit")
    parser.add_argument("--only", nargs="+", metavar="SOURCE", help="capture only these sources")
    parser.add_argument("--out", type=Path, default=ROOT / "tests" / "fixtures")
    args = parser.parse_args(argv)

    keys = dict(Config.load(dotenv_path=ROOT / ".env").api_keys)
    sources = SOURCES
    if args.only:
        unknown = set(args.only) - {s.name for s in SOURCES}
        if unknown:
            parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")
        sources = tuple(s for s in SOURCES if s.name in args.only)

    if args.list:
        for s in SOURCES:
            if not s.key_env:
                status = "no key needed"
            elif keys.get(s.key_env):
                status = f"{s.key_env} set"
            else:
                status = f"{s.key_env} {'missing' if s.key_required else 'not set (optional)'}"
            print(f"{s.name:26} {status}")
        return 0

    targets, problems = lookup_targets(args.ips or DEFAULT_IPS)
    for p in problems:
        print(f"[skip] {p}")
    if not targets:
        print("[!] No globally reachable IP to capture.")
        return 1
    for row in capture(targets, keys, args.out, sources):
        print(f"{row[0]:26} {row[1]:40} {row[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
