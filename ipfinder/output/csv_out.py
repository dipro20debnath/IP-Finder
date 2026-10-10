"""CSV export: one row per address, the headline facts only (the JSON output has
everything). Lists are joined with "; ".

Text from the network (AS names, hostnames, registry fields) could start with
"=", "+", "-" or "@", which Excel and LibreOffice run as a formula ("CSV
injection"). Such text cells get a leading apostrophe; real numbers (including
negative longitudes) are written as numbers and left alone.
"""

from __future__ import annotations

import csv
import io

from ipfinder.core.models import IPReport
from ipfinder.core.text import display_safe

COLUMNS = (
    "input",
    "ip",
    "version",
    "address_type",
    "connection_type",
    "connection_evidence",
    "anycast",
    "country",
    "city",
    "latitude",
    "longitude",
    "location_confidence",
    "location_spread_km",
    "asn",
    "as_name",
    "prefix",
    "rir",
    "rpki",
    "network_name",
    "registered_to",
    "abuse_email",
    "ptr",
    "forward_confirmed",
    "tor_exit",
    "icloud_private_relay",
    "cloud_or_cdn",
    "listed_vpn_network",
    "listed_datacenter",
    "reputation_score",
    "reputation_label",
    "exposure_score",
    "open_ports",
    "possible_cves",
    "rtt_ms",
    "speed_of_light_check",
    "sources_ok",
    "sources_failed",
    "error",
)
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_ASN_ORDER = ("team-cymru", "ripestat", "maxmind", "ipinfo-lite", "ip-api")


def _safe(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(v) for v in value)
    text = display_safe(str(value))
    return "'" + text if text.startswith(_FORMULA_START) else text


def _ok(report: IPReport, name: str) -> dict:
    result = report.result(name)
    return result.data if result is not None and result.ok else {}


def _network(report: IPReport) -> dict:
    for name in _ASN_ORDER:
        network = _ok(report, name).get("network") or {}
        if isinstance(network.get("asn"), int):
            return network
    return {}


def row(report: IPReport) -> dict:
    offline = _ok(report, "offline")
    verdict, summary = report.verdict or {}, report.summary or {}
    connection = verdict.get("connection") or {}
    location = verdict.get("location") or {}
    network = _network(report)
    rdap = _ok(report, "rdap").get("registration") or {}
    rdns = _ok(report, "reverse-dns")
    anonymity = summary.get("anonymity") or {}
    internetdb = _ok(report, "internetdb")
    check = verdict.get("rtt_check") or {}
    rpki = summary.get("rpki") or []
    sources = [r for r in report.results if r.provider != "offline"]
    values = {
        "input": report.input,
        "ip": report.ip,
        "version": report.version,
        "address_type": (offline.get("classification") or {}).get("name"),
        "connection_type": connection.get("label"),
        "connection_evidence": connection.get("evidence"),
        "anycast": (verdict.get("anycast") or {}).get("anycast"),
        "country": location.get("country_code"),
        "city": location.get("city"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "location_confidence": (verdict.get("location_confidence") or {}).get("score"),
        "location_spread_km": location.get("spread_km"),
        "asn": network.get("asn"),
        "as_name": network.get("as_name"),
        "prefix": network.get("prefix"),
        "rir": network.get("rir"),
        "rpki": [f"AS{r['origin']}: {r['status']}" for r in rpki],
        "network_name": rdap.get("name"),
        "registered_to": (rdap.get("registrant") or {}).get("name"),
        "abuse_email": [c["email"] for c in summary.get("abuse_contacts") or []],
        "ptr": rdns.get("ptr"),
        "forward_confirmed": rdns.get("forward_confirmed") if rdns.get("ptr") else None,
        "tor_exit": anonymity.get("tor_exit"),
        "icloud_private_relay": anonymity.get("icloud_private_relay"),
        "cloud_or_cdn": anonymity.get("cloud_or_cdn"),
        "listed_vpn_network": anonymity.get("listed_vpn_network"),
        "listed_datacenter": anonymity.get("listed_datacenter_network"),
        "reputation_score": (verdict.get("reputation") or {}).get("score"),
        "reputation_label": (verdict.get("reputation") or {}).get("label"),
        "exposure_score": (verdict.get("exposure") or {}).get("score"),
        "open_ports": internetdb.get("ports"),
        "possible_cves": internetdb.get("vulns"),
        "rtt_ms": check.get("rtt_ms"),
        "speed_of_light_check": (
            ("consistent" if check["plausible"] else "impossible") if check.get("checked") else None
        ),
        "sources_ok": [r.provider for r in sources if r.ok],
        "sources_failed": [r.provider for r in sources if not r.ok and not r.skipped],
        "error": None,
    }
    return {key: _safe(values.get(key)) for key in COLUMNS}


def render(reports: list[IPReport], errors: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for report in reports:
        writer.writerow(row(report))
    for err in errors:
        message = err["error"] + (f" ({err['hint']})" if err.get("hint") else "")
        writer.writerow({"input": _safe(err["input"]), "error": _safe(message)})
    return buffer.getvalue()
