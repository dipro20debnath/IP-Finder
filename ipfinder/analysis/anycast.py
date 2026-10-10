"""Anycast: one address announced from many places at once, so "where is it?"
has no single answer.

Evidence used, strongest first:
* the address is a well-known anycast public DNS resolver (operators document this);
* it is in Cloudflare's published ranges (Cloudflare announces every address from
  every data centre) or an AWS Global Accelerator range (AWS: "static anycast IP
  addresses");
* it is in Fastly's ranges (Fastly's edge network uses anycast; "likely").
The speed-of-light check against measured round-trip times comes with --active
(Phase 7).
"""

from __future__ import annotations

from ipfinder.lists.index import PrefixIndex

KNOWN_ANYCAST = (
    ("8.8.8.0/24", "Google Public DNS"),
    ("8.8.4.0/24", "Google Public DNS"),
    ("2001:4860:4860::/48", "Google Public DNS"),
    ("1.1.1.0/24", "Cloudflare DNS (1.1.1.1)"),
    ("1.0.0.0/24", "Cloudflare DNS (1.1.1.1)"),
    ("2606:4700:4700::/48", "Cloudflare DNS (1.1.1.1)"),
    ("9.9.9.0/24", "Quad9 DNS"),
    ("149.112.112.0/24", "Quad9 DNS"),
    ("2620:fe::/48", "Quad9 DNS"),
    ("208.67.222.0/24", "OpenDNS (Cisco Umbrella)"),
    ("208.67.220.0/24", "OpenDNS (Cisco Umbrella)"),
    ("2620:119:35::/48", "OpenDNS (Cisco Umbrella)"),
    ("2620:119:53::/48", "OpenDNS (Cisco Umbrella)"),
)

_INDEX = PrefixIndex()
_INDEX.add_many(KNOWN_ANYCAST)


def _ok(results: dict, name: str) -> dict:
    result = results.get(name)
    return result.data if result is not None and result.ok else {}


def detect_anycast(target: str | None, results: dict) -> dict:
    """{"anycast": bool, "confidence": "high"|"medium", "service": str, "reasons": [...]}"""
    if not target:
        return {"anycast": False, "reasons": []}
    reasons: list[str] = []
    confidence = None
    service = None

    hit = _INDEX.longest(target)
    if hit:
        service = hit[1][0]
        reasons.append(f"{hit[0]} is {service}, a documented anycast service")
        confidence = "high"

    for match in _ok(results, "cloud-ranges").get("matches", []):
        provider = match.get("provider")
        if provider == "Cloudflare":
            reasons.append("in Cloudflare's ranges, which are announced from every location")
            confidence = "high"
            service = service or "Cloudflare network"
        elif provider == "Amazon Web Services" and "GLOBALACCELERATOR" in match.get("services", []):
            reasons.append("an AWS Global Accelerator address (static anycast IP)")
            confidence = "high"
            service = service or "AWS Global Accelerator"
        elif provider == "Fastly":
            reasons.append("in Fastly's edge ranges (anycast network)")
            confidence = confidence or "medium"
            service = service or "Fastly network"

    result: dict = {"anycast": bool(reasons), "reasons": reasons}
    if reasons:
        result["confidence"] = confidence
        result["service"] = service
    return result
