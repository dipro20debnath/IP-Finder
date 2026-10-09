"""Layer 1: everything that can be learned about an address without any network access."""

from __future__ import annotations

from ipfinder.analysis import addressing, ipv6_insights
from ipfinder.core.special_ranges import classify, matching_ranges
from ipfinder.core.validator import ParsedInput

# Embedded-IPv4 kinds whose IPv4 address, not the IPv6 wrapper, is what
# geolocation/registry databases know about.
_LOOKUP_VIA_EMBEDDED = ("ipv4_mapped", "nat64", "6to4", "teredo_client")


def decide_lookup(
    cls_reachable: bool | None, cls_name: str, cls_rfc: str, ip_text: str, embedded: list[dict]
) -> dict:
    """Should online layers run, and for which address?"""
    for kind in _LOOKUP_VIA_EMBEDDED:
        for entry in embedded:
            if entry["kind"] == kind and entry["globally_reachable"] is True:
                return {
                    "eligible": True,
                    "target": entry["address"],
                    "reason": f"Using the IPv4 address embedded in this {cls_name} address "
                    f"({kind}, {entry['rfc']})",
                }
    if cls_reachable is True:
        return {"eligible": True, "target": ip_text, "reason": "Globally reachable address"}
    candidates = [e for e in embedded if e["kind"] in _LOOKUP_VIA_EMBEDDED]
    if candidates:
        detail = ", ".join(f"{e['kind']} {e['address']} is {e['category']}" for e in candidates)
        return {
            "eligible": False,
            "target": None,
            "reason": f"{cls_name} ({cls_rfc}) address whose embedded IPv4 is not public "
            f"({detail})",
        }
    return {
        "eligible": False,
        "target": None,
        "reason": f"{cls_name} ({cls_rfc}) is not globally reachable, so public geolocation "
        "and registry data do not apply",
    }


def analyze(parsed: ParsedInput, oui_lookup=None) -> dict:
    ip = parsed.address
    cls = classify(ip)
    ip_text = addressing.compressed(ip)

    data: dict = {
        "ip": ip_text,
        "version": ip.version,
        "input_format": parsed.input_format,
        "port": parsed.port,
        "scope_id": parsed.scope_id,
        "classification": cls.to_dict(),
        "all_matching_ranges": [r.to_dict() for r in matching_ranges(ip)],
        "representations": addressing.representations(ip),
    }

    embedded: list[dict] = []
    if ip.version == 4:
        data["ipv4"] = {
            "historic_class": addressing.ipv4_class(ip),
            "multicast": addressing.ipv4_multicast(ip),
        }
    else:
        v6 = ipv6_insights.insights(ip, oui_lookup)
        embedded = v6["embedded_ipv4"]
        data["ipv6"] = v6

    data["lookup"] = decide_lookup(cls.globally_reachable, cls.name, cls.rfc, ip_text, embedded)

    flags = addressing.python_flags(ip)
    if isinstance(cls.globally_reachable, bool):
        flags["agrees_with_iana_table"] = flags["is_global"] == cls.globally_reachable
    data["python_ipaddress"] = flags
    return data
