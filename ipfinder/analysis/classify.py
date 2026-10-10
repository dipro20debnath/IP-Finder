"""Connection type: one label for "what kind of address is this?", with the evidence.

Decision tree (ADVANCED_PLAN.md section 5.3), first match wins:
  Tor exit list                              -> Anonymizer: Tor exit relay
  iCloud Private Relay list                  -> Privacy relay (Apple), not a VPN
  anycast                                    -> Anycast service
  hosting/cloud signal + VPN/proxy signal    -> Likely VPN or proxy on hosting
  hosting/cloud signal                       -> Hosting / cloud
  VPN/proxy signal (no hosting)              -> Possible VPN or proxy
  mobile signal                              -> Mobile network (cellular, often CGNAT)
  access-line hostname                       -> Residential broadband
  education signal                           -> Education / research
  government signal                          -> Government / military
  business signal                            -> Business
  ISP signal (network-level only)            -> ISP access network (home or business)
  otherwise                                  -> Unknown
Lists (Tor, Apple, cloud ranges) are facts about the address; flags from ip-api,
AbuseIPDB usage types, PeeringDB network types and hostnames are estimates, so
each label says how strong its evidence is.
"""

from __future__ import annotations


def _ok(results: dict, name: str) -> dict:
    result = results.get(name)
    return result.data if result is not None and result.ok else {}


def _signals(results: dict) -> dict[str, list[str]]:
    """Every signal, as human-readable evidence strings tagged with their source."""
    s: dict[str, list[str]] = {
        k: []
        for k in (
            "hosting",
            "vpn",
            "mobile",
            "residential",
            "education",
            "government",
            "business",
            "isp",
        )
    }
    for match in _ok(results, "cloud-ranges").get("matches", []):
        where = " ".join(v for v in (match.get("region"), ",".join(match.get("services", []))) if v)
        s["hosting"].append(f"cloud-ranges: {match['provider']}{f' {where}' if where else ''}")

    flags = _ok(results, "ip-api").get("flags") or {}
    if flags.get("hosting"):
        s["hosting"].append("ip-api: hosting")
    if flags.get("proxy"):
        s["vpn"].append("ip-api: proxy/VPN")
    if flags.get("mobile"):
        s["mobile"].append("ip-api: mobile")

    vpn = _ok(results, "vpn-lists")
    if (vpn.get("vpn") or {}).get("listed"):
        s["vpn"].append("vpn-lists: listed as a VPN network")
    if (vpn.get("datacenter") or {}).get("listed"):
        s["hosting"].append("vpn-lists: listed as a datacenter network")

    usage = (_ok(results, "abuseipdb").get("usage_type") or "").lower()
    if usage:
        tag = f"abuseipdb: {_ok(results, 'abuseipdb')['usage_type']}"
        if "data center" in usage or "hosting" in usage or "content delivery" in usage:
            s["hosting"].append(tag)
        elif "mobile" in usage:
            s["mobile"].append(tag)
        elif "fixed line" in usage:
            s["isp"].append(tag)
        elif "university" in usage or "school" in usage or "library" in usage:
            s["education"].append(tag)
        elif "government" in usage or "military" in usage:
            s["government"].append(tag)
        elif "commercial" in usage or "organization" in usage:
            s["business"].append(tag)

    types = [
        t.lower() for t in (_ok(results, "peeringdb").get("network_info") or {}).get("types", [])
    ]
    for kind in types:
        tag = f"peeringdb: {kind}"
        if kind == "educational/research":
            s["education"].append(tag)
        elif kind == "government":
            s["government"].append(tag)
        elif kind == "enterprise":
            s["business"].append(tag)
        elif kind == "cable/dsl/isp":
            s["isp"].append(tag)
        elif kind == "content":
            s["hosting"].append(tag)

    rdns = _ok(results, "reverse-dns")
    for hint in rdns.get("hints", []):
        tag = f"reverse-dns: {hint['evidence']}"
        category = hint.get("category")
        if category in ("cloud", "hosting", "cdn", "server"):
            s["hosting"].append(tag)
        elif category == "mobile":
            s["mobile"].append(tag)
        elif category == "access":
            s["residential"].append(tag)
        elif category == "static":
            s["business"].append(tag)
        elif category == "anonymity":
            s["vpn"].append(tag)
    return s


def classify_connection(results: dict, anycast: dict) -> dict:
    """The label, its evidence, and every other signal that pointed elsewhere
    (sources often disagree, e.g. "mobile" from one and "data centre" from another)."""
    signals = _signals(results)
    found = _decide(results, anycast, signals)
    used = set(found["evidence"])
    other = [
        f"{group} ({item})"
        for group, items in signals.items()
        for item in items
        if item not in used
    ]
    if other:
        found["other_signals"] = other[:6]
    return found


def _decide(results: dict, anycast: dict, s: dict[str, list[str]]) -> dict:
    tor = _ok(results, "tor")
    if tor.get("is_exit"):
        return _label(
            "anonymizer-tor",
            "Anonymizer: Tor exit relay",
            "list",
            ["tor: listed by the Tor Project"],
        )
    relay = _ok(results, "private-relay")
    if relay.get("is_relay"):
        return _label(
            "privacy-relay",
            "Privacy relay: iCloud Private Relay (not a VPN)",
            "list",
            [f"private-relay: Apple egress range {relay.get('prefix')}"],
        )
    if anycast.get("anycast"):
        name = anycast.get("service")
        return _label(
            "anycast",
            f"Anycast service{f' ({name})' if name else ''}",
            "list" if anycast.get("confidence") == "high" else "estimate",
            list(anycast.get("reasons", [])),
        )

    from_list = any(e.startswith(("cloud-ranges", "vpn-lists")) for e in s["hosting"] + s["vpn"])
    strength = "list" if from_list else "estimate"
    if s["hosting"] and s["vpn"]:
        return _label(
            "hosting-vpn",
            "Likely VPN or proxy on a hosting network",
            strength,
            s["vpn"] + s["hosting"],
        )
    if s["hosting"]:
        cloud = _ok(results, "cloud-ranges").get("matches", [])
        name = f": {cloud[0]['provider']}" if cloud else ""
        return _label("hosting", f"Hosting / cloud{name}", strength, s["hosting"])
    if s["vpn"]:
        return _label("vpn", "Possible VPN or proxy", strength, s["vpn"])
    if s["mobile"]:
        return _label(
            "mobile", "Mobile network (cellular, often shared via CGNAT)", "estimate", s["mobile"]
        )
    if s["residential"]:
        return _label(
            "residential", "Residential broadband", "estimate", s["residential"] + s["isp"]
        )
    for key, text in (
        ("education", "Education / research"),
        ("government", "Government / military"),
        ("business", "Business"),
        ("isp", "ISP access network (home or business)"),
    ):
        if s[key]:
            return _label(key, text, "estimate", s[key])
    return _label("unknown", "Unknown", "none", [])


def _label(code: str, label: str, strength: str, evidence: list[str]) -> dict:
    return {"code": code, "label": label, "evidence": evidence, "strength": strength}
