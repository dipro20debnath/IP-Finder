"""Three separate 0-100 scores, each with the rules that produced it.

They answer different questions and are never added together:
  location confidence  how much to trust the location (ADVANCED_PLAN.md 5.4)
  reputation           has the address been reported or detected doing harm? (5.5)
  exposure             does it expose services to the internet? (5.5)
All three are transparent heuristics, not probabilities: every point is listed in
the breakdown, and a score built from few sources says so.
"""

from __future__ import annotations


def _ok(results: dict, name: str) -> dict:
    result = results.get(name)
    return result.data if result is not None and result.ok else {}


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def _finish(breakdown: list[tuple[str, int]], start: int, label) -> dict:
    score = _clamp(start + sum(points for _, points in breakdown))
    return {
        "score": score,
        "label": label(score),
        "breakdown": [{"reason": reason, "points": points} for reason, points in breakdown],
    }


def confidence_label(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 40 else "low"


def risk_label(score: int) -> str:
    if score == 0:
        return "none found"
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


# ------------------------------------------------------------------ location


def location_confidence(
    consensus: dict, connection: dict, anycast: dict, results: dict, rtt_violation: bool = False
) -> dict:
    """Start at 100 and subtract for every reason the location may be wrong."""
    rules: list[tuple[str, int]] = []
    uncertainty = consensus.get("uncertainty_km")
    sources = consensus.get("coordinate_sources", [])
    if uncertainty is not None and uncertainty > 500:
        rules.append((f"sources up to {uncertainty:g} km apart (or that uncertain)", -40))
    elif uncertainty is not None and uncertainty > 100:
        rules.append((f"sources up to {uncertainty:g} km apart (or that uncertain)", -25))
    if not sources:
        rules.append(("no source gave coordinates", -20))
    elif len(sources) == 1:
        rules.append(("only one source gave coordinates, nothing to cross-check", -10))
    if not consensus.get("countries_agree", True):
        rules.append(("sources disagree on the country", -20))

    code = connection.get("code")
    if code in ("hosting", "hosting-vpn"):
        rules.append(("hosting / data centre: the server's location, not a user's", -30))
    if code in ("anonymizer-tor", "vpn", "hosting-vpn"):
        rules.append(("anonymizer: the real user can be anywhere", -50))
    if code == "privacy-relay":
        rules.append(("shared Apple relay: only the user's rough region is kept", -20))
    if code == "mobile":
        rules.append(("mobile network: the operator's gateway, often far from the user", -20))
    if anycast.get("anycast"):
        rules.append(("anycast: served from many locations at once", -60))
    if rtt_violation:
        rules.append(("measured round-trip time is impossible for this location", -30))

    geofeed = (_ok(results, "geofeed").get("location") or {}).get("country_code")
    if geofeed and geofeed.upper() == consensus.get("country_code"):
        rules.append(("the network operator's own geofeed agrees", 10))
    return _finish(rules, 100, confidence_label)


# ------------------------------------------------------------------ reputation

LISTINGS = (
    ("spamhaus", "abuse_listed", "Spamhaus ZEN"),
    ("threatfox", "found", "ThreatFox"),
    ("urlhaus", "found", "URLhaus"),
    ("feodo", "listed", "Feodo Tracker"),
    ("spamhaus-drop", "listed", "Spamhaus DROP"),
)
ONLINE_SOURCES = ("abuseipdb", "greynoise", "virustotal", "threatfox", "urlhaus", "spamhaus")


def reputation_score(results: dict) -> dict | None:
    """None when no reputation source ran at all."""
    rules: list[tuple[str, int]] = []
    checked: list[str] = []

    abuse = _ok(results, "abuseipdb")
    if abuse:
        checked.append("abuseipdb")
        confidence = abuse.get("score") or 0
        points = round(min(40, confidence * 0.4))
        if points:
            rules.append((f"AbuseIPDB confidence {confidence}/100 (x0.4)", points))

    grey = _ok(results, "greynoise")
    if grey:
        checked.append("greynoise")
        if grey.get("classification") == "malicious":
            rules.append(("GreyNoise classifies it as malicious", 25))
        if grey.get("riot"):
            rules.append(("GreyNoise: a known benign business service (RIOT)", -30))

    vt = _ok(results, "virustotal")
    if vt.get("found"):
        checked.append("virustotal")
        malicious = (vt.get("stats") or {}).get("malicious", 0)
        if malicious:
            rules.append(
                (
                    f"VirusTotal: {malicious} engine(s) say malicious (5 each)",
                    min(25, 5 * malicious),
                )
            )

    listed = []
    for name, field, label in LISTINGS:
        data = _ok(results, name)
        if data:
            checked.append(name)
            if data.get(field):
                listed.append(label)
    if listed:
        rules.append((f"listed by {', '.join(listed)}", 20))

    tor = _ok(results, "tor")
    if tor:
        checked.append("tor")
        if tor.get("is_exit"):
            rules.append(("Tor exit relay (a risk signal, not wrongdoing)", 10))

    if not checked:
        return None
    result = _finish(rules, 0, risk_label)
    result["sources"] = checked
    if not any(name in checked for name in ONLINE_SOURCES):
        result["note"] = (
            "only offline lists were checked; --profile full adds AbuseIPDB, GreyNoise, "
            "VirusTotal, ThreatFox, URLhaus and Spamhaus"
        )
    return result


# ------------------------------------------------------------------ exposure


def exposure_score(results: dict) -> dict | None:
    """From Shodan InternetDB's last scan; None when it did not run."""
    data = _ok(results, "internetdb")
    if not data:
        return None
    rules: list[tuple[str, int]] = []
    if data.get("found"):
        ports = data.get("ports") or []
        risky = data.get("risky_ports") or []
        vulns = data.get("vulns") or []
        if ports:
            rules.append((f"{len(ports)} open port(s) (2 each)", min(20, 2 * len(ports))))
        if risky:
            names = ", ".join(f"{r['port']} {r['service']}" for r in risky)
            rules.append(
                (f"often-attacked services exposed: {names} (15 each)", min(45, 15 * len(risky)))
            )
        if vulns:
            rules.append((f"{len(vulns)} possible CVE(s) (5 each)", min(35, 5 * len(vulns))))
    result = _finish(rules, 0, risk_label)
    result["sources"] = ["internetdb"]
    return result
