"""The analysis engine (L11): turn every provider's answer into one verdict.

  connection           what kind of address this is, with evidence (classify.py)
  anycast              served from many places at once? (anycast.py)
  location             consensus country / city / point and spread (geo.py)
  location_confidence  0-100, with the rules applied (scoring.py)
  reputation           0-100 from the threat sources that ran (scoring.py)
  exposure             0-100 from Shodan InternetDB (scoring.py)
Addresses that are not globally reachable get only a connection label: no online
source applies to them.
"""

from __future__ import annotations

from ipfinder.analysis.anycast import detect_anycast
from ipfinder.analysis.classify import classify_connection
from ipfinder.analysis.geo import location_consensus
from ipfinder.analysis.scoring import exposure_score, location_confidence, reputation_score


def build_verdict(results: dict) -> dict:
    offline = results.get("offline")
    if offline is None or not offline.ok:
        return {}
    lookup = offline.data["lookup"]
    if not lookup["eligible"]:
        cls = offline.data["classification"]
        return {
            "connection": {
                "code": "not-public",
                "label": f"{cls['name']}: not reachable from the internet",
                "evidence": [f"offline: {lookup['reason']}"],
                "strength": "list",
            }
        }

    anycast = detect_anycast(lookup["target"], results)
    connection = classify_connection(results, anycast)
    verdict: dict = {"connection": connection, "anycast": anycast}
    consensus = location_consensus(results)
    if consensus is not None:
        verdict["location"] = consensus
        verdict["location_confidence"] = location_confidence(
            consensus, connection, anycast, results
        )
    reputation = reputation_score(results)
    if reputation is not None:
        verdict["reputation"] = reputation
    exposure = exposure_score(results)
    if exposure is not None:
        verdict["exposure"] = exposure
    return verdict
