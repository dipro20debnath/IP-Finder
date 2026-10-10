"""Phase 6: the analysis engine - location consensus, anycast, connection type,
location confidence, reputation and exposure scores, and the combined verdict."""

import dataclasses
import json

import pytest

from ipfinder.analysis.anycast import detect_anycast
from ipfinder.analysis.classify import classify_connection
from ipfinder.analysis.geo import haversine_km, location_consensus
from ipfinder.analysis.scoring import (
    confidence_label,
    exposure_score,
    location_confidence,
    reputation_score,
    risk_label,
)
from ipfinder.analysis.verdict import build_verdict
from ipfinder.cli import main
from ipfinder.core.models import ProviderResult
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from tests.conftest import ASN_DB, CITY_DB, analyze_with

DHAKA = (23.8103, 90.4125)
CHATTOGRAM = (22.3569, 91.7832)
LONDON = (51.5074, -0.1278)
PARIS = (48.8566, 2.3522)


def results(**data):
    """{"ip-api": {...}} -> provider results as the orchestrator stores them."""
    return {
        name.replace("_", "-"): ProviderResult(name.replace("_", "-"), "L?", True, value)
        for name, value in data.items()
    }


def loc(cc=None, city=None, lat=None, lon=None, radius=None):
    out = {"country_code": cc, "city": city, "latitude": lat, "longitude": lon}
    if radius is not None:
        out["accuracy_radius_km"] = radius
    return {"location": {k: v for k, v in out.items() if v is not None}}


# ------------------------------------------------------------------ geo


def test_haversine_matches_known_distances():
    assert haversine_km(*DHAKA, *CHATTOGRAM) == pytest.approx(214, abs=1)  # plan's example
    assert haversine_km(*LONDON, *PARIS) == pytest.approx(344, abs=1)
    assert haversine_km(0, 0, 0, 180) == pytest.approx(20015, abs=1)  # half the equator
    assert haversine_km(*LONDON, *LONDON) == 0


def test_consensus_agreeing_sources():
    found = location_consensus(
        results(
            maxmind=loc("GB", "London", 51.5142, -0.0931, radius=10),
            ip_api=loc("gb", "london", *LONDON),
        )
    )
    assert found["country_code"] == "GB" and found["countries_agree"] is True
    assert found["city"] == "London" and found["city_sources"] == ["maxmind", "ip-api"]
    assert found["spread_km"] == pytest.approx(2.6, abs=0.2)
    assert found["uncertainty_km"] == 10  # MaxMind's own radius is larger than the spread
    assert found["latitude"] == pytest.approx(51.5108, abs=0.001)


def test_consensus_weighted_country_vote_and_ties():
    # The operator's geofeed (weight 3) beats two databases (1 + 1).
    found = location_consensus(
        results(geofeed=loc("DE", "Berlin"), maxmind=loc("US", "Ashburn"), ip_api=loc("US"))
    )
    assert found["country_code"] == "DE" and found["countries_agree"] is False
    assert found["country_votes"] == {"DE": ["geofeed"], "US": ["maxmind", "ip-api"]}
    assert found["city"] == "Berlin"  # a US city does not count for DE
    assert "latitude" not in found and found["coordinate_sources"] == []
    tie = location_consensus(results(maxmind=loc("US"), ip_api=loc("GB")))
    assert tie["country_code"] == "US"  # tie -> the source listed first
    assert location_consensus(results(cymru={"network": {}})) is None


# ------------------------------------------------------------------ anycast


@pytest.mark.parametrize(
    "target, service",
    [
        ("8.8.8.8", "Google Public DNS"),
        ("2001:4860:4860::8844", "Google Public DNS"),
        ("1.1.1.1", "Cloudflare DNS (1.1.1.1)"),
        ("9.9.9.9", "Quad9 DNS"),
        ("208.67.222.222", "OpenDNS (Cisco Umbrella)"),
    ],
)
def test_known_anycast_resolvers(target, service):
    found = detect_anycast(target, {})
    assert found["anycast"] is True and found["confidence"] == "high"
    assert found["service"] == service


def test_anycast_from_cloud_ranges():
    def cloud(*matches):
        return results(cloud_ranges={"matches": list(matches)})

    assert detect_anycast("104.16.1.1", cloud({"provider": "Cloudflare"}))["confidence"] == "high"
    ga = cloud({"provider": "Amazon Web Services", "services": ["GLOBALACCELERATOR"]})
    assert detect_anycast("3.3.3.3", ga)["service"] == "AWS Global Accelerator"
    ec2 = cloud({"provider": "Amazon Web Services", "services": ["EC2"]})
    assert detect_anycast("3.80.1.1", ec2) == {"anycast": False, "reasons": []}
    assert detect_anycast("151.101.1.1", cloud({"provider": "Fastly"}))["confidence"] == "medium"
    assert detect_anycast(None, {}) == {"anycast": False, "reasons": []}


# ------------------------------------------------------------------ connection type

NO_ANYCAST = {"anycast": False, "reasons": []}


@pytest.mark.parametrize(
    "data, code, strength",
    [
        (
            {"tor": {"is_exit": True}, "ip_api": {"flags": {"mobile": True}}},
            "anonymizer-tor",
            "list",
        ),
        (
            {"private_relay": {"is_relay": True, "prefix": "172.224.226.0/27"}},
            "privacy-relay",
            "list",
        ),
        (
            {
                "cloud_ranges": {
                    "matches": [{"provider": "Amazon Web Services", "services": ["EC2"]}]
                },
                "ip_api": {"flags": {"proxy": True}},
            },
            "hosting-vpn",
            "list",
        ),
        ({"ip_api": {"flags": {"hosting": True}}}, "hosting", "estimate"),
        ({"vpn_lists": {"vpn": {"listed": True}, "datacenter": {"listed": False}}}, "vpn", "list"),
        ({"ip_api": {"flags": {"mobile": True, "hosting": False}}}, "mobile", "estimate"),
        ({"abuseipdb": {"usage_type": "Mobile ISP"}}, "mobile", "estimate"),
        (
            {"reverse_dns": {"hints": [{"category": "access", "evidence": "pool"}]}},
            "residential",
            "estimate",
        ),
        (
            {"peeringdb": {"network_info": {"types": ["Educational/Research"]}}},
            "education",
            "estimate",
        ),
        ({"abuseipdb": {"usage_type": "Government"}}, "government", "estimate"),
        ({"abuseipdb": {"usage_type": "Commercial"}}, "business", "estimate"),
        ({"peeringdb": {"network_info": {"types": ["Cable/DSL/ISP"]}}}, "isp", "estimate"),
        ({"abuseipdb": {"usage_type": "Data Center/Web Hosting/Transit"}}, "hosting", "estimate"),
        ({}, "unknown", "none"),
    ],
)
def test_connection_decision_tree(data, code, strength):
    found = classify_connection(results(**data), NO_ANYCAST)
    assert (found["code"], found["strength"]) == (code, strength)
    assert bool(found["evidence"]) is (code != "unknown")


def test_conflicting_signals_are_kept():
    data = results(
        ip_api={"flags": {"mobile": True, "hosting": False}},
        abuseipdb={"usage_type": "Data Center/Web Hosting/Transit"},
    )
    found = classify_connection(data, NO_ANYCAST)
    assert found["code"] == "hosting"
    assert found["other_signals"] == ["mobile (ip-api: mobile)"]
    tor = classify_connection(
        results(tor={"is_exit": True}, ip_api={"flags": {"hosting": True}}), NO_ANYCAST
    )
    assert tor["other_signals"] == ["hosting (ip-api: hosting)"]


def test_anycast_label_comes_before_hosting():
    data = results(cloud_ranges={"matches": [{"provider": "Cloudflare"}]})
    found = classify_connection(data, detect_anycast("1.1.1.1", data))
    assert (
        found["code"] == "anycast"
        and found["label"] == "Anycast service (Cloudflare DNS (1.1.1.1))"
    )


# ------------------------------------------------------------------ location confidence


def consensus_for(*points, radius=None, **extra):
    data = {}
    for name, (lat, lon) in zip(("maxmind", "ip_api"), points, strict=False):
        data[name] = loc("BD", None, lat, lon, radius=radius if name == "maxmind" else None)
    data.update(extra)
    return location_consensus(results(**data)), results(**data)


def score(consensus, code="unknown", anycast=None, data=None, **kwargs):
    connection = {"code": code}
    return location_confidence(consensus, connection, anycast or NO_ANYCAST, data or {}, **kwargs)


def test_location_confidence_plan_example():
    # ADVANCED_PLAN.md 5.4: Bangladeshi mobile IP, providers 214 km apart -> 55 (Medium).
    consensus, data = consensus_for(DHAKA, CHATTOGRAM)
    found = score(consensus, "mobile", data=data)
    assert found["score"] == 55 and found["label"] == "medium"
    assert [r["points"] for r in found["breakdown"]] == [-25, -20]


def test_location_confidence_rules():
    near, _ = consensus_for(LONDON, LONDON)
    assert score(near)["score"] == 100
    far, _ = consensus_for(LONDON, (40.7128, -74.0060))  # London vs New York
    assert score(far)["score"] == 60  # -40
    single, _ = consensus_for(LONDON)
    assert score(single)["score"] == 90  # nothing to cross-check
    wide, _ = consensus_for(LONDON, radius=1000)
    assert score(wide)["score"] == 50  # MaxMind's radius 1000 km (-40), single (-10)
    assert score(near, "hosting")["score"] == 70
    assert score(near, "hosting-vpn")["score"] == 20  # -30 and -50
    assert score(near, "anonymizer-tor")["score"] == 50
    assert score(near, "privacy-relay")["score"] == 80
    assert score(near, anycast={"anycast": True})["score"] == 40
    assert score(near, rtt_violation=True)["score"] == 70
    assert score(far, "anonymizer-tor", anycast={"anycast": True})["score"] == 0  # floor


def test_location_confidence_geofeed_bonus_and_disagreement():
    consensus, data = consensus_for(DHAKA, DHAKA, geofeed=loc("BD", "Dhaka"))
    assert score(consensus, data=data)["score"] == 100  # +10, capped at 100
    mobile = score(consensus, "mobile", data=data)
    assert mobile["score"] == 90 and mobile["breakdown"][-1]["points"] == 10
    split = location_consensus(
        results(maxmind=loc("BD", None, *DHAKA), ip_api=loc("IN", None, *DHAKA))
    )
    assert score(split)["score"] == 80  # countries disagree
    countries_only = location_consensus(results(ipinfo_lite=loc("BD")))
    assert score(countries_only)["score"] == 80  # no coordinates


@pytest.mark.parametrize(
    "value, label",
    [(100, "high"), (70, "high"), (69, "medium"), (40, "medium"), (39, "low"), (0, "low")],
)
def test_confidence_labels(value, label):
    assert confidence_label(value) == label


# ------------------------------------------------------------------ reputation


def test_reputation_points():
    assert reputation_score({}) is None
    clean = reputation_score(results(tor={"is_exit": False}, feodo={"listed": False}))
    assert clean["score"] == 0 and clean["label"] == "none found"
    assert "only offline lists were checked" in clean["note"]

    assert reputation_score(results(abuseipdb={"score": 100}))["score"] == 40
    assert reputation_score(results(abuseipdb={"score": 37}))["score"] == 15  # 14.8 rounds to 15
    assert reputation_score(results(greynoise={"classification": "malicious"}))["score"] == 25
    vt3 = reputation_score(results(virustotal={"found": True, "stats": {"malicious": 3}}))
    assert vt3["score"] == 15
    vt10 = reputation_score(results(virustotal={"found": True, "stats": {"malicious": 10}}))
    assert vt10["score"] == 25  # capped
    listed = reputation_score(
        results(threatfox={"found": True}, urlhaus={"found": True}, spamhaus={"abuse_listed": True})
    )
    assert listed["score"] == 20  # listings count once
    assert listed["breakdown"][0]["reason"] == "listed by Spamhaus ZEN, ThreatFox, URLhaus"
    assert "note" not in listed
    assert reputation_score(results(tor={"is_exit": True}))["score"] == 10
    pbl_only = reputation_score(results(spamhaus={"listed": True, "abuse_listed": False}))
    assert pbl_only["score"] == 0  # PBL is policy, not abuse


def test_reputation_riot_and_caps():
    riot = reputation_score(results(greynoise={"riot": True, "classification": "benign"}))
    assert riot["score"] == 0 and riot["breakdown"][0]["points"] == -30  # never below 0
    everything = reputation_score(
        results(
            abuseipdb={"score": 100},
            greynoise={"classification": "malicious"},
            virustotal={"found": True, "stats": {"malicious": 9}},
            feodo={"listed": True},
            tor={"is_exit": True},
        )
    )
    assert everything["score"] == 100 and everything["label"] == "high"  # 40+25+25+20+10
    assert everything["sources"] == ["abuseipdb", "greynoise", "virustotal", "feodo", "tor"]


@pytest.mark.parametrize(
    "value, label",
    [(0, "none found"), (1, "low"), (29, "low"), (30, "medium"), (59, "medium"), (60, "high")],
)
def test_risk_labels(value, label):
    assert risk_label(value) == label


# ------------------------------------------------------------------ exposure


def test_exposure_points_and_caps():
    assert exposure_score({}) is None
    nothing = exposure_score(results(internetdb={"found": False}))
    assert nothing["score"] == 0 and nothing["label"] == "none found"
    typical = exposure_score(
        results(
            internetdb={
                "found": True,
                "ports": [23, 80, 443, 3389],
                "risky_ports": [
                    {"port": 23, "service": "Telnet"},
                    {"port": 3389, "service": "RDP"},
                ],
                "vulns": ["CVE-2020-15778", "CVE-2023-38408"],
            }
        )
    )
    assert typical["score"] == 48 and typical["label"] == "medium"  # 8 + 30 + 10
    assert [r["points"] for r in typical["breakdown"]] == [8, 30, 10]
    worst = exposure_score(
        results(
            internetdb={
                "found": True,
                "ports": list(range(1, 30)),
                "risky_ports": [{"port": p, "service": "x"} for p in (21, 23, 445, 3389)],
                "vulns": [f"CVE-2024-{i}" for i in range(10)],
            }
        )
    )
    assert worst["score"] == 100  # 20 + 45 + 35
    web_only = exposure_score(results(internetdb={"found": True, "ports": [80, 443]}))
    assert web_only["score"] == 4 and web_only["label"] == "low"


# ------------------------------------------------------------------ verdict


def test_verdict_for_private_address(config):
    report = analyze_with("192.168.1.10", config, [OfflineProvider()])
    connection = report.verdict["connection"]
    assert connection["code"] == "not-public"
    assert connection["label"] == "Private-Use: not reachable from the internet"
    assert set(report.verdict) == {"connection"}


def test_verdict_with_maxmind_test_database(config):
    mm = dataclasses.replace(config, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB)
    report = analyze_with("81.2.69.142", mm, [OfflineProvider(), MaxMindProvider()])
    verdict = report.verdict
    assert verdict["location"]["city"] == "London" and verdict["location"]["uncertainty_km"] == 10
    assert verdict["location_confidence"]["score"] == 90  # one source only
    assert verdict["connection"]["code"] == "unknown"
    assert "reputation" not in verdict and "exposure" not in verdict


def test_build_verdict_without_offline_result():
    assert build_verdict({}) == {}


def test_cli_shows_verdict_and_json_carries_it(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["lookup", "--no-color", "--no-cache", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    assert "Verdict" in out
    assert "Anycast service (Google Public DNS)  (from published lists)" in out
    assert main(["lookup", "-f", "json", "--no-cache", "8.8.8.8"]) == 0
    verdict = json.loads(capsys.readouterr().out)["reports"][0]["verdict"]
    assert verdict["connection"]["code"] == "anycast"
    assert verdict["anycast"]["service"] == "Google Public DNS"
