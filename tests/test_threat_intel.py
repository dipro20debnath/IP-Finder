"""Phase 5: threat intelligence (AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox,
URLhaus, Spamhaus ZEN) and the offline Feodo Tracker / Spamhaus DROP lists.

Samples follow each service's documented layout: AbuseIPDB's own check example,
GreyNoise's README example, abuse.ch field names from Elastic's integration,
Spamhaus return codes from Spamhaus's SpamAssassin rules.
"""

import dataclasses
import json
from urllib.parse import parse_qs

import httpx
import pytest

from ipfinder.cli import main
from ipfinder.core.dns import DNSLookupError
from ipfinder.core.session import Session
from ipfinder.lists.specs import SPECS
from ipfinder.lists.store import ListStore
from ipfinder.providers import default_providers
from ipfinder.providers.abusech import ThreatFoxProvider, URLhausProvider, defang, ioc_host
from ipfinder.providers.abuseipdb import AbuseIPDBProvider
from ipfinder.providers.base import Provider
from ipfinder.providers.greynoise import GreyNoiseProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.otx import OTXProvider
from ipfinder.providers.spamhaus import SpamhausProvider
from ipfinder.providers.threat_lists import FeodoProvider, SpamhausDropProvider
from ipfinder.providers.virustotal import VirusTotalProvider
from tests.conftest import analyze_with, run

KEYS = {
    "ABUSEIPDB_API_KEY": "abuse-key",
    "GREYNOISE_API_KEY": "grey-key",
    "VIRUSTOTAL_API_KEY": "vt-key",
    "OTX_API_KEY": "otx-key",
    "ABUSECH_AUTH_KEY": "abusech-key",
}


def only(*providers):
    return [OfflineProvider(), *providers]


@pytest.fixture
def full(config):
    return dataclasses.replace(config, profile="full", api_keys=dict(KEYS))


# The example from AbuseIPDB's API documentation (check endpoint, verbose).
ABUSEIPDB_EXAMPLE = {
    "data": {
        "ipAddress": "118.25.6.39",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "domain": "tencent.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 2,
        "numDistinctUsers": 2,
        "lastReportedAt": "2018-12-20T20:55:14+00:00",
        "reports": [
            {
                "reportedAt": "2018-12-20T20:55:14+00:00",
                "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle",
                "categories": [18, 22],
                "reporterId": 1,
                "reporterCountryCode": "US",
            },
            {"reportedAt": "2018-12-19T10:00:00+00:00", "categories": [18, 99]},
        ],
    }
}

GREYNOISE_8888 = {
    "ip": "8.8.8.8",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Google Public DNS",
    "link": "https://viz.greynoise.io/riot/8.8.8.8",
    "last_seen": "2021-03-26",
    "message": "Success",
}

VT_EXAMPLE = {
    "data": {
        "id": "1.2.3.4",
        "type": "ip_address",
        "attributes": {
            "as_owner": "Example AS",
            "last_analysis_date": 1791500000,
            "last_analysis_stats": {
                "harmless": 60,
                "malicious": 3,
                "suspicious": 1,
                "undetected": 30,
                "timeout": 0,
            },
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "malware"},
                "engineB": {"category": "suspicious", "result": "suspicious"},
                "EngineC": {"category": "malicious", "result": "phishing"},
                "EngineD": {"category": "harmless", "result": "clean"},
            },
            "reputation": -12,
            "total_votes": {"harmless": 1, "malicious": 4},
            "tags": [],
        },
    }
}

OTX_EXAMPLE = {
    "indicator": "1.2.3.4",
    "reputation": 0,
    "validation": [],
    "pulse_info": {
        "count": 2,
        "pulses": [
            {
                "name": "Older pulse",
                "created": "2026-01-01T00:00:00",
                "modified": "2026-01-02T00:00:00",
                "tags": ["scanner"],
                "malware_families": [],
            },
            {
                "name": "QakBot C2 servers",
                "created": "2026-09-01T00:00:00",
                "modified": "2026-09-30T00:00:00",
                "tags": ["qakbot", "c2"],
                "malware_families": [{"id": "x", "display_name": "QakBot"}],
                "adversary": "",
            },
        ],
    },
}

THREATFOX_EXAMPLE = {
    "query_status": "ok",
    "data": [
        {
            "id": "841537",
            "ioc": "1.2.3.4:443",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
            "ioc_type": "ip:port",
            "malware": "win.qakbot",
            "malware_printable": "QakBot",
            "confidence_level": 100,
            "first_seen": "2026-09-01 10:00:00 UTC",
            "last_seen": None,
            "tags": ["qakbot"],
        },
        {"id": "2", "ioc": "1.2.3.45:80", "malware_printable": "Other"},
    ],
}

URLHAUS_EXAMPLE = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/1.2.3.4/",
    "host": "1.2.3.4",
    "firstseen": "2026-09-01 10:00:00 UTC",
    "url_count": "3",
    "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
    "urls": [
        {
            "url": "http://1.2.3.4/bins/mozi.m",
            "url_status": "online",
            "date_added": "2026-09-01 10:00:00 UTC",
            "threat": "malware_download",
            "tags": ["Mozi"],
        },
        {"url": "https://1.2.3.4/x.sh", "url_status": "offline", "tags": None},
    ],
}


# ------------------------------------------------------------------ profile and keys


def test_threat_sources_need_full_profile_and_keys(config):
    providers = only(AbuseIPDBProvider(), GreyNoiseProvider(), SpamhausProvider())
    report = analyze_with("1.2.3.4", config, providers)
    assert report.result("abuseipdb").skipped == (
        "not part of the 'standard' profile (use --profile full)"
    )
    full_no_keys = dataclasses.replace(config, profile="full")
    report = analyze_with("1.2.3.4", full_no_keys, only(AbuseIPDBProvider()))
    assert report.result("abuseipdb").skipped == "no API key (ABUSEIPDB_API_KEY in .env)"


def test_full_profile_without_any_key_never_crashes(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["lookup", "--profile", "full", "--no-cache", "-f", "json", "1.2.3.4"]) == 0
    results = {
        r["provider"]: r for r in json.loads(capsys.readouterr().out)["reports"][0]["results"]
    }
    for name, key in (
        ("abuseipdb", "ABUSEIPDB_API_KEY"),
        ("virustotal", "VIRUSTOTAL_API_KEY"),
        ("otx", "OTX_API_KEY"),
        ("threatfox", "ABUSECH_AUTH_KEY"),
        ("urlhaus", "ABUSECH_AUTH_KEY"),
    ):
        assert results[name]["skipped"] == f"no API key ({key} in .env)"
    # Key-optional sources run (and fail cleanly here, as the network is off).
    assert results["greynoise"]["ok"] is False and "cannot reach" in results["greynoise"]["error"]
    assert "does not reach Spamhaus" in results["spamhaus"]["error"]


def test_every_phase5_provider_is_registered():
    names = {p.name for p in default_providers()}
    expected = {"abuseipdb", "greynoise", "virustotal", "otx", "threatfox", "urlhaus", "spamhaus"}
    assert expected | {"feodo", "spamhaus-drop"} <= names


# ------------------------------------------------------------------ AbuseIPDB


def test_abuseipdb(full, fake_api):
    fake_api.json(
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        ABUSEIPDB_EXAMPLE,
        headers={"X-RateLimit-Remaining": "999"},
    )
    report = analyze_with("118.25.6.39", full, only(AbuseIPDBProvider()))
    data = report.result("abuseipdb").data
    assert data["score"] == 100 and data["total_reports"] == 2
    assert data["categories"] == [
        {"id": 18, "name": "Brute-Force", "reports": 2},
        {"id": 22, "name": "SSH", "reports": 1},
        {"id": 99, "name": "category 99", "reports": 1},
    ]
    assert data["quota_remaining"] == 999
    assert "comment" not in json.dumps(data)  # user-written text is not kept
    request = fake_api.requests[0]
    assert request.headers["key"] == "abuse-key"
    assert request.url.params["maxAgeInDays"] == "90" and "verbose" in request.url.params
    assert report.summary["threat"]["abuseipdb_score"] == 100


def test_abuseipdb_rate_limited(full, fake_api):
    fake_api.add(
        "GET",
        "https://api.abuseipdb.com/",
        httpx.Response(429, headers={"Retry-After": "3600"}, json={"errors": []}),
    )
    result = analyze_with("118.25.6.39", full, only(AbuseIPDBProvider())).result("abuseipdb")
    assert result.error == "rate limited by api.abuseipdb.com (HTTP 429); retry in 3600s"
    assert "abuse-key" not in result.error


# ------------------------------------------------------------------ GreyNoise


def test_greynoise_riot_and_key_header(full, config, fake_api):
    fake_api.json("GET", "https://api.greynoise.io/v3/community/8.8.8.8", GREYNOISE_8888)
    data = analyze_with("8.8.8.8", full, only(GreyNoiseProvider())).result("greynoise").data
    assert data["riot"] is True and data["name"] == "Google Public DNS"
    assert fake_api.requests[-1].headers["key"] == "grey-key"
    no_key = dataclasses.replace(config, profile="full")
    analyze_with("8.8.8.8", no_key, only(GreyNoiseProvider()))
    assert "key" not in fake_api.requests[-1].headers


def test_greynoise_not_observed_and_ipv6(full, fake_api):
    fake_api.add(
        "GET",
        "https://api.greynoise.io/v3/community/1.2.3.4",
        httpx.Response(
            404,
            json={
                "ip": "1.2.3.4",
                "noise": False,
                "riot": False,
                "message": "IP not observed scanning the internet or contained in RIOT data set.",
            },
        ),
    )
    data = analyze_with("1.2.3.4", full, only(GreyNoiseProvider())).result("greynoise").data
    assert data["observed"] is False and data["noise"] is False
    v6 = analyze_with("2001:4860:4860::8888", full, only(GreyNoiseProvider()))
    assert v6.result("greynoise").skipped == "GreyNoise covers IPv4 only"


# ------------------------------------------------------------------ VirusTotal


def test_virustotal(full, fake_api):
    fake_api.json("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", VT_EXAMPLE)
    report = analyze_with("1.2.3.4", full, only(VirusTotalProvider()))
    data = report.result("virustotal").data
    assert data["stats"]["malicious"] == 3 and data["engines"] == 94
    assert [f["engine"] for f in data["flagged"]] == ["EngineA", "EngineC", "engineB"]
    assert data["last_analysis"] == "2026-10-08"
    assert data["link"] == "https://www.virustotal.com/gui/ip-address/1.2.3.4"
    assert fake_api.requests[0].headers["x-apikey"] == "vt-key"
    assert report.summary["threat"]["virustotal_malicious"] == 3


def test_virustotal_rate_limit_and_not_found(full, fake_api):
    assert VirusTotalProvider.rate_limit == (4, 60.0)
    fake_api.add("GET", "https://www.virustotal.com/", httpx.Response(404, json={"error": {}}))
    data = analyze_with("1.2.3.4", full, only(VirusTotalProvider())).result("virustotal").data
    assert data == {"found": False, "note": "VirusTotal has no record of this address"}


# ------------------------------------------------------------------ OTX


def test_otx(full, fake_api):
    fake_api.json(
        "GET", "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general", OTX_EXAMPLE
    )
    data = analyze_with("1.2.3.4", full, only(OTXProvider())).result("otx").data
    assert data["pulse_count"] == 2
    assert data["pulses"][0]["name"] == "QakBot C2 servers"  # newest first
    assert data["pulses"][0]["malware_families"] == ["QakBot"]
    assert fake_api.requests[0].headers["x-otx-api-key"] == "otx-key"

    fake_api.json(
        "GET",
        "https://otx.alienvault.com/api/v1/indicators/IPv6/2001:4860:4860::8888/general",
        {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [{"source": "x", "message": "Known DNS resolver"}],
        },
    )
    data = analyze_with("2001:4860:4860::8888", full, only(OTXProvider())).result("otx").data
    assert data["validation"] == ["Known DNS resolver"]


# ------------------------------------------------------------------ abuse.ch


def test_threatfox(full, fake_api):
    fake_api.json("POST", "https://threatfox-api.abuse.ch/api/v1/", THREATFOX_EXAMPLE)
    report = analyze_with("1.2.3.4", full, only(ThreatFoxProvider()))
    data = report.result("threatfox").data
    assert data["found"] is True and data["total"] == 1  # 1.2.3.45:80 is another address
    assert data["iocs"][0]["malware"] == "QakBot" and data["iocs"][0]["confidence"] == 100
    assert data["iocs"][0]["link"] == "https://threatfox.abuse.ch/ioc/841537/"
    request = fake_api.requests[0]
    assert json.loads(request.content) == {"query": "search_ioc", "search_term": "1.2.3.4"}
    assert request.headers["auth-key"] == "abusech-key"
    assert report.summary["threat"]["threatfox_iocs"] == 1


def test_threatfox_no_result_bad_key_and_odd_status(full, fake_api):
    fake_api.json(
        "POST",
        "https://threatfox-api.abuse.ch/",
        {"query_status": "no_result", "data": "Your search did not yield any results"},
    )
    assert analyze_with("1.2.3.4", full, only(ThreatFoxProvider())).result("threatfox").data == {
        "found": False
    }
    fake_api.routes.clear()
    fake_api.add(
        "POST",
        "https://threatfox-api.abuse.ch/",
        httpx.Response(403, json={"query_status": "unknown_auth_key"}),
    )
    error = analyze_with("1.2.3.4", full, only(ThreatFoxProvider())).result("threatfox").error
    assert error == "threatfox-api.abuse.ch refused the request (HTTP 403); check the API key"
    fake_api.routes.clear()
    fake_api.json(
        "POST", "https://threatfox-api.abuse.ch/", {"query_status": "illegal_search_term"}
    )
    error = analyze_with("1.2.3.4", full, only(ThreatFoxProvider())).result("threatfox").error
    assert error == "ThreatFox: illegal_search_term"


def test_ioc_host_forms():
    assert ioc_host("1.2.3.4:443") == "1.2.3.4"
    assert ioc_host("[2001:db8::1]:443") == "2001:db8::1"
    assert ioc_host("2001:db8::1") == "2001:db8::1"
    assert defang("http://1.2.3.4/x") == "hxxp://1.2.3.4/x"


def test_urlhaus(full, fake_api):
    fake_api.json("POST", "https://urlhaus-api.abuse.ch/v1/host/", URLHAUS_EXAMPLE)
    data = analyze_with("1.2.3.4", full, only(URLhausProvider())).result("urlhaus").data
    assert data["found"] is True and data["url_count"] == 3 and data["online"] == 1
    assert data["urls"][0]["url"] == "hxxp://1.2.3.4/bins/mozi.m"
    assert data["urls"][1]["url"] == "hxxps://1.2.3.4/x.sh"
    assert parse_qs(fake_api.requests[0].content.decode()) == {"host": ["1.2.3.4"]}
    fake_api.routes.clear()
    fake_api.json("POST", "https://urlhaus-api.abuse.ch/", {"query_status": "no_results"})
    assert analyze_with("1.2.3.4", full, only(URLhausProvider())).result("urlhaus").data == {
        "found": False
    }


# ------------------------------------------------------------------ Spamhaus ZEN


@pytest.fixture
def zen(fake_dns):
    fake_dns.records[("2.0.0.127.zen.spamhaus.org", "A")] = ["127.0.0.2", "127.0.0.4", "127.0.0.10"]
    return fake_dns


def test_spamhaus_listing_codes(full, zen):
    zen.records[("4.3.2.1.zen.spamhaus.org", "A")] = ["127.0.0.4", "127.0.0.11"]
    report = analyze_with("1.2.3.4", full, only(SpamhausProvider()))
    data = report.result("spamhaus").data
    assert [e["list"] for e in data["lists"]] == ["XBL", "PBL (Spamhaus)"]
    assert data["abuse_listed"] is True and data["zone"] == "public mirror"
    assert report.summary["threat"]["spamhaus_lists"] == ["XBL", "PBL (Spamhaus)"]


def test_spamhaus_pbl_only_is_not_abuse_and_not_listed(full, zen):
    zen.records[("4.3.2.1.zen.spamhaus.org", "A")] = ["127.0.0.10"]
    data = analyze_with("1.2.3.4", full, only(SpamhausProvider())).result("spamhaus").data
    assert data["listed"] is True and data["abuse_listed"] is False
    clean = analyze_with("5.6.7.8", full, only(SpamhausProvider())).result("spamhaus").data
    assert clean == {"listed": False, "abuse_listed": False, "lists": [], "zone": "public mirror"}


def test_spamhaus_refusals_are_errors_not_listings(full, fake_dns):
    result = analyze_with("1.2.3.4", full, only(SpamhausProvider())).result("spamhaus")
    assert "does not reach Spamhaus" in result.error  # test entry missing: filtered DNS
    fake_dns.records[("2.0.0.127.zen.spamhaus.org", "A")] = ["127.255.255.254"]
    result = analyze_with("1.2.3.4", full, only(SpamhausProvider())).result("spamhaus")
    assert "refuses queries sent through public DNS resolvers" in result.error
    fake_dns.records[("2.0.0.127.zen.spamhaus.org", "A")] = ["127.0.0.2"]
    fake_dns.records[("4.3.2.1.zen.spamhaus.org", "A")] = ["127.255.255.255"]
    result = analyze_with("1.2.3.4", full, only(SpamhausProvider())).result("spamhaus")
    assert "too many queries" in result.error


def test_spamhaus_dqs_key_and_ipv6_never_leak_key(full, fake_dns):
    keyed = dataclasses.replace(full, api_keys={**KEYS, "SPAMHAUS_DQS_KEY": "secretdqskey"})
    zone = "secretdqskey.zen.dq.spamhaus.net"
    fake_dns.records[(f"2.0.0.127.{zone}", "A")] = ["127.0.0.2"]
    name = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2." + zone
    fake_dns.records[(name, "A")] = ["127.0.0.2"]
    data = (
        analyze_with("2001:4860:4860::8888", keyed, only(SpamhausProvider()))
        .result("spamhaus")
        .data
    )
    assert data["zone"] == "DQS" and data["lists"][0]["list"] == "SBL"
    assert "secretdqskey" not in json.dumps(data)
    fake_dns.records[(name, "A")] = DNSLookupError(f"DNS query for {name} timed out")
    error = (
        analyze_with("2001:4860:4860::8888", keyed, only(SpamhausProvider()))
        .result("spamhaus")
        .error
    )
    assert error == "DNS query to Spamhaus failed or timed out"


# ------------------------------------------------------------------ offline lists


def write_list(config, name, text):
    store = ListStore(config.lists_dir)
    store.directory.mkdir(parents=True, exist_ok=True)
    store.path(SPECS[name]).write_text(text, encoding="utf-8")


FEODO = [
    {
        "ip_address": "1.2.3.4",
        "port": 443,
        "status": "offline",
        "hostname": None,
        "as_number": 64500,
        "as_name": "EXAMPLE-AS",
        "country": "DE",
        "first_seen": "2026-08-01 10:00:00",
        "last_online": "2026-09-30",
        "malware": "QakBot",
    }
]


def test_feodo_list(config):
    write_list(config, "feodo", json.dumps(FEODO))
    report = analyze_with("1.2.3.4", config, only(FeodoProvider()))
    data = report.result("feodo").data
    assert data["listed"] is True
    assert data["entries"] == [
        {
            "port": 443,
            "status": "offline",
            "malware": "QakBot",
            "first_seen": "2026-08-01 10:00:00",
            "last_online": "2026-09-30",
            "as_name": "EXAMPLE-AS",
            "country": "DE",
        }
    ]
    assert report.summary["threat"]["feodo_c2"] is True
    assert (
        analyze_with("5.6.7.8", config, only(FeodoProvider())).result("feodo").data["listed"]
        is False
    )
    write_list(config, "feodo", "[]")  # an empty list after a takedown is valid
    assert analyze_with("1.2.3.4", config, only(FeodoProvider())).result("feodo").ok


def test_feodo_download_sends_abusech_key_only_when_set(config, fake_api, tmp_path):
    fake_api.add("GET", SPECS["feodo"].url, httpx.Response(200, text=json.dumps(FEODO)))

    async def update(cfg, folder):
        async with Session(cfg) as session:
            return await ListStore(folder).update(SPECS["feodo"], session)

    assert run(update(config, tmp_path / "a"))["status"] == "updated"
    assert "auth-key" not in fake_api.requests[-1].headers
    keyed = dataclasses.replace(config, api_keys={"ABUSECH_AUTH_KEY": "abusech-key"})
    assert run(update(keyed, tmp_path / "b"))["status"] == "updated"
    assert fake_api.requests[-1].headers["auth-key"] == "abusech-key"


class FakeASNSource(Provider):
    name = "team-cymru"
    layer = "L3"

    async def lookup(self, ctx):
        return {"network": {"asn": 64511}}


def drop_ndjson(prefix_template, count, sbl_start=1):
    lines = [
        json.dumps(
            {"cidr": prefix_template.format(i), "sblid": f"SBL{sbl_start + i}", "rir": "ripencc"}
        )
        for i in range(count)
    ]
    lines.append(json.dumps({"type": "metadata", "timestamp": 1791500000, "records": count}))
    return "\n".join(lines) + "\n"


def test_spamhaus_drop_lists(config):
    write_list(config, "spamhaus-drop-v4", drop_ndjson("1.10.{}.0/24", 120))
    write_list(config, "spamhaus-drop-v6", drop_ndjson("2a0e:{:x}::/32", 5))
    asn_lines = [json.dumps({"asn": 64511, "rir": "ripencc", "domain": "bad.example", "cc": "XX"})]
    asn_lines += [json.dumps({"asn": 64600 + i, "rir": "arin"}) for i in range(12)]
    write_list(config, "spamhaus-asndrop", "\n".join(asn_lines))

    data = (
        analyze_with("1.10.7.1", config, only(SpamhausDropProvider())).result("spamhaus-drop").data
    )
    assert data["listed"] is True
    assert data["evidence"] == [{"type": "prefix", "value": "1.10.7.0/24", "sblid": "SBL8"}]
    assert set(data["lists"]) == {"spamhaus-drop-v4", "spamhaus-drop-v6", "spamhaus-asndrop"}

    v6 = (
        analyze_with("2a0e:3::1", config, only(SpamhausDropProvider())).result("spamhaus-drop").data
    )
    assert v6["evidence"][0]["value"] == "2a0e:3::/32"

    by_asn = analyze_with("9.9.9.9", config, only(FakeASNSource(), SpamhausDropProvider()))
    data = by_asn.result("spamhaus-drop").data
    assert data["evidence"] == [{"type": "asn", "value": "AS64511", "name": "bad.example (XX)"}]
    assert by_asn.summary["threat"]["spamhaus_drop"] is True


# ------------------------------------------------------------------ output


def test_lookup_full_profile_shows_threat_section(capsys, monkeypatch, fake_api, zen):
    for key, value in KEYS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("COLUMNS", "220")
    fake_api.json("GET", "https://api.abuseipdb.com/api/v2/check", ABUSEIPDB_EXAMPLE)
    fake_api.json(
        "GET",
        "https://api.greynoise.io/v3/community/1.2.3.4",
        dict(
            GREYNOISE_8888,
            ip="1.2.3.4",
            riot=False,
            noise=True,
            classification="malicious",
            name="unknown",
        ),
    )
    fake_api.json("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", VT_EXAMPLE)
    fake_api.json(
        "GET", "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general", OTX_EXAMPLE
    )
    fake_api.json("POST", "https://threatfox-api.abuse.ch/api/v1/", THREATFOX_EXAMPLE)
    fake_api.json("POST", "https://urlhaus-api.abuse.ch/v1/host/", URLHAUS_EXAMPLE)
    zen.records[("4.3.2.1.zen.spamhaus.org", "A")] = ["127.0.0.4"]
    assert main(["lookup", "--profile", "full", "--no-color", "--no-cache", "1.2.3.4"]) == 0
    out = capsys.readouterr().out
    assert "Threat reputation" in out
    assert "score 100/100 - 2 report(s) from 2 reporter(s) in 90 days, last 2018-12-20" in out
    assert "Brute-Force (2), SSH (1)" in out
    assert "malicious - scanning the internet" in out
    assert "3 of 94 engines say malicious, 1 suspicious (analysed 2026-10-08)" in out
    assert "QakBot C2 servers [QakBot]" in out
    assert "QakBot - Indicator that identifies a botnet command&control server" in out
    assert "3 malware URL(s), 1 online" in out and "hxxp://1.2.3.4/bins/mozi.m" in out
    assert "XBL: Exploits Block List" in out
    assert "non-commercial use only" in out
    assert "abuse-key" not in out and "vt-key" not in out
