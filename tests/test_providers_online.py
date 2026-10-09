"""Online providers, tested against the response formats in each provider's docs.

The sample payloads below follow the documented field layouts. Live responses are
recorded separately with scripts/capture_fixtures.py.
"""

import dataclasses
import json

import httpx
import pytest

from ipfinder.core.cache import Cache
from ipfinder.core.dns import DNSLookupError
from ipfinder.core.session import Session
from ipfinder.providers.base import ProviderError
from ipfinder.providers.cymru import (
    TeamCymruProvider,
    origin_query,
    parse_as_name,
    parse_origin,
)
from ipfinder.providers.ipapi import IpApiProvider, normalize, public_ip
from ipfinder.providers.ipinfo_lite import IpinfoLiteProvider
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.peeringdb import PeeringDBProvider
from tests.conftest import ASN_DB, CITY_DB, analyze_many_with, analyze_with, run

# Example response from the ip-api.com JSON documentation (24.48.0.1).
IP_API_DOC_EXAMPLE = {
    "query": "24.48.0.1",
    "status": "success",
    "country": "Canada",
    "countryCode": "CA",
    "region": "QC",
    "regionName": "Quebec",
    "city": "Montreal",
    "zip": "H1K",
    "lat": 45.6085,
    "lon": -73.5493,
    "timezone": "America/Toronto",
    "isp": "Le Groupe Videotron Ltee",
    "org": "Videotron Ltee",
    "as": "AS5769 Videotron Ltee",
}

IPINFO_LITE_EXAMPLE = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}


def only(*providers):
    return [OfflineProvider(), *providers]


# ---------------------------------------------------------------- ip-api


def test_ip_api_normalize_doc_example():
    data = normalize(IP_API_DOC_EXAMPLE)
    assert data["location"] == {
        "country": "Canada",
        "country_code": "CA",
        "region": "Quebec",
        "region_code": "QC",
        "city": "Montreal",
        "postal_code": "H1K",
        "latitude": 45.6085,
        "longitude": -73.5493,
        "timezone": "America/Toronto",
    }
    assert data["network"] == {
        "asn": 5769,
        "as_name": "Videotron Ltee",
        "isp": "Le Groupe Videotron Ltee",
        "org": "Videotron Ltee",
    }
    assert data["raw"] == IP_API_DOC_EXAMPLE


@pytest.mark.parametrize("message", ["private range", "reserved range", "invalid query"])
def test_ip_api_fail_status(message):
    with pytest.raises(ProviderError, match=message):
        normalize({"status": "fail", "message": message, "query": "10.0.0.1"})


def test_ip_api_lookup_and_rate_limit_headers(config, fake_api):
    fake_api.json(
        "GET",
        "http://ip-api.com/json/24.48.0.1",
        IP_API_DOC_EXAMPLE,
        headers={"X-Rl": "0", "X-Ttl": "42"},
    )

    async def go():
        async with Session(config, cache=Cache(None)) as session:
            from ipfinder.core.orchestrator import analyze

            report = await analyze("24.48.0.1", session, only(IpApiProvider()))
            return report, session.limiter("ip-api", 45, 60.0)

    report, limiter = run(go())
    result = report.result("ip-api")
    assert result.ok and result.data["location"]["city"] == "Montreal"
    request = fake_api.requests[0]
    assert request.url.params["fields"].startswith("status,message,")
    assert "hosting" in request.url.params["fields"]
    assert limiter._blocked_until > 0  # X-Rl: 0 paused further calls


def test_ip_api_http_429(config, fake_api):
    fake_api.add("GET", "http://ip-api.com/json/", httpx.Response(429, headers={"X-Ttl": "30"}))
    report = analyze_with("24.48.0.1", config, only(IpApiProvider()))
    assert report.result("ip-api").error == "rate limited by ip-api.com (HTTP 429); retry in 30s"


def test_ip_api_batch_prefetch(config, fake_api):
    targets = [f"24.48.{i // 256}.{i % 256}" for i in range(1, 151)]

    def batch(request):
        ips = json.loads(request.content)
        assert len(ips) <= 100
        out = []
        for address in ips:
            if address == "24.48.0.7":
                out.append({"status": "fail", "message": "reserved range", "query": address})
            else:
                out.append({**IP_API_DOC_EXAMPLE, "query": address})
        return httpx.Response(200, json=out, headers={"X-Rl": "14", "X-Ttl": "60"})

    fake_api.add("POST", "http://ip-api.com/batch", batch)
    reports, errors = analyze_many_with(targets, config, only(IpApiProvider()))
    posts = [r for r in fake_api.requests if r.method == "POST"]
    assert [len(json.loads(r.content)) for r in posts] == [100, 50]
    assert not [r for r in fake_api.requests if r.method == "GET"]  # all served from batch
    assert errors == []
    failed = next(r for r in reports if r.ip == "24.48.0.7")
    assert failed.result("ip-api").error == "ip-api: reserved range"
    assert reports[0].result("ip-api").cached is True


def test_ip_api_batch_wrong_length_is_an_error(config, fake_api):
    fake_api.json("POST", "http://ip-api.com/batch", [IP_API_DOC_EXAMPLE])
    fake_api.json("GET", "http://ip-api.com/json/", IP_API_DOC_EXAMPLE)
    reports, _ = analyze_many_with(["24.48.0.1", "24.48.0.2"], config, only(IpApiProvider()))
    assert "unexpected response" in reports[0].notes[0]
    assert all(r.result("ip-api").ok for r in reports)  # fell back to single lookups


def test_public_ip(config, fake_api):
    fake_api.json("GET", "http://ip-api.com/json/", {"status": "success", "query": "203.0.113.9"})

    async def go():
        async with Session(config) as session:
            return await public_ip(session)

    assert run(go()) == "203.0.113.9"


# ---------------------------------------------------------------- IPinfo Lite

TOKEN = "secret-ipinfo-token"


def test_ipinfo_lite(config, fake_api):
    fake_api.json("GET", "https://api.ipinfo.io/lite/8.8.8.8", IPINFO_LITE_EXAMPLE)
    keyed = dataclasses.replace(config, api_keys={"IPINFO_TOKEN": TOKEN})
    result = analyze_with("8.8.8.8", keyed, only(IpinfoLiteProvider())).result("ipinfo-lite")
    assert result.data["network"] == {
        "asn": 15169,
        "as_name": "Google LLC",
        "as_domain": "google.com",
    }
    assert result.data["location"]["country_code"] == "US"
    assert fake_api.requests[0].url.params["token"] == TOKEN


def test_ipinfo_lite_bad_token_never_leaks(config, fake_api):
    fake_api.add("GET", "https://api.ipinfo.io/lite/", httpx.Response(403, json={"error": "x"}))
    keyed = dataclasses.replace(config, api_keys={"IPINFO_TOKEN": TOKEN})
    report = analyze_with("8.8.8.8", keyed, only(IpinfoLiteProvider()))
    error = report.result("ipinfo-lite").error
    assert error == "api.ipinfo.io refused the request (HTTP 403); check the API key"
    assert TOKEN not in json.dumps(report.to_dict())


def test_ipinfo_lite_network_error_never_leaks(config):
    keyed = dataclasses.replace(config, api_keys={"IPINFO_TOKEN": TOKEN})
    report = analyze_with("8.8.8.8", keyed, only(IpinfoLiteProvider()))
    assert report.result("ipinfo-lite").error == "cannot reach api.ipinfo.io (ConnectError)"
    assert TOKEN not in json.dumps(report.to_dict())


def test_ipinfo_lite_bogon(config, fake_api):
    fake_api.json("GET", "https://api.ipinfo.io/lite/", {"ip": "8.8.8.8", "bogon": True})
    keyed = dataclasses.replace(config, api_keys={"IPINFO_TOKEN": TOKEN})
    report = analyze_with("8.8.8.8", keyed, only(IpinfoLiteProvider()))
    assert "bogon" in report.result("ipinfo-lite").error


# ---------------------------------------------------------------- MaxMind (real test databases)


@pytest.fixture
def mm_config(config):
    return dataclasses.replace(config, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB)


def test_maxmind_city_record(mm_config):
    data = analyze_with("81.2.69.142", mm_config, only(MaxMindProvider())).result("maxmind").data
    assert data["location"] == {
        "continent": "Europe",
        "continent_code": "EU",
        "country": "United Kingdom",
        "country_code": "GB",
        "region": "England",
        "region_code": "ENG",
        "city": "London",
        "latitude": 51.5142,
        "longitude": -0.0931,
        "accuracy_radius_km": 10,
        "timezone": "Europe/London",
    }
    assert data["registered_country"] == {"country": "United States", "country_code": "US"}
    assert data["city_prefix"] == "81.2.69.142/31"
    assert data["databases"]["city"]["type"] == "GeoLite2-City"
    assert len(data["databases"]["city"]["build_date"]) == 10


def test_maxmind_asn_record(mm_config):
    data = analyze_with("89.160.20.112", mm_config, only(MaxMindProvider())).result("maxmind").data
    assert data["network"] == {"asn": 29518, "as_name": "Bredband2 AB", "prefix": "89.160.0.0/17"}
    assert data["location"]["city"] == "Linköping"


def test_maxmind_ipv6(mm_config):
    data = analyze_with("2001:480::1", mm_config, only(MaxMindProvider())).result("maxmind").data
    assert data["location"]["city"] == "San Diego"
    assert data["location"]["accuracy_radius_km"] == 50


def test_maxmind_address_not_in_database(mm_config):
    result = analyze_with("8.8.8.8", mm_config, only(MaxMindProvider())).result("maxmind")
    assert result.error == "address not found in the GeoLite2 database(s)"


def test_maxmind_skipped_without_files(config):
    result = analyze_with("8.8.8.8", config, only(MaxMindProvider())).result("maxmind")
    assert result.skipped.startswith("database not found")


def test_maxmind_asn_database_alone(config):
    asn_only = dataclasses.replace(config, maxmind_asn_db=ASN_DB)
    data = analyze_with("1.128.0.1", asn_only, only(MaxMindProvider())).result("maxmind").data
    assert data["network"]["asn"] == 1221
    assert "location" not in data


def test_maxmind_corrupt_file(config, tmp_path):
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"this is not a MaxMind database")
    broken = dataclasses.replace(config, maxmind_city_db=bad)
    result = analyze_with("8.8.8.8", broken, only(MaxMindProvider())).result("maxmind")
    assert result.error.startswith(f"cannot read {bad}")


# ---------------------------------------------------------------- Team Cymru


def test_origin_query_names():
    assert origin_query("216.90.108.31") == "31.108.90.216.origin.asn.cymru.com"
    assert origin_query("2001:4860:4860::8888").endswith(".0.6.8.4.1.0.0.2.origin6.asn.cymru.com")
    assert origin_query("2001:4860:4860::8888").startswith("8.8.8.8.0.0.0.0.")


def test_parse_origin_prefers_most_specific_prefix():
    records = [
        "23028 | 216.90.0.0/16 | US | arin | 1998-09-25",
        "23028 | 216.90.108.0/24 | US | arin | 1998-09-25",
    ]
    assert parse_origin(records) == {
        "asn": 23028,
        "origin_asns": [23028],
        "prefix": "216.90.108.0/24",
        "country_code": "US",
        "rir": "ARIN",
        "allocated": "1998-09-25",
    }


def test_parse_origin_multiple_asns():
    data = parse_origin(["13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28"])
    assert data["asn"] == 13335
    assert data["origin_asns"] == [13335, 209242]


def test_parse_as_name():
    # Team Cymru's own example
    assert parse_as_name(["23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"]) == (
        "TEAM-CYMRU - Team Cymru Inc., US"
    )
    with pytest.raises(ProviderError):
        parse_origin(["garbage"])


def test_cymru_lookup(config, fake_dns):
    fake_dns.records["31.108.90.216.origin.asn.cymru.com"] = [
        "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
    ]
    fake_dns.records["AS23028.asn.cymru.com"] = [
        "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"
    ]
    data = (
        analyze_with("216.90.108.31", config, only(TeamCymruProvider())).result("team-cymru").data
    )
    assert data["network"]["asn"] == 23028
    assert data["network"]["as_name"] == "TEAM-CYMRU - Team Cymru Inc., US"
    assert data["network"]["prefix"] == "216.90.108.0/24"


def test_cymru_ipv6_example(config, fake_dns):
    # Example answer quoted in APNIC's blog for Google's IPv6 space.
    fake_dns.records[origin_query("2001:4860:4860::8888")] = [
        "15169 | 2001:4860::/32 | US | arin | 2005-03-14"
    ]
    result = analyze_with("2001:4860:4860::8888", config, only(TeamCymruProvider()))
    data = result.result("team-cymru").data
    assert data["network"]["prefix"] == "2001:4860::/32"
    assert "as_name" not in data["network"]  # AS name lookup failed: still useful


def test_cymru_not_announced_vs_blocked_dns(config, fake_dns):
    result = analyze_with("192.0.0.9", config, only(TeamCymruProvider())).result("team-cymru")
    assert "DNS resolver cannot reach asn.cymru.com" in result.error

    fake_dns.records["AS15169.asn.cymru.com"] = ["15169 | US | arin | 2000-03-30 | GOOGLE"]
    result = analyze_with("192.0.0.9", config, only(TeamCymruProvider())).result("team-cymru")
    assert result.error == "no BGP origin record (address not announced)"


def test_cymru_dns_timeout(config, fake_dns):
    fake_dns.records["31.108.90.216.origin.asn.cymru.com"] = DNSLookupError("DNS query timed out")
    result = analyze_with("216.90.108.31", config, only(TeamCymruProvider())).result("team-cymru")
    assert result.error == "DNS query timed out"


# ---------------------------------------------------------------- PeeringDB

PEERINGDB_NET = {
    "id": 433,
    "name": "Google LLC",
    "aka": "Google, YouTube",
    "website": "https://about.google/",
    "asn": 15169,
    "info_type": "Content",
    "info_types": ["Content"],
    "info_scope": "Global",
    "info_traffic": "",
    "info_ratio": "Mostly Outbound",
    "info_prefixes4": 15000,
    "info_prefixes6": 750,
    "policy_general": "Selective",
    "irr_as_set": "RADB::AS-GOOGLE",
}


def _with_cymru_asn(fake_dns, asn=15169):
    fake_dns.records["8.8.8.8.origin.asn.cymru.com"] = [
        f"{asn} | 8.8.8.0/24 | US | arin | 2023-12-28"
    ]


def test_peeringdb_uses_asn_from_stage_one(config, fake_api, fake_dns):
    _with_cymru_asn(fake_dns)
    fake_api.json("GET", "https://www.peeringdb.com/api/net", {"data": [PEERINGDB_NET], "meta": {}})
    report = analyze_with("8.8.8.8", config, only(TeamCymruProvider(), PeeringDBProvider()))
    data = report.result("peeringdb").data
    assert data["asn"] == 15169
    info = data["network_info"]
    assert info["types"] == ["Content"]
    assert info["url"] == "https://www.peeringdb.com/net/433"
    assert "traffic" not in info  # empty string dropped
    request = fake_api.requests[0]
    assert request.url.params["asn"] == "15169"
    assert "authorization" not in request.headers


def test_peeringdb_api_key_and_old_info_type(config, fake_api, fake_dns):
    _with_cymru_asn(fake_dns)
    net = {k: v for k, v in PEERINGDB_NET.items() if k != "info_types"}
    fake_api.json("GET", "https://www.peeringdb.com/api/net", {"data": [net]})
    keyed = dataclasses.replace(config, api_keys={"PEERINGDB_API_KEY": "pdb-key"})
    report = analyze_with("8.8.8.8", keyed, only(TeamCymruProvider(), PeeringDBProvider()))
    assert report.result("peeringdb").data["network_info"]["types"] == ["Content"]
    assert fake_api.requests[0].headers["authorization"] == "Api-Key pdb-key"


def test_peeringdb_unregistered_asn(config, fake_api, fake_dns):
    _with_cymru_asn(fake_dns, asn=64496)
    fake_api.json("GET", "https://www.peeringdb.com/api/net", {"data": [], "meta": {}})
    report = analyze_with("8.8.8.8", config, only(TeamCymruProvider(), PeeringDBProvider()))
    assert report.result("peeringdb").data["note"] == "AS not registered in PeeringDB"


def test_peeringdb_skipped_without_asn(config):
    report = analyze_with("8.8.8.8", config, only(PeeringDBProvider()))
    assert report.result("peeringdb").skipped == "no ASN found by the other sources"


# ---------------------------------------------------------------- everything together


def test_full_report_combines_sources(config, fake_api, fake_dns):
    fake_api.json("GET", "http://ip-api.com/json/81.2.69.142", {**IP_API_DOC_EXAMPLE, "query": "x"})
    _ = fake_dns
    mm = dataclasses.replace(config, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB)
    report = analyze_with(
        "81.2.69.142", mm, only(IpApiProvider(), MaxMindProvider(), TeamCymruProvider())
    )
    summary = report.summary
    assert summary["map_source"] == "maxmind"  # has an accuracy radius
    assert summary["coordinates"]["accuracy_radius_km"] == 10
    assert summary["country_by_source"] == {"maxmind": "GB", "ip-api": "CA"}
    assert summary["countries_agree"] is False
    assert summary["local_time"]["timezone"] == "Europe/London"
