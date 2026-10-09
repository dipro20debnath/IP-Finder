"""Phase 3: RDAP, RIPEstat, reverse DNS and Geofeed.

Sample payloads follow the documented layouts (RFC 9083 / ARIN RDAP, RIPEstat
Data API, RFC 8805). Live responses are recorded with scripts/capture_fixtures.py.
"""

import copy
import ipaddress
import json

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import httpx
import pytest

from ipfinder.analysis.hostname import hostname_hints
from ipfinder.cli import main
from ipfinder.core.cache import Cache
from ipfinder.core.dns import DNSLookupError, _text
from ipfinder.core.session import Session
from ipfinder.providers import PLANNED_PROVIDERS, default_providers
from ipfinder.providers.base import ProviderError
from ipfinder.providers.geofeed import GeofeedProvider, best_entry, parse_geofeed
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.rdap import (
    RDAPProvider,
    find_server,
    geofeed_urls,
    parse_bootstrap,
    parse_network,
)
from ipfinder.providers.reverse_dns import ReverseDNSProvider
from ipfinder.providers.ripestat import RIPEstatProvider, parse_neighbours, unwrap
from tests.conftest import analyze_many_with, analyze_with, run

BOOTSTRAP_V4 = {
    "description": "RDAP bootstrap file for IPv4 address allocations",
    "publication": "2025-01-01T00:00:00Z",
    "version": "1.0",
    "services": [
        [
            ["8.0.0.0/8", "3.0.0.0/8"],
            ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"],
        ],
        [["193.0.0.0/8"], ["https://rdap.db.ripe.net/"]],
        [["1.0.0.0/8"], ["https://rdap.apnic.net/"]],
        [["200.0.0.0/8"], ["https://rdap.lacnic.net/rdap/"]],
    ],
}
BOOTSTRAP_V6 = {
    "version": "1.0",
    "services": [[["2001:4800::/23"], ["https://rdap.arin.net/registry/"]]],
}

# Layout of ARIN's answer for 8.8.8.8 (abuse contact nested inside the registrant).
ARIN_8888 = {
    "rdapConformance": ["nro_rdap_profile_0", "rdap_level_0", "cidr0", "arin_originas0"],
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-2",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "ipVersion": "v4",
    "name": "GOGL",
    "type": "DIRECT ALLOCATION",
    "parentHandle": "NET-8-0-0-0-0",
    "status": ["active"],
    "port43": "whois.arin.net",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "arin_originas0_originautnums": [],
    "events": [
        {"eventAction": "last changed", "eventDate": "2023-12-28T17:24:56-05:00"},
        {"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"},
    ],
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Google LLC"],
                    ["kind", {}, "text", "org"],
                ],
            ],
            "entities": [
                {
                    "objectClassName": "entity",
                    "handle": "ABUSE5250-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Abuse"],
                            ["kind", {}, "text", "group"],
                            ["email", {}, "text", "network-abuse@google.com"],
                            ["tel", {"type": ["work", "voice"]}, "text", "+1-650-253-0000"],
                        ],
                    ],
                }
            ],
        }
    ],
}

# RIPE-style record: no cidr0, a country, description remarks, a geofeed remark.
RIPE_STYLE = {
    "objectClassName": "ip network",
    "handle": "193.0.0.0 - 193.0.7.255",
    "startAddress": "193.0.0.0",
    "endAddress": "193.0.7.255",
    "name": "RIPE-NCC",
    "type": "ASSIGNED PA",
    "country": "NL",
    "port43": "whois.ripe.net",
    "remarks": [
        {"description": ["RIPE Network Coordination Centre", "Amsterdam, Netherlands"]},
        {"title": "remarks", "description": ["Geofeed https://geofeed.example/ripe.csv."]},
    ],
    "links": [
        {"rel": "self", "href": "https://rdap.db.ripe.net/ip/193.0.0.0/21"},
        {
            "rel": "geo",
            "type": "application/geofeed+csv",
            "href": "https://geofeed.example/ripe.csv",
        },
        {"rel": "geo", "href": "http://insecure.example/feed.csv"},
    ],
    "entities": [
        {"handle": "ORG-RIEN1-RIPE", "roles": ["registrant"]},
        {
            "handle": "OPS4-RIPE",
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["email", {}, "text", "abuse@ripe.example"]]],
        },
    ],
}


def only(*providers):
    return [OfflineProvider(), *providers]


def serve_rdap(fake_api, ip="8.8.8.8", payload=ARIN_8888, server="https://rdap.arin.net/registry/"):
    fake_api.json("GET", "https://data.iana.org/rdap/ipv4.json", BOOTSTRAP_V4)
    fake_api.json("GET", "https://data.iana.org/rdap/ipv6.json", BOOTSTRAP_V6)
    fake_api.json("GET", f"{server}ip/{ip}", payload)


# ------------------------------------------------------------------ RDAP


def test_bootstrap_longest_match_and_https_preferred():
    entries = parse_bootstrap(
        {
            "services": [
                [["8.0.0.0/8"], ["http://plain.example/", "https://rdap.arin.net/registry"]],
                [["8.8.0.0/16"], ["http://only-http.example/rdap/"]],
                [["not-a-prefix"], ["https://x.example/"]],
                ["broken"],
            ]
        }
    )
    assert find_server(entries, "8.1.1.1") == "https://rdap.arin.net/registry/"
    assert find_server(entries, "8.8.8.8") == "http://only-http.example/rdap/"
    assert find_server(entries, "9.9.9.9") is None
    assert find_server(entries, "2001:db8::1") is None
    assert parse_bootstrap(None) == [] and parse_bootstrap({"services": "x"}) == []


def test_rdap_arin_record(config, fake_api):
    serve_rdap(fake_api)
    report = analyze_with("8.8.8.8", config, only(RDAPProvider()))
    data = report.result("rdap").data
    reg = data["registration"]
    assert reg["handle"] == "NET-8-8-8-0-2" and reg["name"] == "GOGL"
    assert reg["range"] == "8.8.8.0 - 8.8.8.255" and reg["cidrs"] == ["8.8.8.0/24"]
    assert reg["type"] == "DIRECT ALLOCATION" and reg["parent_handle"] == "NET-8-0-0-0-0"
    assert reg["registered"].startswith("2023-12-28")
    assert reg["registrant"] == {"name": "Google LLC", "handle": "GOGL", "kind": "org"}
    assert "origin_asns" not in reg  # empty list in the record
    assert data["abuse_contacts"] == [
        {
            "handle": "ABUSE5250-ARIN",
            "name": "Abuse",
            "emails": ["network-abuse@google.com"],
            "phones": ["+1-650-253-0000"],
        }
    ]
    assert data["rir"] == "ARIN" and data["server"] == "rdap.arin.net"
    assert data["url"] == "https://rdap.arin.net/registry/ip/8.8.8.8"
    rdap_request = next(r for r in fake_api.requests if "rdap.arin.net" in str(r.url))
    assert rdap_request.headers["accept"] == "application/rdap+json"
    assert report.summary["abuse_contacts"] == [
        {"email": "network-abuse@google.com", "sources": ["rdap"]}
    ]


def test_rdap_bootstrap_fetched_once_and_cached_on_disk(config, fake_api, tmp_path):
    serve_rdap(fake_api)
    fake_api.json("GET", "https://rdap.arin.net/registry/ip/8.8.4.4", ARIN_8888)
    fake_api.json("GET", "https://rdap.arin.net/registry/ip/8.8.1.1", ARIN_8888)
    analyze_many_with(["8.8.8.8", "8.8.4.4"], config, only(RDAPProvider()))
    assert len([r for r in fake_api.requests if "data.iana.org" in str(r.url)]) == 1

    path = tmp_path / "cache.sqlite"
    analyze_with("8.8.4.4", config, only(RDAPProvider()), cache=Cache(path))
    before = len(fake_api.requests)
    analyze_with("8.8.1.1", config, only(RDAPProvider()), cache=Cache(path))  # new run
    assert [str(r.url) for r in fake_api.requests[before:]] == [
        "https://rdap.arin.net/registry/ip/8.8.1.1"
    ]


def test_rdap_fallback_to_rdap_org(config, fake_api):
    # IANA unreachable: rdap.org redirects to the RIR's own server.
    fake_api.add(
        "GET",
        "https://rdap.org/ip/8.8.8.8",
        httpx.Response(302, headers={"location": "https://rdap.arin.net/registry/ip/8.8.8.8"}),
    )
    fake_api.json("GET", "https://rdap.arin.net/registry/ip/8.8.8.8", ARIN_8888)
    data = analyze_with("8.8.8.8", config, only(RDAPProvider())).result("rdap").data
    assert data["rir"] == "ARIN" and data["server"] == "rdap.arin.net"


def test_rdap_not_found_and_not_delegated(config, fake_api):
    serve_rdap(fake_api, payload={"errorCode": 404})
    fake_api.add(
        "GET",
        "https://rdap.db.ripe.net/ip/193.0.6.139",
        httpx.Response(404, json={"errorCode": 404, "title": "Not Found"}),
    )
    result = analyze_with("193.0.6.139", config, only(RDAPProvider())).result("rdap")
    assert result.error == "rdap.db.ripe.net has no RDAP record for this address"
    result = analyze_with("9.9.9.9", config, only(RDAPProvider())).result("rdap")
    assert "has not delegated this range to any RIR" in result.error


def test_rdap_wrong_object_and_bad_json(config, fake_api):
    serve_rdap(fake_api, payload={"objectClassName": "entity"})
    result = analyze_with("8.8.8.8", config, only(RDAPProvider())).result("rdap")
    assert result.error == "RDAP server returned something other than an IP network"
    fake_api.routes.clear()
    fake_api.json("GET", "https://data.iana.org/rdap/ipv4.json", BOOTSTRAP_V4)
    fake_api.add("GET", "https://rdap.arin.net/", httpx.Response(200, text="<html>"))
    result = analyze_with("8.8.8.8", config, only(RDAPProvider())).result("rdap")
    assert result.error == "rdap.arin.net returned invalid JSON"


def test_rdap_ripe_style_record():
    data = parse_network(copy.deepcopy(RIPE_STYLE), "rdap.db.ripe.net")
    reg = data["registration"]
    assert reg["cidrs"] == ["193.0.0.0/21"]  # computed from the range
    assert reg["country_code"] == "NL"
    assert reg["description"] == ["RIPE Network Coordination Centre", "Amsterdam, Netherlands"]
    assert reg["registrant"] == {"handle": "ORG-RIEN1-RIPE"}
    assert data["abuse_contacts"] == [{"handle": "OPS4-RIPE", "emails": ["abuse@ripe.example"]}]
    assert data["rir"] == "RIPE NCC"
    # link (rel geo) and remark give the same HTTPS URL once; plain HTTP is refused
    assert data["geofeed_urls"] == ["https://geofeed.example/ripe.csv"]


def test_rdap_unusual_shapes_do_not_crash():
    weird = {
        "objectClassName": "ip network",
        "startAddress": "2001:db8::",
        "endAddress": "10.0.0.1",  # mixed versions: no CIDR can be computed
        "cidr0_cidrs": [{"v6prefix": "zz", "length": 3}, "junk"],
        "events": [{"eventAction": "registration"}, "junk"],
        "entities": [{"roles": "abuse"}, {"roles": ["abuse"], "vcardArray": ["vcard", "x"]}],
        "remarks": ["junk", {"description": "not a list"}],
        "links": ["junk", {"rel": "geo", "href": 5}],
        "arin_originas0_originautnums": [15169],
    }
    data = parse_network(weird, "rdap.example")
    assert data["registration"]["cidrs"] == []
    assert data["registration"]["origin_asns"] == [15169]
    assert data["rir"] is None and data["geofeed_urls"] == []
    assert data["abuse_contacts"] == [{"emails": []}]


def test_geofeed_url_forms():
    obj = {
        "remarks": [
            {"description": ["Geofeed https://a.example/feed.csv", "geofeed: https://b.example/x)"]}
        ],
        "links": [
            {"rel": "alternate", "type": "application/geofeed+csv", "href": "https://c.example/g"}
        ],
    }
    assert geofeed_urls(obj) == [
        "https://c.example/g",
        "https://a.example/feed.csv",
        "https://b.example/x",
    ]


def test_rdap_rate_limit_per_server(config):
    async def go():
        async with Session(config) as session:
            provider = RDAPProvider()
            lacnic = provider._limiter(session, "https://rdap.lacnic.net/rdap/")
            arin = provider._limiter(session, "https://rdap.arin.net/registry/")
            return lacnic.calls, arin.calls, lacnic is arin

    assert run(go()) == (10, 30, False)


# ------------------------------------------------------------------ RIPEstat

RIPESTAT = "https://stat.ripe.net/data/"


def ok(data):
    return {"status": "ok", "status_code": 200, "messages": [], "data": data}


def serve_ripestat(fake_api, announced=True, origins=((15169, "GOOGLE - Google LLC"),)):
    fake_api.json(
        "GET",
        RIPESTAT + "prefix-overview/",
        ok(
            {
                "announced": announced,
                "resource": "8.8.8.0/24" if announced else "8.8.8.8/32",
                "asns": [{"asn": a, "holder": h} for a, h in origins] if announced else [],
            }
        ),
    )
    fake_api.json(
        "GET",
        RIPESTAT + "abuse-contact-finder/",
        ok({"abuse_contacts": ["Network-Abuse@google.com", 5, ""], "authoritative_rir": "arin"}),
    )
    fake_api.json(
        "GET",
        RIPESTAT + "rpki-validation/",
        ok(
            {
                "status": "valid",
                "validator": "routinator",
                "validating_roas": [
                    {
                        "origin": "15169",
                        "prefix": "8.8.8.0/24",
                        "max_length": 24,
                        "validity": "valid",
                    }
                ],
            }
        ),
    )
    fake_api.json(
        "GET",
        RIPESTAT + "routing-status/",
        ok(
            {
                "first_seen": {
                    "prefix": "8.8.8.0/24",
                    "origin": "15169",
                    "time": "2004-01-01T00:00:00",
                },
                "last_seen": {
                    "prefix": "8.8.8.0/24",
                    "origin": "15169",
                    "time": "2026-10-09T08:00:00",
                },
                "visibility": {
                    "v4": {"ris_peers_seeing": 330, "total_ris_peers": 333},
                    "v6": {"ris_peers_seeing": 0, "total_ris_peers": 320},
                },
            }
        ),
    )
    fake_api.json(
        "GET",
        RIPESTAT + "asn-neighbours/",
        ok(
            {
                "neighbour_counts": {"left": 3, "right": 1, "unique": 4, "uncertain": 0},
                "neighbours": [
                    {"asn": 3356, "type": "left", "power": 50},
                    {"asn": 1299, "type": "left", "power": 120},
                    {"asn": 174, "type": "left", "power": 50},
                    {"asn": 36040, "type": "right", "power": 3},
                    {"asn": 99, "type": "uncertain", "power": 999},
                ],
            }
        ),
    )


def test_ripestat_announced_prefix(config, fake_api):
    serve_ripestat(fake_api)
    report = analyze_with("8.8.8.8", config, only(RIPEstatProvider()))
    data = report.result("ripestat").data
    assert data["announced"] is True
    assert data["network"] == {
        "asn": 15169,
        "prefix": "8.8.8.0/24",
        "as_name": "GOOGLE - Google LLC",
        "rir": "ARIN",
    }
    assert data["rpki"] == [
        {
            "origin": 15169,
            "status": "valid",
            "roas": [
                {"origin": 15169, "prefix": "8.8.8.0/24", "max_length": 24, "validity": "valid"}
            ],
        }
    ]
    assert data["routing"]["visibility"] == {"ris_peers_seeing": 330, "total_ris_peers": 333}
    assert data["routing"]["first_seen"]["time"].startswith("2004-01-01")
    assert data["neighbours"]["top_upstream_side"] == [1299, 174, 3356]  # by power, then ASN
    assert data["neighbours"]["upstream_side"] == 3
    assert data["abuse_contacts"] == ["Network-Abuse@google.com"]
    assert "partial_errors" not in data
    assert report.summary["rpki"] == [{"origin": 15169, "status": "valid"}]
    assert report.summary["announced"] is True
    for request in fake_api.requests:
        assert request.url.params["sourceapp"] == "ip-finder"
    rpki = next(r for r in fake_api.requests if "rpki-validation" in str(r.url))
    assert rpki.url.params["resource"] == "AS15169" and rpki.url.params["prefix"] == "8.8.8.0/24"


def test_ripestat_not_announced(config, fake_api):
    serve_ripestat(fake_api, announced=False)
    data = analyze_with("8.8.8.8", config, only(RIPEstatProvider())).result("ripestat").data
    assert data["announced"] is False and "network" not in data and "rpki" not in data
    calls = [r.url.path.split("/")[2] for r in fake_api.requests]
    assert "rpki-validation" not in calls and "asn-neighbours" not in calls
    routing = next(r for r in fake_api.requests if "routing-status" in str(r.url))
    assert routing.url.params["resource"] == "8.8.8.8"
    assert data["routing"]["last_seen"]["origin"] == 15169


def test_ripestat_moas_validates_each_origin(config, fake_api):
    serve_ripestat(fake_api, origins=((15169, "GOOGLE"), (64500, None)))
    data = analyze_with("8.8.8.8", config, only(RIPEstatProvider())).result("ripestat").data
    assert data["network"]["origin_asns"] == [15169, 64500]
    assert [r["origin"] for r in data["rpki"]] == [15169, 64500]


def test_ripestat_partial_failure_is_shown_but_not_cached(config, fake_api, tmp_path):
    serve_ripestat(fake_api)
    fake_api.routes.insert(
        0, ("GET", RIPESTAT + "rpki-validation/", lambda req: httpx.Response(500))
    )
    cache = Cache(tmp_path / "c.sqlite")
    result = analyze_with("8.8.8.8", config, only(RIPEstatProvider()), cache=cache).result(
        "ripestat"
    )
    assert result.ok
    assert result.data["partial_errors"] == {
        "rpki-validation AS15169": "stat.ripe.net answered HTTP 500"
    }
    assert result.data["rpki"] == []
    assert cache.get("ripestat", "8.8.8.8") is None
    assert cache.get_error("ripestat", "8.8.8.8") is None
    cache.close()


def test_ripestat_overview_failure_is_an_error(config, fake_api):
    fake_api.json(
        "GET",
        RIPESTAT + "prefix-overview/",
        {"status": "error", "messages": [["error", "Invalid resource"]], "data": {}},
    )
    result = analyze_with("8.8.8.8", config, only(RIPEstatProvider())).result("ripestat")
    assert result.error == "RIPEstat prefix-overview: Invalid resource"


def test_ripestat_unwrap_and_neighbours():
    with pytest.raises(ProviderError, match="unexpected response"):
        unwrap("x", ["not", "a", "dict"])
    with pytest.raises(ProviderError, match="unexpected response"):
        unwrap("x", {"status": "ok", "data": []})
    assert parse_neighbours({"neighbours": "junk", "neighbour_counts": {}}) == {}


# ------------------------------------------------------------------ reverse DNS


def test_dns_record_text_forms():
    ptr = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, "dns.google.")
    a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8")
    txt = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"15169 | 8.8.8.0/24" " | US"')
    assert _text(ptr, "PTR") == "dns.google"
    assert _text(a, "A") == "8.8.8.8"
    assert _text(txt, "TXT") == "15169 | 8.8.8.0/24 | US"


def test_reverse_dns_forward_confirmed(config, fake_dns):
    fake_dns.records[("8.8.8.8.in-addr.arpa", "PTR")] = ["dns.google"]
    fake_dns.records[("dns.google", "A")] = ["8.8.4.4", "8.8.8.8"]
    data = analyze_with("8.8.8.8", config, only(ReverseDNSProvider())).result("reverse-dns").data
    assert data["ptr"] == ["dns.google"]
    assert data["forward_confirmed"] is True
    assert data["fcrdns"] == [
        {"hostname": "dns.google", "forward": ["8.8.4.4", "8.8.8.8"], "confirmed": True}
    ]


def test_reverse_dns_not_confirmed(config, fake_dns):
    # Anyone controlling the reverse zone can claim any name.
    fake_dns.records[("4.3.2.1.in-addr.arpa", "PTR")] = ["Mail.Google.com."]
    fake_dns.records[("mail.google.com", "A")] = ["142.250.1.1"]
    data = analyze_with("1.2.3.4", config, only(ReverseDNSProvider())).result("reverse-dns").data
    assert data["ptr"] == ["mail.google.com"]
    assert data["forward_confirmed"] is False
    assert data["hints"] == [{"category": "mail", "hint": "mail server", "evidence": "mail"}]


def test_reverse_dns_forward_lookup_fails(config, fake_dns):
    fake_dns.records[("4.3.2.1.in-addr.arpa", "PTR")] = ["gone.example.net"]
    data = analyze_with("1.2.3.4", config, only(ReverseDNSProvider())).result("reverse-dns").data
    assert data["fcrdns"][0]["confirmed"] is False
    assert data["fcrdns"][0]["forward_error"] == "gone.example.net does not exist"


def test_reverse_dns_ipv6(config, fake_dns):
    name = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
    fake_dns.records[(name, "PTR")] = ["dns.google"]
    fake_dns.records[("dns.google", "AAAA")] = ["2001:4860:4860:0:0:0:0:8888"]
    data = (
        analyze_with("2001:4860:4860::8888", config, only(ReverseDNSProvider()))
        .result("reverse-dns")
        .data
    )
    assert data["forward_confirmed"] is True
    assert data["fcrdns"][0]["forward"] == ["2001:4860:4860::8888"]


def test_reverse_dns_missing_vs_blocked(config, fake_dns):
    result = analyze_with("1.2.3.4", config, only(ReverseDNSProvider())).result("reverse-dns")
    assert result.ok is False and "blocked or filtered" in result.error
    fake_dns.records[("8.8.8.8.in-addr.arpa", "PTR")] = ["dns.google"]
    result = analyze_with("1.2.3.4", config, only(ReverseDNSProvider())).result("reverse-dns")
    assert result.ok and result.data["ptr"] == []
    assert result.data["note"].startswith("no PTR record")


def test_reverse_dns_timeout_is_an_error(config, fake_dns):
    fake_dns.records[("4.3.2.1.in-addr.arpa", "PTR")] = DNSLookupError("DNS query timed out")
    result = analyze_with("1.2.3.4", config, only(ReverseDNSProvider())).result("reverse-dns")
    assert result.error == "DNS query timed out"


@pytest.mark.parametrize(
    "hostname, target, categories",
    [
        ("c-73-162-1-2.hsd1.ca.comcast.net", "73.162.1.2", ["generated", "access"]),
        ("ec2-3-80-1-1.compute-1.amazonaws.com", "3.80.1.1", ["generated", "cloud"]),
        ("static.4.3.2.1.clients.your-server.de", "1.2.3.4", ["generated", "hosting"]),
        ("dns.google", "8.8.8.8", []),
        ("tor-exit-1.example.org", "1.2.3.4", ["anonymity"]),
        ("ae1.cr1.tor1.example.net", "1.2.3.4", []),  # "tor1" alone is usually Toronto
        ("ip-1-2-3-4.4g.example.net", "1.2.3.4", ["generated", "mobile"]),
        ("host.home.example", "1.2.3.4", []),  # the registered domain is ignored
        ("vps123.example.com", "1.2.3.4", ["server"]),
        ("cpe-1-2-3-44.example.com", "1.2.3.4", ["access"]),  # 1-2-3-44 is not 1-2-3-4
        ("x.0102030a.example.net", "1.2.3.10", ["generated"]),
        ("srv001002003004.example.net", "1.2.3.4", ["generated", "server"]),
    ],
)
def test_hostname_hints(hostname, target, categories):
    assert [h["category"] for h in hostname_hints(hostname, target)] == categories


def test_hostname_hint_zero_padded():
    assert hostname_hints("dyn-001002003004.example.net", "1.2.3.4")[0]["evidence"] == (
        "zero-padded address in the name"
    )


# ------------------------------------------------------------------ Geofeed

GEOFEED_URL = "https://geofeed.example/feed.csv"
GEOFEED_CSV = """﻿# RPKI Signature: 8.8.8.0/24
# MIIG...
8.8.8.0/24,US,US-CA,Mountain View,
8.8.8.0/25,US,US-NY,"New York, NY",
8.8.0.0/16,GB,GB-ENG,London,
8.8.8.1/24,DE,,,
not-a-prefix,US,,,
2001:db8::/32,US,,,
"""


def with_geofeed(payload):
    payload = copy.deepcopy(payload)
    payload["links"] = [{"rel": "geo", "type": "application/geofeed+csv", "href": GEOFEED_URL}]
    return payload


def test_parse_geofeed():
    entries, signed = parse_geofeed(GEOFEED_CSV)
    assert signed is True
    assert [str(n) for n, _ in entries] == [
        "8.8.8.0/24",
        "8.8.8.0/25",
        "8.8.0.0/16",
        "2001:db8::/32",
    ]
    assert entries[1][1] == {"country_code": "US", "region_code": "US-NY", "city": "New York, NY"}
    network, location, outside = best_entry(
        entries, "8.8.8.8", [ipaddress.ip_network("8.8.8.0/24")]
    )
    assert str(network) == "8.8.8.0/25" and location["city"] == "New York, NY"
    assert outside == 1  # the /16 lies outside the registered /24


def test_geofeed_after_rdap(config, fake_api):
    serve_rdap(fake_api, payload=with_geofeed(ARIN_8888))
    fake_api.add("GET", GEOFEED_URL, httpx.Response(200, text=GEOFEED_CSV))
    report = analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider()))
    data = report.result("geofeed").data
    assert data["prefix"] == "8.8.8.0/25"
    assert data["location"]["region_code"] == "US-NY"
    assert data["signed"] is True and data["entries"] == 4
    assert report.summary["country_by_source"] == {"geofeed": "US"}


def test_geofeed_entry_outside_registered_range_is_ignored(config, fake_api):
    serve_rdap(fake_api, payload=with_geofeed(ARIN_8888))
    fake_api.add("GET", GEOFEED_URL, httpx.Response(200, text="8.8.0.0/16,GB,,London,\n"))
    data = (
        analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider()))
        .result("geofeed")
        .data
    )
    assert "location" not in data
    assert "outside the registered range (1 entry ignored, RFC 9632)" in data["note"]


def test_geofeed_refuses_redirect_to_http_and_large_files(config, fake_api, monkeypatch):
    serve_rdap(fake_api, payload=with_geofeed(ARIN_8888))
    fake_api.add(
        "GET",
        GEOFEED_URL,
        httpx.Response(302, headers={"location": "http://geofeed.example/feed.csv"}),
    )
    fake_api.add("GET", "http://geofeed.example/", httpx.Response(200, text=GEOFEED_CSV))
    result = analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider())).result(
        "geofeed"
    )
    assert (
        result.error == "geofeed download failed: geofeed.example redirected to plain HTTP; refused"
    )

    fake_api.routes = [r for r in fake_api.routes if "geofeed.example" not in r[1]]
    fake_api.add("GET", GEOFEED_URL, httpx.Response(200, text="x" * 5000))
    monkeypatch.setattr("ipfinder.providers.geofeed.MAX_BYTES", 1000)
    result = analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider())).result(
        "geofeed"
    )
    assert "larger than" in result.error


def test_geofeed_skips(config, fake_api):
    serve_rdap(fake_api)
    report = analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider()))
    assert report.result("geofeed").skipped == "the registration record names no geofeed file"
    report = analyze_with("8.8.8.8", config, only(GeofeedProvider()))
    assert report.result("geofeed").skipped == "needs the RDAP registration record"


# ------------------------------------------------------------------ registry and output


def test_phase3_providers_registered():
    names = [p.name for p in default_providers()]
    for name in ("rdap", "ripestat", "reverse-dns", "geofeed"):
        assert name in names
    assert not {"rdap", "ripestat", "dns", "geofeed"} & {p.name for p in PLANNED_PROVIDERS}
    stages = {p.name: p.stage for p in default_providers()}
    assert stages["geofeed"] == 2 and stages["rdap"] == 1


def test_peeringdb_uses_ripestat_asn(config, fake_api):
    from ipfinder.providers.peeringdb import PeeringDBProvider

    serve_ripestat(fake_api)
    fake_api.json("GET", "https://www.peeringdb.com/api/net", {"data": []})
    report = analyze_with("8.8.8.8", config, only(RIPEstatProvider(), PeeringDBProvider()))
    assert report.result("peeringdb").data["asn"] == 15169


@pytest.fixture
def everything(fake_api, fake_dns):
    serve_rdap(fake_api)
    serve_ripestat(fake_api)
    fake_dns.records[("8.8.8.8.in-addr.arpa", "PTR")] = ["dns.google"]
    fake_dns.records[("dns.google", "A")] = ["8.8.8.8"]


def test_lookup_text_shows_phase3_sections(capsys, monkeypatch, everything):
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["lookup", "--no-color", "--no-cache", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    assert "Routing and RPKI (RIPEstat)" in out
    assert "announced as 8.8.8.0/24 by AS15169 (GOOGLE - Google LLC)" in out
    assert "valid - a ROA authorises this origin AS for this prefix" in out
    assert "330 of 333 RIS peers (99%)" in out
    assert "Registration (RDAP)" in out and "GOGL (NET-8-8-8-0-2)" in out
    assert "Google LLC (GOGL)" in out and "ARIN (rdap.arin.net)" in out
    assert "network-abuse@google.com  (rdap, ripestat)" in out
    assert "yes - dns.google resolves back to this address" in out


def test_lookup_json_has_abuse_and_rpki(capsys, everything):
    assert main(["lookup", "-f", "json", "--no-cache", "8.8.8.8"]) == 0
    summary = json.loads(capsys.readouterr().out)["reports"][0]["summary"]
    assert summary["abuse_contacts"] == [
        {"email": "network-abuse@google.com", "sources": ["rdap", "ripestat"]}
    ]
    assert summary["rpki"] == [{"origin": 15169, "status": "valid"}]
    assert summary["asn_by_source"] == {"ripestat": 15169}


def test_rpki_invalid_is_highlighted(capsys, monkeypatch, everything, fake_api):
    fake_api.routes.insert(
        0,
        (
            "GET",
            RIPESTAT + "rpki-validation/",
            lambda req: httpx.Response(
                200, json=ok({"status": "invalid_asn", "validating_roas": []})
            ),
        ),
    )
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["lookup", "--no-color", "--no-cache", "8.8.8.8"]) == 0
    assert "INVALID - no ROA authorises this origin AS" in capsys.readouterr().out


def test_remote_text_cannot_inject_terminal_codes(capsys, monkeypatch, fake_api, fake_dns):
    hostile = copy.deepcopy(ARIN_8888)
    hostile["name"] = "EVIL\x1b]0;pwned\x07\x1b[2J"
    serve_rdap(fake_api, payload=hostile)
    fake_dns.records[("8.8.8.8.in-addr.arpa", "PTR")] = ["dns.google"]
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["lookup", "--no-color", "--no-cache", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "EVIL\\x1b]0;pwned\\x07\\x1b[2J" in out


def test_sources_lists_phase3_as_ready(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["sources"]) == 0
    out = capsys.readouterr().out
    lines = {line.split("│")[1].strip(): line for line in out.splitlines() if line.count("│") > 3}
    for name in ("rdap", "ripestat", "reverse-dns", "geofeed"):
        assert "ready" in lines[name], name


def test_geofeed_size_cap_without_content_length(config, fake_api, monkeypatch):
    async def chunks():
        for _ in range(10):
            yield b"8.8.8.0/24,US,,,\n" * 30

    serve_rdap(fake_api, payload=with_geofeed(ARIN_8888))
    fake_api.add("GET", GEOFEED_URL, lambda req: httpx.Response(200, content=chunks()))
    monkeypatch.setattr("ipfinder.providers.geofeed.MAX_BYTES", 1000)
    result = analyze_with("8.8.8.8", config, only(RDAPProvider(), GeofeedProvider())).result(
        "geofeed"
    )
    assert result.error == "geofeed download failed: geofeed.example file is larger than 0.001 MB"
