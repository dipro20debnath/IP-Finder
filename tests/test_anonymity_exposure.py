"""Phase 4: downloaded lists (Tor, cloud, Private Relay, VPN), update-lists,
MaxMind download and Shodan InternetDB.

List samples follow each publisher's documented format; the AWS and X4BNet
formats were also checked against the live files on 2026-10-09.
"""

import hashlib
import io
import json
import tarfile
from dataclasses import replace

import httpx
import pytest

from ipfinder.cli import main
from ipfinder.core.cache import Cache
from ipfinder.core.http import fetch_bytes
from ipfinder.core.session import Session
from ipfinder.lists.index import PrefixIndex, parse_cidr
from ipfinder.lists.maxmind import update_maxmind
from ipfinder.lists.specs import SPECS, parse_tor_exit_addresses
from ipfinder.lists.store import ListError, ListStore
from ipfinder.providers.base import Provider
from ipfinder.providers.cloud_ranges import CloudRangesProvider
from ipfinder.providers.internetdb import InternetDBProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.private_relay import PrivateRelayProvider
from ipfinder.providers.tor import TorProvider
from ipfinder.providers.vpn_lists import VPNListsProvider
from tests.conftest import ASN_DB, CITY_DB, analyze_with, run

TOR_EXIT = "185.220.101.1"


def only(*providers):
    return [OfflineProvider(), *providers]


def tor_bulk(extra=()):
    return "\n".join([f"185.220.100.{i}" for i in range(1, 151)] + [TOR_EXIT, *extra]) + "\n"


def tor_exit_addresses():
    records = [
        "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E",
        "Published 2026-10-09 06:23:54",
        "LastStatus 2026-10-09 07:00:00",
        f"ExitAddress {TOR_EXIT} 2026-10-09 07:04:23",
    ]
    for i in range(1, 120):
        records += [
            f"ExitNode {i:040X}",
            "Published 2026-10-09 05:00:00",
            "LastStatus 2026-10-09 06:00:00",
            f"ExitAddress 185.220.102.{i} 2026-10-09 06:10:00",
        ]
    return "\n".join(records) + "\n"


def aws_json():
    prefixes = [
        {
            "ip_prefix": "3.80.0.0/12",
            "region": "us-east-1",
            "service": "AMAZON",
            "network_border_group": "us-east-1",
        },
        {
            "ip_prefix": "3.80.0.0/12",
            "region": "us-east-1",
            "service": "EC2",
            "network_border_group": "us-east-1",
        },
        {
            "ip_prefix": "3.0.0.0/8",
            "region": "GLOBAL",
            "service": "AMAZON",
            "network_border_group": "GLOBAL",
        },
    ] + [
        {
            "ip_prefix": f"52.{i // 256}.{i % 256}.0/24",
            "region": "us-west-2",
            "service": "AMAZON",
            "network_border_group": "us-west-2",
        }
        for i in range(1000)
    ]
    v6 = [
        {
            "ipv6_prefix": "2600:1f00::/24",
            "region": "us-east-1",
            "service": "EC2",
            "network_border_group": "us-east-1-wl1",
        }
    ]
    return json.dumps(
        {
            "syncToken": "1",
            "createDate": "2026-10-09-15-37-06",
            "prefixes": prefixes,
            "ipv6_prefixes": v6,
        }
    )


def google_json(prefixes, cloud=True):
    entries = []
    for prefix in prefixes:
        key = "ipv6Prefix" if ":" in prefix else "ipv4Prefix"
        entry = {key: prefix}
        if cloud:
            entry.update(service="Google Cloud", scope="us-central1")
        entries.append(entry)
    filler = [{"ipv4Prefix": f"34.{i}.0.0/16"} for i in range(60)]
    return json.dumps({"creationTime": "2026-10-09T10:00:00", "prefixes": entries + filler})


def azure_json():
    values = [
        {
            "name": "AzureCloud.eastus",
            "properties": {
                "region": "eastus",
                "systemService": "",
                "addressPrefixes": ["20.42.0.0/16"],
            },
        },
        {
            "name": "AzureFrontDoor.Frontend",
            "properties": {
                "region": "",
                "systemService": "AzureFrontDoor",
                "addressPrefixes": ["20.42.1.0/24"],
            },
        },
        {
            "name": "AzureCloud",
            "properties": {
                "region": "",
                "systemService": "",
                "addressPrefixes": [f"40.{i // 256}.{i % 256}.0/24" for i in range(1000)],
            },
        },
    ]
    return json.dumps({"changeNumber": 321, "cloud": "Public", "values": values})


def geofeed_lines(first, count=1000):
    lines = [first] + [
        f"172.225.{i // 256}.{i % 256}/32,US,US-CA,Los Angeles," for i in range(count)
    ]
    return "\n".join(lines) + "\n"


def write_list(config, name, text, fetched_at=None):
    store = ListStore(config.lists_dir)
    spec = SPECS[name]
    store.directory.mkdir(parents=True, exist_ok=True)
    store.path(spec).write_text(text, encoding="utf-8")
    if fetched_at is not None:
        (store.directory / f"{name}.meta.json").write_text(json.dumps({"fetched_at": fetched_at}))


# ------------------------------------------------------------------ index


def test_parse_cidr_is_strict_but_masks_host_bits():
    assert parse_cidr("192.0.2.0/24") == (4, 0xC0000200, 24)
    assert parse_cidr("192.0.2.77/24") == (4, 0xC0000200, 24)  # host bits cleared
    assert parse_cidr("2001:db8::1") == (6, 0x20010DB8 << 96 | 1, 128)
    for bad in (
        "01.2.3.4",
        "1.2.3",
        "1.2.3.4/33",
        "1.2.3.4/",
        "1.2.3.4/x",
        "::1/129",
        "fe80::1%eth0",
        "",
        "256.1.1.1",
        " / ",
    ):
        assert parse_cidr(bad) is None, bad


def test_prefix_index_longest_match_and_duplicates():
    index = PrefixIndex()
    index.add("3.0.0.0/8", "wide")
    index.add("3.80.0.0/12", "a")
    index.add("3.80.0.0/12", "b")
    index.add("2600:1f00::/24", "v6")
    assert index.add("garbage") is False
    assert index.lookup("3.80.1.1") == [("3.80.0.0/12", ["a", "b"]), ("3.0.0.0/8", ["wide"])]
    assert index.longest("2600:1f00::5") == ("2600:1f00::/24", ["v6"])
    assert index.lookup("4.4.4.4") == [] and index.longest("::1") is None
    assert index.count == 4 and index.versions == {4, 6}


# ------------------------------------------------------------------ parsers


def test_tor_parsers():
    dataset = SPECS["tor-exits"].parse(tor_bulk(["2001:db8::99", "# comment", "junk"]))
    assert dataset.index.longest(TOR_EXIT)[0] == f"{TOR_EXIT}/32"
    assert 6 in dataset.index.versions
    relays = parse_tor_exit_addresses(tor_exit_addresses()).index.longest(TOR_EXIT)[1]
    assert relays == [
        {
            "fingerprint": "0011BD2485AD45D984EC4159C88FC066E5E3300E",
            "published": "2026-10-09 06:23:54",
            "laststatus": "2026-10-09 07:00:00",
            "tested": "2026-10-09 07:04:23",
        }
    ]
    with pytest.raises(ValueError, match="only 0 entries"):
        SPECS["tor-exits"].parse("<html><body>Service unavailable</body></html>")


def test_cloud_parsers():
    aws = SPECS["aws"].parse(aws_json())
    assert aws.published == "2026-10-09 15:37:06 UTC" and aws.entries == 1004
    assert SPECS["azure"].parse(azure_json()).published == "change 321"
    oracle = SPECS["oracle"].parse(
        json.dumps(
            {
                "last_updated_timestamp": "2026-10-08T22:10:41.418Z",
                "regions": [
                    {
                        "region": "us-phoenix-1",
                        "cidrs": [
                            {"cidr": f"129.146.{i}.0/24", "tags": ["OCI"]} for i in range(60)
                        ],
                    }
                ],
            }
        )
    )
    assert oracle.index.longest("129.146.5.9")[1] == [("us-phoenix-1", ("OCI",))]
    cloudflare = SPECS["cloudflare"].parse(
        json.dumps(
            {
                "success": True,
                "result": {
                    "ipv4_cidrs": [f"104.{16 + i}.0.0/16" for i in range(5)],
                    "ipv6_cidrs": ["2606:4700::/32"],
                    "etag": "x",
                },
            }
        )
    )
    assert cloudflare.index.longest("2606:4700::1111")
    with pytest.raises(ValueError):
        SPECS["cloudflare"].parse(json.dumps({"success": False, "errors": [{"code": 1}]}))
    fastly = SPECS["fastly"].parse(
        json.dumps(
            {
                "addresses": [f"151.101.{i}.0/24" for i in range(5)],
                "ipv6_addresses": ["2a04:4e40::/32"],
            }
        )
    )
    assert fastly.entries == 6
    for name in ("aws", "google", "azure", "oracle", "fastly"):
        with pytest.raises(ValueError):
            SPECS[name].parse("[]")


def test_geofeed_csv_and_asn_parsers():
    text = geofeed_lines('172.224.226.0/27,GB,GB-EN,"London, City of",,extra')
    dataset = SPECS["private-relay"].parse(text)
    assert dataset.index.longest("172.224.226.9")[1] == [("GB", "GB-EN", "London, City of")]
    asns = SPECS["vpn-asns"].parse(
        "AS9009 # M247, GB (NordVPN)\nas60068\n# comment\nASX\n"
        + "\n".join(f"AS{i}" for i in range(1, 5))
    )
    assert asns.asns[9009] == "M247, GB (NordVPN)" and asns.asns[60068] == ""


# ------------------------------------------------------------------ store and update-lists


def test_store_update_fresh_force_and_broken_download(config, fake_api, tmp_path):
    fake_api.add("GET", SPECS["tor-exits"].url, httpx.Response(200, text=tor_bulk()))
    clock = [1_000_000.0]
    store = ListStore(tmp_path / "lists", clock=lambda: clock[0])
    spec = SPECS["tor-exits"]

    async def update(force=False):
        async with Session(config) as session:
            return await store.update(spec, session, force)

    result = run(update())
    assert result["status"] == "updated" and result["entries"] == 151
    meta = json.loads((tmp_path / "lists" / "tor-exits.meta.json").read_text())
    assert meta["url"] == spec.url and meta["entries"] == 151
    assert run(update())["status"] == "fresh"
    calls = len(fake_api.requests)

    # A broken download (error page) never replaces a working list.
    fake_api.routes.clear()
    fake_api.add("GET", spec.url, httpx.Response(200, text="<html>maintenance</html>"))
    result = run(update(force=True))
    assert result["status"] == "failed"
    assert "the download is not a valid list (only 0 entries" in result["error"]
    assert len(fake_api.requests) == calls + 1
    assert store.load(spec).entries == 151

    clock[0] += 7 * 3600
    assert store.info(spec)["stale"] is True and store.info(spec)["age_hours"] == 7.0


def test_store_load_errors(tmp_path):
    store = ListStore(tmp_path)
    spec = SPECS["aws"]
    with pytest.raises(ListError) as excinfo:
        store.load(spec)
    assert excinfo.value.missing
    store.path(spec).write_text("{not json")
    with pytest.raises(ListError, match="run: ipfinder update-lists --force aws"):
        store.load(spec)


def test_azure_link_is_read_from_the_download_page(config, fake_api, tmp_path):
    link = (
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/"
        "ServiceTags_Public_20261005.json"
    )
    page = f'<html><a href="{link}" class="mscom-link">Download</a></html>'
    fake_api.add("GET", SPECS["azure"].url, httpx.Response(200, text=page))
    fake_api.add("GET", link, httpx.Response(200, text=azure_json()))
    store = ListStore(tmp_path)

    async def update():
        async with Session(config) as session:
            return await store.update(SPECS["azure"], session)

    result = run(update())
    assert result["status"] == "updated" and result["url"] == link
    fake_api.routes.clear()
    fake_api.add("GET", SPECS["azure"].url, httpx.Response(200, text="<html>new layout</html>"))

    async def update_other():
        async with Session(config) as session:
            return await ListStore(tmp_path / "other").update(SPECS["azure"], session)

    result = run(update_other())
    assert result["status"] == "failed" and "download link not found" in result["error"]


def test_fetch_bytes_drops_auth_on_cross_host_redirect(config, fake_api):
    fake_api.add(
        "GET",
        "https://updates.example/file",
        httpx.Response(302, headers={"location": "https://storage.example/presigned"}),
    )
    fake_api.add("GET", "https://storage.example/", httpx.Response(200, content=b"data"))

    async def go():
        async with Session(config) as session:
            return await fetch_bytes(
                session, "https://updates.example/file", max_bytes=100, auth=("1234", "secret")
            )

    assert run(go())[0] == b"data"
    first, second = fake_api.requests
    assert first.headers["authorization"].startswith("Basic ")
    assert "authorization" not in second.headers


# ------------------------------------------------------------------ providers


def test_list_providers_skip_until_downloaded(config):
    report = analyze_with(TOR_EXIT, config, only(TorProvider(), CloudRangesProvider()))
    assert report.result("tor").skipped == "list not downloaded (run: ipfinder update-lists)"
    assert report.result("cloud-ranges").skipped.startswith("list not downloaded")


def test_tor_exit_detected(config):
    write_list(config, "tor-exits", tor_bulk())
    write_list(config, "tor-exit-addresses", tor_exit_addresses())
    report = analyze_with(TOR_EXIT, config, only(TorProvider()))
    data = report.result("tor").data
    assert data["is_exit"] is True
    assert data["matched"] == ["tor-exits", "tor-exit-addresses"]
    assert data["relays"][0]["relay_search"] == (
        "https://metrics.torproject.org/rs.html#details/0011BD2485AD45D984EC4159C88FC066E5E3300E"
    )
    assert report.summary["anonymity"]["tor_exit"] is True
    other = analyze_with("185.220.200.1", config, only(TorProvider())).result("tor").data
    assert other["is_exit"] is False and other["relays"] == []


def test_tor_ipv6_and_stale_list(config):
    write_list(config, "tor-exits", tor_bulk(), fetched_at=0)
    data = analyze_with("2001:4860:4860::8888", config, only(TorProvider())).result("tor").data
    assert "hold no IPv6 addresses" in data["note"]
    assert data["stale"] == ["tor-exits"]
    assert data["not_downloaded"] == ["tor-exit-addresses"]


def test_tor_unreadable_list_is_an_error(config):
    write_list(config, "tor-exits", "<html>not a list</html>")
    result = analyze_with(TOR_EXIT, config, only(TorProvider())).result("tor")
    assert result.ok is False and "cannot be read" in result.error


def test_private_relay(config):
    write_list(config, "private-relay", geofeed_lines("172.224.226.0/27,GB,GB-EN,London,"))
    report = analyze_with("172.224.226.9", config, only(PrivateRelayProvider()))
    data = report.result("private-relay").data
    assert data == {
        "lists": data["lists"],
        "is_relay": True,
        "prefix": "172.224.226.0/27",
        "location": {"country_code": "GB", "region_code": "GB-EN", "city": "London"},
    }
    assert report.summary["country_by_source"] == {"private-relay": "GB"}
    assert report.summary["anonymity"]["icloud_private_relay"] is True


def test_cloud_ranges(config):
    write_list(config, "aws", aws_json())
    write_list(config, "google-cloud", google_json(["35.192.0.0/12"]))
    write_list(config, "google", google_json(["35.192.0.0/12", "8.8.8.0/24"], cloud=False))
    write_list(config, "azure", azure_json())
    data = analyze_with("3.80.1.1", config, only(CloudRangesProvider())).result("cloud-ranges").data
    assert data["matches"] == [
        {
            "provider": "Amazon Web Services",
            "list": "aws",
            "prefix": "3.80.0.0/12",
            "region": "us-east-1",
            "services": ["EC2"],
        }
    ]
    assert data["not_downloaded"] == ["oracle", "cloudflare", "fastly"]

    gcp = analyze_with("35.192.0.1", config, only(CloudRangesProvider())).result("cloud-ranges")
    assert [m["list"] for m in gcp.data["matches"]] == ["google-cloud"]  # goog.json dropped
    assert gcp.data["matches"][0]["region"] == "us-central1"

    google = analyze_with("8.8.8.8", config, only(CloudRangesProvider())).result("cloud-ranges")
    assert google.data["matches"][0]["note"].startswith("Google's own services and APIs")

    azure = analyze_with("20.42.1.5", config, only(CloudRangesProvider())).result("cloud-ranges")
    assert azure.data["matches"] == [
        {
            "provider": "Microsoft Azure",
            "list": "azure",
            "prefix": "20.42.1.0/24",
            "region": "eastus",
            "services": ["AzureFrontDoor"],
            "service_tags": ["AzureCloud.eastus", "AzureFrontDoor.Frontend"],
        }
    ]
    ipv6 = analyze_with("2600:1f00::1", config, only(CloudRangesProvider())).result("cloud-ranges")
    assert ipv6.data["matches"][0]["network_border_group"] == "us-east-1-wl1"


class FakeASNSource(Provider):
    """Stands in for Team Cymru: reports an ASN in stage 1."""

    name = "team-cymru"
    layer = "L3"

    def __init__(self, asn):
        self.asn = asn

    async def lookup(self, ctx):
        return {"network": {"asn": self.asn}}


def test_vpn_lists_by_prefix_and_asn(config):
    write_list(config, "vpn-networks", "\n".join(f"2.26.{i}.0/24" for i in range(150)))
    write_list(config, "datacenter-networks", "\n".join(f"2.26.{i}.0/24" for i in range(150)))
    write_list(
        config,
        "vpn-asns",
        "AS9009 # M247, GB (NordVPN)\n" + "\n".join(f"AS{i}" for i in range(1, 6)),
    )
    data = analyze_with("2.26.100.1", config, only(VPNListsProvider())).result("vpn-lists").data
    assert data["vpn"] == {
        "listed": True,
        "evidence": [{"type": "prefix", "value": "2.26.100.0/24"}],
    }
    assert data["datacenter"]["listed"] is True

    report = analyze_with("185.1.1.1", config, only(FakeASNSource(9009), VPNListsProvider()))
    data = report.result("vpn-lists").data
    assert data["vpn"]["evidence"] == [
        {"type": "asn", "value": "AS9009", "name": "M247, GB (NordVPN)"}
    ]
    assert data["datacenter"] == {"listed": False, "evidence": []}
    assert report.summary["anonymity"]["listed_vpn_network"] is True

    v6 = analyze_with("2001:4860::1", config, only(VPNListsProvider())).result("vpn-lists").data
    assert "IPv4-only" in v6["note"]


# ------------------------------------------------------------------ InternetDB

INTERNETDB_SAMPLE = {
    "ip": "1.2.3.4",
    "ports": [443, 23, 80, 3389],
    "hostnames": ["example.net"],
    "cpes": ["cpe:/a:openbsd:openssh:8.0"],
    "tags": ["self-signed"],
    "vulns": ["CVE-2023-38408", "CVE-2020-15778"],
}


def test_internetdb_found_and_cached_layout(config, fake_api, tmp_path):
    fake_api.json("GET", "https://internetdb.shodan.io/1.2.3.4", INTERNETDB_SAMPLE)
    cache = Cache(tmp_path / "c.sqlite")
    data = (
        analyze_with("1.2.3.4", config, only(InternetDBProvider()), cache=cache)
        .result("internetdb")
        .data
    )
    assert data["ports"] == [23, 80, 443, 3389]
    assert data["risky_ports"] == [
        {"port": 23, "service": "Telnet"},
        {"port": 3389, "service": "RDP"},
    ]
    assert data["vulns"] == ["CVE-2020-15778", "CVE-2023-38408"]
    again = analyze_with(
        "1.2.3.4", config, only(InternetDBProvider()), cache=Cache(tmp_path / "c.sqlite")
    )
    assert again.result("internetdb").cached and again.result("internetdb").data == data


def test_internetdb_no_data_and_errors(config, fake_api):
    fake_api.add(
        "GET",
        "https://internetdb.shodan.io/1.2.3.4",
        httpx.Response(404, json={"detail": "No information available"}),
    )
    data = analyze_with("1.2.3.4", config, only(InternetDBProvider())).result("internetdb").data
    assert data == {"found": False, "note": "Shodan has no scan data for this address"}
    fake_api.routes.clear()
    fake_api.add("GET", "https://internetdb.shodan.io/", httpx.Response(503))
    result = analyze_with("1.2.3.4", config, only(InternetDBProvider())).result("internetdb")
    assert result.error == "internetdb.shodan.io answered HTTP 503"


# ------------------------------------------------------------------ MaxMind download


def tar_gz(name, data):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


CITY_BYTES, ASN_BYTES = CITY_DB.read_bytes(), ASN_DB.read_bytes()


def serve_maxmind(fake_api, city=CITY_BYTES, asn=ASN_BYTES, md5=None):
    for edition, data in (("GeoLite2-City", city), ("GeoLite2-ASN", asn)):
        fake_api.json(
            "GET",
            f"https://updates.maxmind.com/geoip/updates/metadata?edition_id={edition}",
            {
                "databases": [
                    {
                        "edition_id": edition,
                        "date": "2026-10-07",
                        "md5": md5 or hashlib.md5(data).hexdigest(),
                    }
                ]
            },
        )
        fake_api.add(
            "GET",
            f"https://updates.maxmind.com/geoip/databases/{edition}/download?date=20261007&suffix=tar.gz",
            httpx.Response(200, content=tar_gz(f"{edition}_20261007/{edition}.mmdb", data)),
        )


def maxmind_config(config, tmp_path):
    return replace(
        config,
        api_keys={"MAXMIND_ACCOUNT_ID": "123456", "MAXMIND_LICENSE_KEY": "secret"},
        maxmind_city_db=tmp_path / "GeoLite2-City.mmdb",
        maxmind_asn_db=tmp_path / "GeoLite2-ASN.mmdb",
    )


def run_maxmind(cfg, force=False):
    async def go():
        async with Session(cfg) as session:
            return await update_maxmind(session, cfg, force)

    return run(go())


def test_maxmind_download_install_and_skip_when_current(config, fake_api, tmp_path):
    serve_maxmind(fake_api)
    cfg = maxmind_config(config, tmp_path)
    results = run_maxmind(cfg)
    assert [r["status"] for r in results] == ["updated", "updated"]
    assert (tmp_path / "GeoLite2-City.mmdb").read_bytes() == CITY_BYTES
    assert all(r.headers["authorization"].startswith("Basic ") for r in fake_api.requests)
    calls = len(fake_api.requests)
    assert [r["status"] for r in run_maxmind(cfg)] == ["fresh", "fresh"]
    assert len(fake_api.requests) == calls + 2  # metadata only, no download


def test_maxmind_failures(config, fake_api, tmp_path):
    assert run_maxmind(config)[0]["status"] == "skipped"
    serve_maxmind(fake_api, md5="0" * 32)
    cfg = maxmind_config(config, tmp_path)
    assert {r["error"] for r in run_maxmind(cfg)} == {
        "checksum mismatch; the download was corrupted"
    }
    fake_api.routes.clear()
    serve_maxmind(fake_api, city=ASN_BYTES)  # wrong edition in the City slot
    city = run_maxmind(cfg)[0]
    assert city["status"] == "failed" and "expected GeoLite2-City" in city["error"]
    assert not (tmp_path / "GeoLite2-City.mmdb").exists()
    fake_api.routes.clear()
    serve_maxmind(fake_api, city=b"not a database")
    assert "not readable" in run_maxmind(cfg)[0]["error"]


# ------------------------------------------------------------------ CLI and output


def test_update_lists_command(capsys, fake_api, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    fake_api.add("GET", SPECS["tor-exits"].url, httpx.Response(200, text=tor_bulk()))
    assert main(["update-lists", "tor-exits", "tor-exit-addresses", "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "tor-exits" in out and "151" in out and "updated" in out
    assert "failed: cannot reach check.torproject.org (ConnectError)" in out
    assert main(["update-lists", "--status", "tor-exits"]) == 0
    assert "ok" in capsys.readouterr().out
    assert main(["update-lists", "nope"]) == 2
    assert "Unknown list: nope" in capsys.readouterr().err


def test_lookup_shows_anonymity_and_exposure(capsys, fake_api, monkeypatch, tmp_path):
    monkeypatch.setenv("COLUMNS", "200")
    config_dir = tmp_path / "data" / "lists"
    config_dir.mkdir(parents=True)
    (config_dir / SPECS["tor-exits"].filename).write_text(tor_bulk())
    sample = dict(INTERNETDB_SAMPLE, ip=TOR_EXIT)
    fake_api.json("GET", f"https://internetdb.shodan.io/{TOR_EXIT}", sample)
    assert main(["lookup", "--no-color", "--no-cache", TOR_EXIT]) == 0
    out = capsys.readouterr().out
    assert "Anonymity and hosting (local lists)" in out
    assert "YES - listed by the Tor Project as an exit relay" in out
    assert "Exposed services (Shodan InternetDB)" in out
    assert "23 Telnet, 3389 RDP" in out
    assert "2: CVE-2020-15778, CVE-2023-38408" in out
    assert "free for non-commercial use only" in out

    assert main(["lookup", "-f", "json", "--no-cache", TOR_EXIT]) == 0
    summary = json.loads(capsys.readouterr().out)["reports"][0]["summary"]
    assert summary["anonymity"]["tor_exit"] is True


def test_sources_lists_phase4(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    assert main(["sources"]) == 0
    out = capsys.readouterr().out
    lines = {line.split("│")[1].strip(): line for line in out.splitlines() if line.count("│") > 3}
    assert "list not downloaded" in lines["tor"] and "ipfinder update-lists" in lines["tor"]
    assert "ready" in lines["internetdb"]
    for name in ("cloud-ranges", "private-relay", "vpn-lists"):
        assert name in lines
