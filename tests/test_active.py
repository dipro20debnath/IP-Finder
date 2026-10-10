"""Phase 7: active probing. Nothing may be sent without --active and a confirmation.

Probes are tested against real local servers (TCP, and TLS with a test
certificate in tests/data/tls/). Ping and traceroute parsers are tested with
samples written in each tool's output format on Linux, macOS and Windows.
"""

import asyncio
import dataclasses
import ssl
import sys
from pathlib import Path

import pytest

from ipfinder.active import probes
from ipfinder.active.x509 import parse_certificate
from ipfinder.analysis.rtt import rtt_check
from ipfinder.cli import main
from ipfinder.providers.active import (
    RTTProvider,
    TLSCertProvider,
    TracerouteProvider,
    parse_location_setting,
)
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from tests.conftest import ASN_DB, CITY_DB, analyze_with, run
from tests.test_cli import FakeStdin

TLS_DIR = Path(__file__).parent / "data" / "tls"
CERT, KEY = TLS_DIR / "cert.pem", TLS_DIR / "key.pem"
LONDON = "51.5142,-0.0931"
DHAKA = "23.8103,90.4125"

LINUX_PING = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=11.2 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=10.4 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=12.0 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 10.4/11.2/12.0/0.65 ms
"""
MACOS_PING = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=9.874 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.112 ms
round-trip min/avg/max/stddev = 9.874/9.993/10.112/0.119 ms
"""
WINDOWS_PING = """Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=14ms TTL=117
Reply from 8.8.8.8: bytes=32 time<1ms TTL=117
Request timed out.

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 14ms, Average = 7ms
"""
WINDOWS_PING_DE = "Antwort von 8.8.8.8: Bytes=32 Zeit=12ms TTL=117\n"

LINUX_TRACEROUTE = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms
 2  *
 3  100.64.0.1  4.103 ms
 4  72.14.215.85  9.871 ms
 5  8.8.8.8  10.204 ms
"""
WINDOWS_TRACERT = """Tracing route to 8.8.8.8 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    11 ms    10 ms    12 ms  8.8.8.8

Trace complete.
"""
TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.420ms
 1:  192.168.1.1                                           0.391ms
 2:  no reply
 3:  8.8.8.8                                              10.120ms reached
     Resume: pmtu 1500 hops 3 back 3
"""


# ------------------------------------------------------------------ X.509


def test_parse_test_certificate():
    der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
    cert = parse_certificate(der)
    assert cert["subject"] == {"CN": "example.test", "O": "IP Finder Test"}
    assert cert["dns_names"] == ["example.test", "www.example.test"]
    assert cert["ip_addresses"] == ["192.0.2.10", "2001:db8::10"]
    assert cert["self_signed"] is True
    assert cert["not_after"].startswith("2126-")  # GeneralizedTime after 2049


@pytest.mark.skipif(
    not hasattr(__import__("_ssl"), "_test_decode_cert"), reason="CPython test helper missing"
)
def test_parser_agrees_with_cpython():
    import _ssl

    reference = _ssl._test_decode_cert(str(CERT))
    mine = parse_certificate(ssl.PEM_cert_to_DER_cert(CERT.read_text()))
    assert mine["serial"].upper().lstrip("0") == reference["serialNumber"].lstrip("0")
    assert [v for k, v in reference["subjectAltName"] if k == "DNS"] == mine["dns_names"]


@pytest.mark.parametrize("data", [b"", b"\x30", b"\x30\x05\x02\x01", b"\x04\x00", b"garbage" * 20])
def test_parser_rejects_malformed(data):
    with pytest.raises(ValueError):
        parse_certificate(data)


# ------------------------------------------------------------------ ping and traceroute


@pytest.mark.parametrize(
    "output, times",
    [
        (LINUX_PING, [11.2, 10.4, 12.0]),
        (MACOS_PING, [9.874, 10.112]),
        (WINDOWS_PING, [14.0, 1.0]),  # "<1ms" counts as 1 ms, an upper bound
        (WINDOWS_PING_DE, [12.0]),
        ("Request timed out.\nRequest timed out.\n", []),
    ],
)
def test_parse_ping(output, times):
    assert probes.parse_ping(output) == times


def test_commands_per_platform():
    assert probes.ping_command("8.8.8.8", "linux") == [
        "ping",
        "-n",
        "-c",
        "4",
        "-W",
        "2",
        "8.8.8.8",
    ]
    assert probes.ping_command("8.8.8.8", "darwin")[-3:] == ["-W", "2000", "8.8.8.8"]
    assert probes.ping_command("2001:db8::1", "darwin")[0] == "ping6"
    assert probes.ping_command("8.8.8.8", "win32") == ["ping", "-n", "4", "-w", "2000", "8.8.8.8"]
    assert [c[0] for c in probes.traceroute_commands("8.8.8.8", "linux")] == [
        "traceroute",
        "tracepath",
    ]
    assert probes.traceroute_commands("8.8.8.8", "win32")[0][:2] == ["tracert", "-d"]
    assert probes.traceroute_commands("2001:db8::1", "darwin")[0][0] == "traceroute6"


def test_parse_traceroute_formats():
    assert probes.parse_traceroute(LINUX_TRACEROUTE) == [
        {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 0.512},
        {"hop": 2, "ip": None, "rtt_ms": None},
        {"hop": 3, "ip": "100.64.0.1", "rtt_ms": 4.103},
        {"hop": 4, "ip": "72.14.215.85", "rtt_ms": 9.871},
        {"hop": 5, "ip": "8.8.8.8", "rtt_ms": 10.204},
    ]
    tracert = probes.parse_traceroute(WINDOWS_TRACERT)
    assert [h["ip"] for h in tracert] == ["192.168.1.1", None, "8.8.8.8"]
    assert tracert[0]["rtt_ms"] == 1.0 and tracert[2]["rtt_ms"] == 10.0
    tracepath = probes.parse_traceroute(TRACEPATH)
    assert [(h["hop"], h["ip"], h["rtt_ms"]) for h in tracepath] == [
        (1, "192.168.1.1", 0.42),
        (2, None, None),
        (3, "8.8.8.8", 10.12),
    ]


def test_run_command_missing_and_partial_output_on_timeout():
    assert run(probes.run_command(["no-such-command-ipfinder"], 1.0)) is None
    code, out = run(probes.run_command([sys.executable, "-c", "print('hello')"], 10.0))
    assert code == 0 and out.strip() == "hello"
    slow = "import time; print('first hop', flush=True); time.sleep(30)"
    code, out = run(probes.run_command([sys.executable, "-c", slow], 1.5))
    assert "first hop" in out and code != 0


# ---------------------------------------------------- TCP and TLS against local servers


def test_tcp_rtt_open_and_refused():
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            open_result = await probes.tcp_rtt("127.0.0.1", ports=(port,), samples=3)
        closed = await probes.tcp_rtt("127.0.0.1", ports=(port,), samples=2)  # server gone
        return open_result, closed

    open_result, closed = run(go())
    assert open_result["state"] == "open" and len(open_result["samples_ms"]) == 3
    assert 0 <= open_result["min_ms"] < 1000
    if sys.platform != "win32":
        assert closed["state"] == "refused"


def test_tls_certificate_from_local_server():
    async def go(cafile=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=context)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await probes.tls_certificate("127.0.0.1", port, timeout=5.0, cafile=cafile)

    cert = run(go())
    assert cert["dns_names"] == ["example.test", "www.example.test"]
    assert cert["trusted"] is False and "self" in cert["trust_error"].lower()
    assert cert["tls_version"].startswith("TLS") and len(cert["sha256"]) == 64
    assert run(go(cafile=str(CERT)))["trusted"] is True  # trusted once its CA is known


# ------------------------------------------------------------------ speed-of-light check


def vantage(location):
    lat, lon = parse_location_setting(location)
    return {"latitude": lat, "longitude": lon, "source": "IPFINDER_LOCATION", "uncertainty_km": 10}


def test_rtt_check_bounds():
    london = {"latitude": 51.5142, "longitude": -0.0931, "uncertainty_km": 10}
    near = rtt_check({"min_rtt_ms": 2.0, "vantage": vantage(LONDON)}, london)
    assert near["max_distance_km"] == 200 and near["plausible"] is True
    far = rtt_check({"min_rtt_ms": 5.0, "vantage": vantage(DHAKA)}, london)
    assert far["plausible"] is False and far["distance_km"] > 7900  # 5 ms allows 500 km
    slow = rtt_check({"min_rtt_ms": 180.0, "vantage": vantage(DHAKA)}, london)
    assert slow["plausible"] is True  # a long RTT proves nothing about distance
    assert rtt_check(None, london) is None
    unknown = rtt_check({"min_rtt_ms": 5.0, "vantage": {"error": "x"}}, london)
    assert unknown == {"rtt_ms": 5.0, "max_distance_km": 500.0, "checked": False, "reason": "x"}
    assert (
        rtt_check({"min_rtt_ms": 5.0, "vantage": vantage(DHAKA)}, {"country_code": "GB"})["reason"]
        == "no source gave coordinates for the address"
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        ("23.8103,90.4125", (23.8103, 90.4125)),
        (" -33.9, 151.2 ", (-33.9, 151.2)),
        ("91,0", None),
        ("x", None),
        ("1,2,3", None),
    ],
)
def test_location_setting(text, expected):
    assert parse_location_setting(text) == expected


# ------------------------------------------------------------------ providers with fake probes


@pytest.fixture
def fake_probes(monkeypatch):
    calls = []

    async def fake_tcp(target, ports=(443, 80), samples=4, timeout=2.0):
        calls.append(("tcp", target))
        return {"port": 443, "state": "open", "samples_ms": [2.4, 2.1], "min_ms": 2.1}

    async def fake_run(args, timeout):
        calls.append((args[0], args[-1]))
        if args[0] == "ping":
            return 0, LINUX_PING
        if args[0] == "traceroute":
            return 0, LINUX_TRACEROUTE.replace("8.8.8.8", args[-1])
        return None

    async def fake_tls(target, port=443, timeout=5.0, cafile=None):
        calls.append(("tls", target))
        cert = parse_certificate(ssl.PEM_cert_to_DER_cert(CERT.read_text()))
        cert.update(
            port=443,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            sha256="ab" * 32,
            trusted=False,
            trust_error="self-signed certificate",
        )
        return cert

    async def no_interception(port, timeout=2.0, host=probes.CANARY):
        return False

    monkeypatch.setattr(probes, "tcp_rtt", fake_tcp)
    monkeypatch.setattr(probes, "run_command", fake_run)
    monkeypatch.setattr(probes, "tls_certificate", fake_tls)
    monkeypatch.setattr(probes, "interception_check", no_interception)
    return calls


@pytest.fixture
def active_london(config):
    return dataclasses.replace(
        config, active_mode=True, my_location=LONDON, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB
    )


ACTIVE = [
    OfflineProvider(),
    MaxMindProvider(),
    RTTProvider(),
    TracerouteProvider(),
    TLSCertProvider(),
]


def test_active_providers_and_plausible_location(active_london, fake_probes, fake_dns):
    fake_dns.records["85.215.14.72.origin.asn.cymru.com"] = [
        "15169 | 72.14.192.0/18 | US | arin | 2004-11-10"
    ]
    report = analyze_with("81.2.69.142", active_london, ACTIVE)
    rtt = report.result("rtt").data
    assert rtt["min_rtt_ms"] == 2.1 and rtt["icmp"]["received"] == 3
    assert rtt["vantage"]["source"] == "IPFINDER_LOCATION"
    hops = report.result("traceroute").data["hops"]
    assert hops[0]["network"] == "private / reserved"
    assert hops[3]["asn"] == 15169 and hops[3]["country_code"] == "US"
    assert report.result("tls-cert").data["crt_sh"] == "https://crt.sh/?q=" + "ab" * 32
    check = report.verdict["rtt_check"]
    assert check["plausible"] is True and check["max_distance_km"] == 210  # 2.1 ms
    assert all(r["points"] != -30 for r in report.verdict["location_confidence"]["breakdown"])


def test_impossible_location_lowers_confidence(active_london, fake_probes):
    from_dhaka = dataclasses.replace(active_london, my_location=DHAKA)
    report = analyze_with(
        "81.2.69.142", from_dhaka, [OfflineProvider(), MaxMindProvider(), RTTProvider()]
    )
    check = report.verdict["rtt_check"]
    assert check["plausible"] is False
    assert "physically impossible" in check["meaning"]
    rules = report.verdict["location_confidence"]["breakdown"]
    assert {
        "reason": "measured round-trip time is impossible for this location",
        "points": -30,
    } in rules


def test_vantage_from_ip_api_when_not_configured(config, fake_probes, fake_api):
    fake_api.json(
        "GET",
        "http://ip-api.com/json/?fields",
        {"status": "success", "lat": 23.7104, "lon": 90.4074, "city": "Dhaka", "countryCode": "BD"},
    )
    active = dataclasses.replace(config, active_mode=True)
    data = analyze_with("8.8.8.8", active, [OfflineProvider(), RTTProvider()]).result("rtt").data
    assert data["vantage"] == {
        "latitude": 23.71,
        "longitude": 90.41,
        "city": "Dhaka",
        "country_code": "BD",
        "source": "ip-api (your public IP)",
        "uncertainty_km": 100,
    }


def test_provider_errors(config, monkeypatch):
    async def nothing(*args, **kwargs):
        return None

    async def refused(*args, **kwargs):
        raise ConnectionRefusedError

    async def no_interception(port, timeout=2.0, host=probes.CANARY):
        return False

    monkeypatch.setattr(probes, "tcp_rtt", nothing)
    monkeypatch.setattr(probes, "run_command", nothing)
    monkeypatch.setattr(probes, "tls_certificate", refused)
    monkeypatch.setattr(probes, "interception_check", no_interception)
    active = dataclasses.replace(config, active_mode=True)
    report = analyze_with(
        "8.8.8.8",
        active,
        [OfflineProvider(), RTTProvider(), TracerouteProvider(), TLSCertProvider()],
    )
    assert report.result("rtt").error == "no reply to TCP ports 443/80 or to ping"
    assert "is not installed" in report.result("traceroute").error
    assert report.result("tls-cert").error == "port 443 is closed"


# ------------------------------------------------------------------ the gate (Definition of Done)


@pytest.fixture
def forbidden(monkeypatch):
    """Any probe call fails the test: nothing may be sent."""

    async def boom(*args, **kwargs):
        raise AssertionError("an active probe ran without permission")

    for name in ("tcp_rtt", "run_command", "tls_certificate", "interception_check"):
        monkeypatch.setattr(probes, name, boom)


def test_never_runs_without_active(capsys, forbidden, monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeStdin("", tty=True))
    assert main(["lookup", "-f", "json", "--no-cache", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    for name in ("rtt", "traceroute", "tls-cert"):
        assert f'"provider": "{name}"' in out
    assert out.count("active probing is off (use --active") == 3


def test_active_needs_confirmation(capsys, forbidden, monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeStdin("8.8.8.8\n", tty=False))
    assert main(["lookup", "--active", "8.8.8.8"]) == 2
    assert "input is not a terminal" in capsys.readouterr().err
    monkeypatch.setattr("sys.stdin", FakeStdin("yes\n", tty=True))
    assert main(["lookup", "--active", "8.8.8.8"]) == 2
    err = capsys.readouterr().err
    assert "Only scan systems you own or have written permission to test." in err
    assert "Not confirmed. Nothing was sent." in err
    monkeypatch.setattr("sys.stdin", FakeStdin("", tty=True))
    assert main(["me", "--active"]) == 2


def test_active_limit(capsys, forbidden):
    ips = [f"8.8.{i}.1" for i in range(21)]
    assert main(["lookup", "--active", "--authorized", *ips]) == 2
    assert "at most 20 addresses" in capsys.readouterr().err


def test_active_after_confirmation(capsys, fake_probes, monkeypatch):
    monkeypatch.setenv("IPFINDER_LOCATION", "37.42,-122.08")
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr("sys.stdin", FakeStdin("I AM AUTHORIZED\n", tty=True))
    assert main(["lookup", "--active", "--no-color", "--no-cache", "8.8.8.8"]) == 0
    out = capsys.readouterr().out
    assert "Active probes (packets sent to the target)" in out
    assert "2.1 ms (port 443 open, best of 2)" in out and "10.4 ms (3 of 4 replies)" in out
    assert "Path (traceroute, reached the target)" in out
    assert "example.test, www.example.test" in out
    assert ("tcp", "8.8.8.8") in fake_probes and ("tls", "8.8.8.8") in fake_probes

    fake_probes.clear()
    assert main(["lookup", "--active", "--authorized", "-f", "json", "--no-cache", "8.8.8.8"]) == 0
    assert ("tcp", "8.8.8.8") in fake_probes


def test_private_targets_are_not_probed(capsys, forbidden):
    assert (
        main(["lookup", "--active", "--authorized", "-f", "json", "--no-cache", "192.168.1.1"]) == 0
    )
    assert capsys.readouterr().out.count("address is not globally reachable") >= 3


# ---------------------------------------------------- interception (transparent proxies)


def test_interception_check_against_local_servers(monkeypatch):
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            answered = await probes.interception_check(port, host="127.0.0.1")
        refused = await probes.interception_check(port, host="127.0.0.1")
        return answered, refused

    answered, refused = run(go())
    assert answered is True  # something answered for an address that should not
    if sys.platform != "win32":
        assert refused is True  # a non-existent host cannot refuse either

    async def unreachable(*args, **kwargs):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(asyncio, "open_connection", unreachable)
    assert run(probes.interception_check(443)) is False


def test_intercepted_network_discards_tcp_and_tls(config, fake_probes, monkeypatch):
    async def intercepted(port, timeout=2.0, host=probes.CANARY):
        return True

    monkeypatch.setattr(probes, "interception_check", intercepted)
    active = dataclasses.replace(config, active_mode=True, my_location=LONDON)
    report = analyze_with("8.8.8.8", active, [OfflineProvider(), RTTProvider(), TLSCertProvider()])
    rtt = report.result("rtt").data
    assert "answers TCP port 443 itself" in rtt["tcp"]["error"]
    assert rtt["min_rtt_ms"] == 10.4  # ping only
    error = report.result("tls-cert").error
    assert (
        "the certificate would be the proxy's" in error
        or "any certificate would be the proxy's" in error
    )

    async def no_ping(args, timeout):
        return 0, "Request timed out.\n"

    monkeypatch.setattr(probes, "run_command", no_ping)
    report = analyze_with("8.8.8.8", active, [OfflineProvider(), RTTProvider()])
    assert "round trip cannot be measured" in report.result("rtt").error
