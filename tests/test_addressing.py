import platform

import pytest

from ipfinder.analysis.addressing import (
    compressed,
    ipv4_class,
    ipv4_multicast,
    python_flags,
    representations,
)
from tests.conftest import ip


def test_ipv4_representations():
    assert representations(ip("8.8.8.8")) == {
        "compressed": "8.8.8.8",
        "integer": 134744072,
        "hex": "0x08080808",
        "binary": "00001000.00001000.00001000.00001000",
        "reverse_pointer": "8.8.8.8.in-addr.arpa",
        "ipv4_mapped_ipv6": "::ffff:8.8.8.8",
        "sixtofour_prefix": "2002:808:808::/48",
    }


def test_ipv4_representations_private():
    rep = representations(ip("192.168.1.10"))
    assert rep["integer"] == 3232235786
    assert rep["hex"] == "0xc0a8010a"
    assert rep["reverse_pointer"] == "10.1.168.192.in-addr.arpa"
    assert rep["sixtofour_prefix"] is None  # RFC 3056: needs a globally unique IPv4


def test_ipv6_representations():
    rep = representations(ip("2001:db8::1"))
    assert rep["compressed"] == "2001:db8::1"
    assert rep["exploded"] == "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert rep["hex"] == "0x20010db8000000000000000000000001"
    assert rep["reverse_pointer"].endswith(".8.b.d.0.1.0.0.2.ip6.arpa")


def test_ipv4_mapped_text_is_the_same_on_every_python():
    # CPython output depends on the patch release (3.12.3 prints ::ffff:808:808,
    # 3.10.20 / 3.11.17 / 3.13+ print ::ffff:8.8.8.8); IP Finder normalises it.
    rep = representations(ip("::ffff:8.8.8.8"))
    assert compressed(ip("::ffff:8.8.8.8")) == "::ffff:8.8.8.8"
    assert rep["compressed"] == "::ffff:8.8.8.8"
    assert rep["exploded"] == "0000:0000:0000:0000:0000:ffff:0808:0808"


@pytest.mark.parametrize(
    "address", ["10.0.0.1", "127.0.0.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "100.64.0.1"]
)
def test_no_6to4_prefix_for_non_global_ipv4(address):
    assert representations(ip(address))["sixtofour_prefix"] is None


@pytest.mark.parametrize(
    "address,cls,network",
    [
        ("10.0.0.1", "A", "10.0.0.0/8"),
        ("127.0.0.1", "A", "127.0.0.0/8"),
        ("172.16.5.4", "B", "172.16.0.0/16"),
        ("191.255.0.1", "B", "191.255.0.0/16"),
        ("192.168.1.1", "C", "192.168.1.0/24"),
        ("223.1.2.3", "C", "223.1.2.0/24"),
        ("224.0.0.1", "D (multicast)", None),
        ("250.1.1.1", "E (reserved)", None),
    ],
)
def test_ipv4_class(address, cls, network):
    info = ipv4_class(ip(address))
    assert info["class"] == cls
    assert info["classful_network"] == network


@pytest.mark.parametrize(
    "address,block_part,rfc",
    [
        ("224.0.0.251", "Local Network Control", "RFC 5771"),
        ("224.0.1.1", "Internetwork Control", "RFC 5771"),
        ("232.1.1.1", "Source-Specific Multicast", "RFC 4607"),
        ("233.252.0.1", "MCAST-TEST-NET", "RFC 6676"),
        ("233.253.0.1", "AD-HOC Block III", "RFC 5771"),
        ("234.1.2.3", "Unicast-Prefix-based", "RFC 6034"),
        ("239.255.255.250", "Administratively Scoped", "RFC 2365"),
        ("225.1.1.1", "other IANA block", "RFC 5771"),
    ],
)
def test_ipv4_multicast_blocks(address, block_part, rfc):
    info = ipv4_multicast(ip(address))
    assert block_part in info["block"]
    assert info["rfc"] == rfc


def test_glop_decodes_as_number():
    # RFC 3180 example: AS 5662 -> 233.22.30.0/24
    info = ipv4_multicast(ip("233.22.30.1"))
    assert info["glop_asn"] == 5662
    assert "glop_asn" not in ipv4_multicast(ip("233.252.0.1"))


def test_well_known_multicast_names():
    assert ipv4_multicast(ip("224.0.0.251"))["well_known"] == "mDNS (Multicast DNS)"
    assert "SSDP" in ipv4_multicast(ip("239.255.255.250"))["well_known"]


def test_non_multicast_returns_none():
    assert ipv4_multicast(ip("8.8.8.8")) is None


def test_python_flags():
    flags = python_flags(ip("fe80::1"))
    assert flags["is_link_local"] is True
    assert flags["is_site_local"] is False
    assert flags["python_version"] == platform.python_version()
    assert "is_site_local" not in python_flags(ip("10.0.0.1"))
