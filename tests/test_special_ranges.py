import pytest

from ipfinder.core.special_ranges import IPV4_SPECIAL, IPV6_SPECIAL, classify, matching_ranges
from tests.conftest import ip

# (address, category, rfc, globally_reachable)
CASES = [
    # --- IPv4 ---
    ("8.8.8.8", "global_unicast", "RFC 791", True),
    ("0.1.2.3", "this_network", "RFC 791", False),
    ("0.0.0.0", "unspecified", "RFC 1122", False),
    ("10.20.30.40", "private", "RFC 1918", False),
    ("172.16.0.1", "private", "RFC 1918", False),
    ("172.31.255.255", "private", "RFC 1918", False),
    ("172.32.0.1", "global_unicast", "RFC 791", True),
    ("192.168.1.10", "private", "RFC 1918", False),
    ("100.64.0.0", "shared", "RFC 6598", False),
    ("100.127.255.255", "shared", "RFC 6598", False),
    ("100.128.0.0", "global_unicast", "RFC 791", True),
    ("127.0.0.1", "loopback", "RFC 1122", False),
    ("169.254.169.254", "link_local", "RFC 3927", False),
    ("192.0.0.1", "protocol_assignment", "RFC 7335", False),
    ("192.0.0.8", "protocol_assignment", "RFC 7600", False),
    ("192.0.0.9", "anycast", "RFC 7723", True),
    ("192.0.0.10", "anycast", "RFC 8155", True),
    ("192.0.0.170", "translation", "RFC 8880", False),
    ("192.0.0.171", "translation", "RFC 8880", False),
    ("192.0.0.200", "protocol_assignment", "RFC 6890", False),
    ("192.0.2.1", "documentation", "RFC 5737", False),
    ("198.51.100.7", "documentation", "RFC 5737", False),
    ("203.0.113.5", "documentation", "RFC 5737", False),
    ("192.31.196.1", "as112", "RFC 7535", True),
    ("192.52.193.1", "amt", "RFC 7450", True),
    ("192.88.99.1", "deprecated", "RFC 7526", None),
    ("192.88.99.2", "anycast", "RFC 6751", False),
    ("192.175.48.6", "as112", "RFC 7534", True),
    ("198.18.0.1", "benchmarking", "RFC 2544", False),
    ("198.19.255.255", "benchmarking", "RFC 2544", False),
    ("198.20.0.0", "global_unicast", "RFC 791", True),
    ("224.0.0.251", "multicast", "RFC 5771", None),
    ("239.255.255.250", "multicast", "RFC 5771", None),
    ("240.0.0.1", "reserved", "RFC 1112", False),
    ("255.255.255.254", "reserved", "RFC 1112", False),
    ("255.255.255.255", "broadcast", "RFC 919", False),
    # --- IPv6 ---
    ("::", "unspecified", "RFC 4291", False),
    ("::1", "loopback", "RFC 4291", False),
    ("::808:808", "deprecated", "RFC 4291", False),
    ("::ffff:8.8.8.8", "ipv4_mapped", "RFC 4291", False),
    ("64:ff9b::808:808", "translation", "RFC 6052", True),
    ("64:ff9b:1::1", "translation", "RFC 8215", False),
    ("100::1", "discard", "RFC 6666", False),
    ("100:0:0:1::1", "dummy", "RFC 9780", False),
    ("100:0:0:2::1", "unallocated", "RFC 4291", False),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "tunnel", "RFC 4380", None),
    ("2001:1::1", "anycast", "RFC 7723", True),
    ("2001:1::2", "anycast", "RFC 8155", True),
    ("2001:1::3", "anycast", "RFC 9665", True),
    ("2001:1::4", "protocol_assignment", "RFC 2928", False),
    ("2001:2::1", "benchmarking", "RFC 5180", False),
    ("2001:3::1", "amt", "RFC 7450", True),
    ("2001:4:112::1", "as112", "RFC 7535", True),
    ("2001:10::1", "deprecated", "RFC 4843", None),
    ("2001:20::1", "orchid", "RFC 7343", True),
    ("2001:30::1", "drone_id", "RFC 9374", True),
    ("2001:1ff:ffff::1", "protocol_assignment", "RFC 2928", False),
    ("2001:200::1", "global_unicast", "RFC 4291", True),
    ("2001:db8::1", "documentation", "RFC 3849", False),
    ("2002:808:808::1", "tunnel", "RFC 3056", None),
    ("2620:4f:8000::1", "as112", "RFC 7534", True),
    ("3fff::1", "documentation", "RFC 9637", False),
    ("3fff:fff::1", "documentation", "RFC 9637", False),
    ("3fff:1000::1", "global_unicast", "RFC 4291", True),
    ("5f00::1", "srv6", "RFC 9602", False),
    ("fd12:3456::1", "unique_local", "RFC 4193", False),
    ("fe80::1", "link_local", "RFC 4291", False),
    ("fec0::1", "deprecated", "RFC 3879", False),
    ("ff02::1", "multicast", "RFC 4291", None),
    ("2001:4860:4860::8888", "global_unicast", "RFC 4291", True),
    ("2400:cb00::1", "global_unicast", "RFC 4291", True),
    ("4000::1", "unallocated", "RFC 4291", False),
]


@pytest.mark.parametrize("address,category,rfc,reachable", CASES)
def test_classify(address, category, rfc, reachable):
    result = classify(ip(address))
    assert (result.category, result.rfc, result.globally_reachable) == (category, rfc, reachable)


@pytest.mark.parametrize("table", [IPV4_SPECIAL, IPV6_SPECIAL])
def test_tables_are_most_specific_first(table):
    lengths = [r.network.prefixlen for r in table]
    assert lengths == sorted(lengths, reverse=True)


def test_matching_ranges_lists_every_containing_block():
    names = [r.name for r in matching_ranges(ip("2001:1::1"))]
    assert names == ["Port Control Protocol Anycast", "IETF Protocol Assignments"]


def test_global_unicast_has_no_special_match():
    assert matching_ranges(ip("8.8.8.8")) == ()


def test_to_dict_is_json_friendly():
    d = classify(ip("100.64.1.1")).to_dict()
    assert d == {
        "range": "100.64.0.0/10",
        "name": "Shared Address Space (CGNAT)",
        "category": "shared",
        "rfc": "RFC 6598",
        "globally_reachable": False,
        "source": "IANA special-purpose registry",
    }


def test_range_text_matches_iana_notation_on_every_python():
    # Python 3.13 would print ::ffff:0.0.0.0/96; IANA writes ::ffff:0:0/96.
    assert classify(ip("::ffff:8.8.8.8")).to_dict()["range"] == "::ffff:0:0/96"
    assert classify(ip("64:ff9b::808:808")).to_dict()["range"] == "64:ff9b::/96"
