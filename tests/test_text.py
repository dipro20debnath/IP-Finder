import ipaddress
import random

import pytest

from ipfinder.core.text import display_safe, ipv6_exploded, ipv6_hex_compressed, network_text


def test_rfc5952_compression_matches_python_for_non_mapped_addresses():
    rng = random.Random(5952)
    for _ in range(5000):
        groups = [rng.choice([0, 0, 0, 1, 0xFFFF, rng.randrange(65536)]) for _ in range(8)]
        value = 0
        for g in groups:
            value = (value << 16) | g
        address = ipaddress.IPv6Address(value)
        if address.ipv4_mapped is None:
            assert ipv6_hex_compressed(value) == str(address)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("::", "::"),
        ("::1", "::1"),
        ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),  # single 0 group is not '::'
        ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"),  # longest run wins
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),  # first of equal runs
        ("::ffff:8.8.8.8", "::ffff:808:808"),
    ],
)
def test_rfc5952_examples(text, expected):
    assert ipv6_hex_compressed(int(ipaddress.IPv6Address(text))) == expected


def test_exploded_and_network_text():
    assert ipv6_exploded(1) == "0000:0000:0000:0000:0000:0000:0000:0001"
    assert network_text(ipaddress.ip_network("::ffff:0:0/96")) == "::ffff:0:0/96"
    assert network_text(ipaddress.ip_network("10.0.0.0/8")) == "10.0.0.0/8"


def test_display_safe():
    assert display_safe("\x1b[31m") == "\\x1b[31m"
    assert display_safe("a\u200bb") == "a\\u200bb"
    assert display_safe("\ufeff1") == "\\ufeff1"
    assert display_safe("৮.৮ ok") == "৮.৮ ok"
