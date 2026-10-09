"""IANA special-purpose address ranges, with the RFC that defines each one.

The tool keeps its own copy of these tables instead of relying on Python's
``ipaddress.is_global`` / ``is_private``, because those flags change between
Python patch releases (for example ``3fff::/20``, the IPv6 documentation prefix
from RFC 9637, is unknown to CPython 3.12.3 but known to 3.11.17 and 3.13).
With a fixed table every Python version gives the same answer.

Sources:
  * IANA IPv4 Special-Purpose Address Registry
    https://www.iana.org/assignments/iana-ipv4-special-registry/
  * IANA IPv6 Special-Purpose Address Registry
    https://www.iana.org/assignments/iana-ipv6-special-registry/
  * Address-architecture blocks that are not in those registries
    (multicast, deprecated site-local, IPv4-compatible, unallocated IPv6).

``globally_reachable`` mirrors the registry's "Globally Reachable" column:
True, False, or None where the registry says "N/A" (tunnel and deprecated blocks).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class SpecialRange:
    network: IPNetwork
    name: str
    category: str
    rfc: str
    globally_reachable: bool | None
    source: str = "IANA special-purpose registry"

    def to_dict(self) -> dict:
        return {
            "range": str(self.network),
            "name": self.name,
            "category": self.category,
            "rfc": self.rfc,
            "globally_reachable": self.globally_reachable,
            "source": self.source,
        }


ARCH = "address architecture"

# (prefix, name, category, rfc, globally_reachable[, source])
_IPV4_TABLE = [
    ("0.0.0.0/8", '"This network"', "this_network", "RFC 791", False),
    ("0.0.0.0/32", '"This host on this network"', "unspecified", "RFC 1122", False),
    ("10.0.0.0/8", "Private-Use", "private", "RFC 1918", False),
    ("100.64.0.0/10", "Shared Address Space (CGNAT)", "shared", "RFC 6598", False),
    ("127.0.0.0/8", "Loopback", "loopback", "RFC 1122", False),
    ("169.254.0.0/16", "Link Local", "link_local", "RFC 3927", False),
    ("172.16.0.0/12", "Private-Use", "private", "RFC 1918", False),
    ("192.0.0.0/24", "IETF Protocol Assignments", "protocol_assignment", "RFC 6890", False),
    ("192.0.0.0/29", "IPv4 Service Continuity Prefix", "protocol_assignment", "RFC 7335", False),
    ("192.0.0.8/32", "IPv4 dummy address", "protocol_assignment", "RFC 7600", False),
    ("192.0.0.9/32", "Port Control Protocol Anycast", "anycast", "RFC 7723", True),
    ("192.0.0.10/32", "Traversal Using Relays around NAT Anycast", "anycast", "RFC 8155", True),
    ("192.0.0.170/32", "NAT64/DNS64 Discovery", "translation", "RFC 8880", False),
    ("192.0.0.171/32", "NAT64/DNS64 Discovery", "translation", "RFC 8880", False),
    ("192.0.2.0/24", "Documentation (TEST-NET-1)", "documentation", "RFC 5737", False),
    ("192.31.196.0/24", "AS112-v4", "as112", "RFC 7535", True),
    ("192.52.193.0/24", "AMT", "amt", "RFC 7450", True),
    ("192.88.99.0/24", "Deprecated (6to4 Relay Anycast)", "deprecated", "RFC 7526", None),
    ("192.168.0.0/16", "Private-Use", "private", "RFC 1918", False),
    ("192.175.48.0/24", "Direct Delegation AS112 Service", "as112", "RFC 7534", True),
    ("198.18.0.0/15", "Benchmarking", "benchmarking", "RFC 2544", False),
    ("198.51.100.0/24", "Documentation (TEST-NET-2)", "documentation", "RFC 5737", False),
    ("203.0.113.0/24", "Documentation (TEST-NET-3)", "documentation", "RFC 5737", False),
    ("224.0.0.0/4", "Multicast", "multicast", "RFC 5771", None, ARCH),
    ("240.0.0.0/4", "Reserved", "reserved", "RFC 1112", False),
    ("255.255.255.255/32", "Limited Broadcast", "broadcast", "RFC 919", False),
]

_IPV6_TABLE = [
    ("::/128", "Unspecified Address", "unspecified", "RFC 4291", False),
    ("::1/128", "Loopback Address", "loopback", "RFC 4291", False),
    ("::/96", "IPv4-Compatible (deprecated)", "deprecated", "RFC 4291", False, ARCH),
    ("::ffff:0:0/96", "IPv4-mapped Address", "ipv4_mapped", "RFC 4291", False),
    (
        "64:ff9b::/96",
        "IPv4-IPv6 Translation (NAT64 well-known prefix)",
        "translation",
        "RFC 6052",
        True,
    ),
    ("64:ff9b:1::/48", "IPv4-IPv6 Translation (local-use)", "translation", "RFC 8215", False),
    ("100::/64", "Discard-Only Address Block", "discard", "RFC 6666", False),
    ("2001::/23", "IETF Protocol Assignments", "protocol_assignment", "RFC 2928", False),
    ("2001::/32", "Teredo", "tunnel", "RFC 4380", None),
    ("2001:1::1/128", "Port Control Protocol Anycast", "anycast", "RFC 7723", True),
    ("2001:1::2/128", "Traversal Using Relays around NAT Anycast", "anycast", "RFC 8155", True),
    ("2001:1::3/128", "DNS-SD Service Registration Protocol Anycast", "anycast", "RFC 9665", True),
    ("2001:2::/48", "Benchmarking", "benchmarking", "RFC 5180", False),
    ("2001:3::/32", "AMT", "amt", "RFC 7450", True),
    ("2001:4:112::/48", "AS112-v6", "as112", "RFC 7535", True),
    ("2001:10::/28", "Deprecated (previously ORCHID)", "deprecated", "RFC 4843", None),
    ("2001:20::/28", "ORCHIDv2", "orchid", "RFC 7343", True),
    ("2001:30::/28", "Drone Remote ID Protocol Entity Tags (DETs)", "drone_id", "RFC 9374", True),
    ("2001:db8::/32", "Documentation", "documentation", "RFC 3849", False),
    ("2002::/16", "6to4", "tunnel", "RFC 3056", None),
    ("2620:4f:8000::/48", "Direct Delegation AS112 Service", "as112", "RFC 7534", True),
    ("3fff::/20", "Documentation", "documentation", "RFC 9637", False),
    ("5f00::/16", "Segment Routing (SRv6) SIDs", "srv6", "RFC 9602", False),
    ("fc00::/7", "Unique-Local", "unique_local", "RFC 4193", False),
    ("fe80::/10", "Link-Local Unicast", "link_local", "RFC 4291", False),
    ("fec0::/10", "Site-Local (deprecated)", "deprecated", "RFC 3879", False, ARCH),
    ("ff00::/8", "Multicast", "multicast", "RFC 4291", None, ARCH),
]

IPV6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


def _build(table) -> tuple[SpecialRange, ...]:
    ranges = []
    for row in table:
        prefix, name, category, rfc, reachable, *rest = row
        ranges.append(
            SpecialRange(
                network=ipaddress.ip_network(prefix),
                name=name,
                category=category,
                rfc=rfc,
                globally_reachable=reachable,
                source=rest[0] if rest else "IANA special-purpose registry",
            )
        )
    # Most specific first, so the first match is the one that applies.
    return tuple(sorted(ranges, key=lambda r: r.network.prefixlen, reverse=True))


IPV4_SPECIAL = _build(_IPV4_TABLE)
IPV6_SPECIAL = _build(_IPV6_TABLE)

GLOBAL_UNICAST_V4 = SpecialRange(
    network=ipaddress.ip_network("0.0.0.0/0"),
    name="Public unicast (globally routable)",
    category="global_unicast",
    rfc="RFC 791",
    globally_reachable=True,
    source=ARCH,
)
GLOBAL_UNICAST_V6 = SpecialRange(
    network=IPV6_GLOBAL_UNICAST,
    name="Global Unicast",
    category="global_unicast",
    rfc="RFC 4291",
    globally_reachable=True,
    source=ARCH,
)
UNALLOCATED_V6 = SpecialRange(
    network=ipaddress.ip_network("::/0"),
    name="Reserved by IETF (outside 2000::/3 global unicast)",
    category="unallocated",
    rfc="RFC 4291",
    globally_reachable=False,
    source=ARCH,
)


@lru_cache(maxsize=4096)
def matching_ranges(ip: IPAddress) -> tuple[SpecialRange, ...]:
    """All special ranges containing ``ip``, most specific first."""
    table = IPV4_SPECIAL if ip.version == 4 else IPV6_SPECIAL
    return tuple(r for r in table if ip in r.network)


def classify(ip: IPAddress) -> SpecialRange:
    """The single range that decides how ``ip`` behaves (longest-prefix match)."""
    matches = matching_ranges(ip)
    if matches:
        return matches[0]
    if ip.version == 4:
        return GLOBAL_UNICAST_V4
    if ip in IPV6_GLOBAL_UNICAST:
        return GLOBAL_UNICAST_V6
    return UNALLOCATED_V6
