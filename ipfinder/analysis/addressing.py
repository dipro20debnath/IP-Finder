"""Version-independent facts about an address: representations, IPv4 class, multicast."""

from __future__ import annotations

import ipaddress
import platform

from ipfinder.core.special_ranges import IPAddress, classify
from ipfinder.core.text import ipv6_exploded

IPV4_MULTICAST_BLOCKS = [
    # (prefix, name, rfc) - most specific first
    ("233.252.0.0/24", "MCAST-TEST-NET (documentation)", "RFC 6676"),
    ("224.0.0.0/24", "Local Network Control Block (never forwarded by routers)", "RFC 5771"),
    ("224.0.1.0/24", "Internetwork Control Block", "RFC 5771"),
    ("233.252.0.0/14", "AD-HOC Block III", "RFC 5771"),
    ("232.0.0.0/8", "Source-Specific Multicast (SSM)", "RFC 4607"),
    ("233.0.0.0/8", "GLOP Block (multicast range derived from a 16-bit AS number)", "RFC 3180"),
    ("234.0.0.0/8", "Unicast-Prefix-based IPv4 Multicast", "RFC 6034"),
    ("239.0.0.0/8", "Administratively Scoped (organisation-local)", "RFC 2365"),
]
_IPV4_MULTICAST_NETS = [
    (ipaddress.ip_network(prefix), name, rfc) for prefix, name, rfc in IPV4_MULTICAST_BLOCKS
]

IPV4_WELL_KNOWN_MULTICAST = {
    "224.0.0.1": "All Systems on this subnet",
    "224.0.0.2": "All Routers on this subnet",
    "224.0.0.5": "OSPF All Routers",
    "224.0.0.6": "OSPF Designated Routers",
    "224.0.0.9": "RIPv2 Routers",
    "224.0.0.18": "VRRP",
    "224.0.0.22": "IGMPv3",
    "224.0.0.251": "mDNS (Multicast DNS)",
    "224.0.0.252": "LLMNR",
    "224.0.1.1": "NTP",
    "239.255.255.250": "SSDP (UPnP discovery)",
}


def compressed(ip: IPAddress) -> str:
    """Canonical text form, identical on every Python version.

    IPv4-mapped IPv6 is written ``::ffff:a.b.c.d`` (RFC 5952 section 5). CPython's
    own output depends on the patch release: 3.12.3 prints ``::ffff:808:808``,
    while 3.10.20, 3.11.17 and 3.13+ print ``::ffff:8.8.8.8``.
    """
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return f"::ffff:{ip.ipv4_mapped}"
    return str(ip)


def _sixtofour_prefix(ip: ipaddress.IPv4Address) -> str | None:
    """2002:V4ADDR::/48 exists only for a globally unique IPv4 address (RFC 3056
    section 2; RFC 3964 section 5.3.1 lists the disallowed ranges)."""
    if classify(ip).globally_reachable is not True:
        return None
    return f"{ipaddress.IPv6Address((0x2002 << 112) | (int(ip) << 80))}/48"


def representations(ip: IPAddress) -> dict:
    value = int(ip)
    if ip.version == 4:
        return {
            "compressed": str(ip),
            "integer": value,
            "hex": f"0x{value:08x}",
            "binary": ".".join(f"{octet:08b}" for octet in ip.packed),
            "reverse_pointer": ip.reverse_pointer,
            "ipv4_mapped_ipv6": f"::ffff:{ip}",
            "sixtofour_prefix": _sixtofour_prefix(ip),
        }
    return {
        "compressed": compressed(ip),
        "exploded": ipv6_exploded(value),
        "integer": value,
        "hex": f"0x{value:032x}",
        "reverse_pointer": ip.reverse_pointer,
    }


def ipv4_class(ip: ipaddress.IPv4Address) -> dict:
    """Historic classful category (obsolete since CIDR, RFC 1519 in 1993; now RFC 4632)."""
    first = ip.packed[0]
    if first < 128:
        cls, mask = "A", 8
    elif first < 192:
        cls, mask = "B", 16
    elif first < 224:
        cls, mask = "C", 24
    elif first < 240:
        cls, mask = "D (multicast)", None
    else:
        cls, mask = "E (reserved)", None
    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False) if mask else None
    return {
        "class": cls,
        "classful_network": str(network) if network else None,
        "note": "Classful addressing is historic; the Internet has used CIDR since 1993",
    }


def ipv4_multicast(ip: ipaddress.IPv4Address) -> dict | None:
    if not ip.is_multicast:
        return None
    info: dict = {"block": "Multicast (other IANA block)", "rfc": "RFC 5771"}
    for net, name, rfc in _IPV4_MULTICAST_NETS:
        if ip in net:
            info = {"block": name, "rfc": rfc}
            break
    if info["rfc"] == "RFC 3180":
        octets = ip.packed
        info["glop_asn"] = octets[1] * 256 + octets[2]
    well_known = IPV4_WELL_KNOWN_MULTICAST.get(str(ip))
    if well_known:
        info["well_known"] = well_known
    return info


def python_flags(ip: IPAddress) -> dict:
    """What this Python's ``ipaddress`` module says (can differ between versions)."""
    flags = {
        name: getattr(ip, name)
        for name in (
            "is_global",
            "is_private",
            "is_reserved",
            "is_loopback",
            "is_link_local",
            "is_multicast",
            "is_unspecified",
        )
    }
    if ip.version == 6:
        flags["is_site_local"] = ip.is_site_local
    flags["python_version"] = platform.python_version()
    return flags
