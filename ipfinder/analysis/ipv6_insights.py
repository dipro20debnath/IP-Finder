"""Information hidden inside an IPv6 address.

* embedded IPv4 (IPv4-mapped, NAT64, 6to4, Teredo)
* structure (/32, /48, /56, /64 prefixes and the 64-bit interface ID)
* interface-ID type (EUI-64 -> MAC address, ISATAP, anycast, manual, random)
* multicast scope, flags and well-known groups
"""

from __future__ import annotations

import ipaddress

from ipfinder.core.special_ranges import classify

NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
TEREDO = ipaddress.ip_network("2001::/32")
SIXTOFOUR = ipaddress.ip_network("2002::/16")
IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
STARTS_WITH_000 = ipaddress.ip_network("::/3")

MULTICAST_SCOPES = {
    0x0: "Reserved",
    0x1: "Interface-Local",
    0x2: "Link-Local",
    0x3: "Realm-Local",
    0x4: "Admin-Local",
    0x5: "Site-Local",
    0x8: "Organization-Local",
    0xE: "Global",
    0xF: "Reserved",
}

IPV6_WELL_KNOWN_MULTICAST = {
    "ff01::1": "All Nodes (interface-local)",
    "ff01::2": "All Routers (interface-local)",
    "ff02::1": "All Nodes on the link",
    "ff02::2": "All Routers on the link",
    "ff02::5": "OSPFv3 All SPF Routers",
    "ff02::6": "OSPFv3 All DR Routers",
    "ff02::9": "RIPng Routers",
    "ff02::d": "All PIM Routers",
    "ff02::16": "MLDv2-capable Routers",
    "ff02::fb": "mDNS (Multicast DNS)",
    "ff02::1:2": "All DHCP Relay Agents and Servers",
    "ff02::1:3": "LLMNR",
    "ff05::2": "All Routers (site-local)",
    "ff05::1:3": "All DHCP Servers (site-local)",
    "ff05::101": "All NTP Servers (site-local)",
}
SOLICITED_NODE = ipaddress.ip_network("ff02::1:ff00:0/104")

TEREDO_CONE_BIT = 0x8000
TEREDO_RANDOM_BITS = 0x3CFF  # the 12 "A" bits of CRAAAAUG AAAAAAAA (RFC 5991)

# IANA "Reserved IPv6 Interface Identifiers" registry (RFC 5453) entries that look
# like Modified EUI-64 (built from the IANA Ethernet block 00-00-5E).
_RESERVED_IID_PMIPV6 = 0x02005EFFFE005213  # Proxy Mobile IPv6, RFC 6543
_RESERVED_IID_BLOCK = (0x02005EFFFE000000, 0x02005EFFFEFFFFFF)  # RFC 4291 / RFC 5453


def _embedded_entry(kind: str, v4: ipaddress.IPv4Address, rfc: str, **detail) -> dict:
    cls = classify(v4)
    return {
        "kind": kind,
        "address": str(v4),
        "rfc": rfc,
        "category": cls.category,
        "globally_reachable": cls.globally_reachable,
        **detail,
    }


def embedded_ipv4(ip: ipaddress.IPv6Address) -> list[dict]:
    """IPv4 addresses carried inside an IPv6 address, in lookup-priority order."""
    found: list[dict] = []
    value = int(ip)
    if ip in IPV4_MAPPED:
        found.append(_embedded_entry("ipv4_mapped", ip.ipv4_mapped, "RFC 4291"))
    if ip in NAT64_WKP:
        v4 = ipaddress.IPv4Address(value & 0xFFFFFFFF)
        found.append(_embedded_entry("nat64", v4, "RFC 6052"))
    if ip in SIXTOFOUR:
        found.append(
            _embedded_entry("6to4", ip.sixtofour, "RFC 3056", role="6to4 router's public IPv4")
        )
    if ip in TEREDO:
        server, client = ip.teredo
        flags = (value >> 48) & 0xFFFF
        port = ((value >> 32) & 0xFFFF) ^ 0xFFFF
        found.append(
            _embedded_entry(
                "teredo_client",
                client,
                "RFC 4380, RFC 5991",
                role="client's public (NAT) IPv4",
                client_port=port,
                flags=f"0x{flags:04x}",
                cone_bit=bool(flags & TEREDO_CONE_BIT),
                random_flag_bits=bool(flags & TEREDO_RANDOM_BITS),
                flags_note=(
                    "Flags layout CRAAAAUG AAAAAAAA. RFC 5991 deprecated the cone bit (C), so "
                    "C=0 does not mean the client is not behind a cone NAT; non-zero A bits "
                    "mean an RFC 5991 client that randomises its address"
                ),
            )
        )
        found.append(_embedded_entry("teredo_server", server, "RFC 4380", role="Teredo server"))
    return found


def structure(ip: ipaddress.IPv6Address) -> dict:
    iid = int(ip) & 0xFFFFFFFFFFFFFFFF
    groups = [(iid >> shift) & 0xFFFF for shift in (48, 32, 16, 0)]
    return {
        "prefix_32": str(ipaddress.ip_network(f"{ip}/32", strict=False)),
        "prefix_48": str(ipaddress.ip_network(f"{ip}/48", strict=False)),
        "prefix_56": str(ipaddress.ip_network(f"{ip}/56", strict=False)),
        "subnet_64": str(ipaddress.ip_network(f"{ip}/64", strict=False)),
        "interface_id": ":".join(f"{g:04x}" for g in groups),
        "note": "ISPs commonly assign a /48 or /56 to a site and a /64 to each LAN",
    }


def _has_interface_id(ip: ipaddress.IPv6Address) -> bool:
    """RFC 4291 section 2.5.1: unicast addresses need a 64-bit interface ID, except
    those starting with binary 000 (::, ::1, IPv4-mapped, NAT64, discard-only...)."""
    return not (
        ip.is_multicast
        or ip in STARTS_WITH_000
        or ip in TEREDO  # Teredo's low 64 bits are flags, port and client IPv4
    )


def interface_id(ip: ipaddress.IPv6Address, oui_lookup=None) -> dict | None:
    """Classify the 64-bit interface identifier. ``oui_lookup(mac) -> vendor | None``."""
    if not _has_interface_id(ip):
        return None
    iid = ip.packed[8:]
    value = int.from_bytes(iid, "big")

    if value == 0:
        return {
            "type": "subnet_router_anycast",
            "description": "All-zero interface ID: Subnet-Router anycast address",
            "rfc": "RFC 4291",
        }

    if _RESERVED_IID_BLOCK[0] <= value <= _RESERVED_IID_BLOCK[1]:
        if value == _RESERVED_IID_PMIPV6:
            name, rfc = "Proxy Mobile IPv6 (shared by every Mobile Access Gateway)", "RFC 6543"
        else:
            name, rfc = "reserved, IANA Ethernet block 00-00-5E", "RFC 4291, RFC 5453"
        return {
            "type": "reserved_iid",
            "description": f"IANA-reserved interface ID: {name}; not a device's own MAC",
            "rfc": rfc,
        }

    if iid[3:5] == b"\xff\xfe" and iid[0] & 0x01:
        return {
            "type": "eui64_pattern_group_bit",
            "description": (
                "Has the ff:fe EUI-64 marker but the g (individual/group) bit is set, so it "
                "was not built from a device's own (individual) MAC address"
            ),
            "rfc": "RFC 4291 Appendix A, RFC 7136",
        }

    if iid[3:5] == b"\xff\xfe":
        mac_bytes = bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:8]
        mac = ":".join(f"{b:02x}" for b in mac_bytes)
        universal = not (mac_bytes[0] & 0x02)
        info = {
            "type": "eui64",
            "description": "Modified EUI-64: the interface ID was built from the device's MAC",
            "rfc": "RFC 4291 Appendix A",
            "mac": mac,
            "mac_universally_administered": universal,
            "oui": mac[:8],
            "vendor": None,
            "confidence": "high (a random ID matches this pattern by chance 1 in 65,536)",
            "privacy": "This MAC can identify and track the same device across networks",
        }
        if not universal:
            info["vendor_note"] = (
                "Locally administered (randomised or virtual) MAC: no manufacturer registered"
            )
        elif oui_lookup is not None:
            info["vendor"] = oui_lookup(mac)
        return info

    if iid[1:4] == b"\x00\x5e\xfe" and iid[0] in (0x00, 0x02):
        v4 = ipaddress.IPv4Address(iid[4:8])
        return {
            "type": "isatap",
            "description": "ISATAP tunnel: the interface ID carries the host's IPv4 address",
            "rfc": "RFC 5214",
            "ipv4": str(v4),
            "ipv4_globally_unique_flag": bool(iid[0] & 0x02),
        }

    if iid[0] == 0xFD and iid[1:7] == b"\xff\xff\xff\xff\xff\xff" and iid[7] >= 0x80:
        anycast_id = iid[7] & 0x7F
        name = "Mobile IPv6 Home-Agents anycast" if anycast_id == 0x7E else "reserved"
        return {
            "type": "reserved_subnet_anycast",
            "description": f"Reserved subnet anycast ID {anycast_id} ({name})",
            "rfc": "RFC 2526",
        }

    if value <= 0xFFFF:
        return {
            "type": "low_byte",
            "description": "Small, manually assigned interface ID (typical for servers/routers)",
        }

    # 0x01000000 and up: an IPv4 in 0.0.0.0/8 ("this network") is never a host address.
    if value >> 32 == 0 and value >= 0x01000000:
        return {
            "type": "possible_embedded_ipv4",
            "description": "Upper 32 bits are zero; the lower 32 bits may be an IPv4 address",
            "ipv4": str(ipaddress.IPv4Address(value & 0xFFFFFFFF)),
            "confidence": "low (heuristic)",
        }

    non_zero_groups = sum(1 for i in range(0, 8, 2) if iid[i : i + 2] != b"\x00\x00")
    if non_zero_groups <= 2:
        return {
            "type": "manual",
            "description": (
                "Mostly-zero interface ID: likely manually or DHCPv6 assigned "
                "(servers, routers, address pools)"
            ),
            "confidence": "low (heuristic)",
        }

    return {
        "type": "opaque",
        "description": (
            "No recognised structure: may be a temporary (RFC 8981), stable-private "
            "(RFC 7217), DHCPv6-assigned or hand-picked ID; no hardware information "
            "can be derived"
        ),
    }


def multicast(ip: ipaddress.IPv6Address) -> dict | None:
    if not ip.is_multicast:
        return None
    second = ip.packed[1]
    flags, scope = second >> 4, second & 0x0F
    info: dict = {
        "scope": MULTICAST_SCOPES.get(scope, f"Unassigned ({scope:x})"),
        "scope_value": scope,
        "flags": {
            "transient": bool(flags & 0x1),  # T: not a permanently IANA-assigned group
            "prefix_based": bool(flags & 0x2),  # P: RFC 3306
            "embedded_rp": bool(flags & 0x4),  # R: RFC 3956
        },
        "rfc": "RFC 4291, RFC 7346",
    }
    key = str(ip)
    if key in IPV6_WELL_KNOWN_MULTICAST:
        info["well_known"] = IPV6_WELL_KNOWN_MULTICAST[key]
    elif ip in SOLICITED_NODE:
        low24 = int(ip) & 0xFFFFFF
        info["well_known"] = (
            "Solicited-Node (Neighbor Discovery) group for unicast addresses ending in "
            f"..{low24 >> 16:02x}:{low24 & 0xFFFF:04x}"
        )
    return info


def insights(ip: ipaddress.IPv6Address, oui_lookup=None) -> dict:
    return {
        # Prefix sizes only describe routed unicast space with a real interface ID;
        # for link-local, Teredo, multicast and ::/3 blocks they would mislead.
        "structure": structure(ip) if _has_interface_id(ip) and not ip.is_link_local else None,
        "embedded_ipv4": embedded_ipv4(ip),
        "interface_id": interface_id(ip, oui_lookup),
        "multicast": multicast(ip),
    }
