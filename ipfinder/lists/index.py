"""Longest-prefix lookup over many CIDR blocks.

Blocks are kept in one hash table per (IP version, prefix length), keyed by the
network bits, so a lookup costs one dictionary probe per prefix length present.
Parsing uses ``socket.inet_pton`` (about 5x faster than ``ipaddress``), which
matters for lists with hundreds of thousands of entries such as Private Relay.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

from ipfinder.core.text import network_text

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Strict dotted quad: no leading zeros (octal on some systems), exactly four parts.
_IPV4 = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")
_BITS = {4: 32, 6: 128}


def _split(text: str) -> tuple[int, int, int] | None:
    """'192.0.2.0/24' -> (4, 24, network bits as int); None if malformed."""
    addr, slash, length = text.strip().partition("/")
    try:
        if ":" in addr:
            version, bits, packed = 6, 128, socket.inet_pton(socket.AF_INET6, addr)
        elif _IPV4.fullmatch(addr):
            version, bits, packed = 4, 32, socket.inet_pton(socket.AF_INET, addr)
        else:
            return None
    except (OSError, ValueError):
        return None
    if slash:
        if not (length.isdigit() and len(length) <= 3):
            return None
        prefixlen = int(length)
        if prefixlen > bits:
            return None
    else:
        prefixlen = bits
    return version, prefixlen, int.from_bytes(packed, "big") >> (bits - prefixlen)


def parse_cidr(text: str) -> tuple[int, int, int] | None:
    """'192.0.2.0/24' -> (4, network int, 24); a bare address is a /32 or /128.
    Host bits are cleared. Returns None for anything malformed."""
    parsed = _split(text)
    if parsed is None:
        return None
    version, prefixlen, key = parsed
    return version, key << (_BITS[version] - prefixlen), prefixlen


class PrefixIndex:
    def __init__(self) -> None:
        self._tables: dict[tuple[int, int], dict[int, list[Any]]] = {}
        self.count = 0
        self.versions: set[int] = set()

    def add(self, cidr: str, value: Any = None) -> bool:
        return self.add_many(((cidr, value),)) == 1

    def add_many(self, items) -> int:
        """Add (cidr, value) pairs; malformed blocks are skipped. Returns how many were
        added. One loop with local names, because big lists have 10^5+ entries."""
        tables = self._tables
        split = _split
        added = 0
        for cidr, value in items:
            parsed = split(cidr)
            if parsed is None:
                continue
            version, prefixlen, key = parsed
            table = tables.get((version, prefixlen))
            if table is None:
                table = tables[(version, prefixlen)] = {}
                self.versions.add(version)
            bucket = table.get(key)
            if bucket is None:
                table[key] = [value]
            else:
                bucket.append(value)
            added += 1
        self.count += added
        return added

    def lookup(self, address: str) -> list[tuple[str, list[Any]]]:
        """Every block containing ``address``, most specific first:
        [("192.0.2.0/24", [values...]), ...]."""
        ip = ipaddress.ip_address(address)
        bits = _BITS[ip.version]
        value = int(ip)
        lengths = sorted((p for v, p in self._tables if v == ip.version), reverse=True)
        found = []
        for prefixlen in lengths:
            key = value >> (bits - prefixlen)
            hit = self._tables[(ip.version, prefixlen)].get(key)
            if hit is not None:
                network = ipaddress.ip_network((key << (bits - prefixlen), prefixlen))
                found.append((network_text(network), hit))
        return found

    def longest(self, address: str) -> tuple[str, list[Any]] | None:
        found = self.lookup(address)
        return found[0] if found else None
