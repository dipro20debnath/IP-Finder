"""Text helpers that give the same output on every Python version, and safe display
of untrusted input.

CPython's text form of IPv4-mapped IPv6 addresses depends on the patch release
(e.g. 3.12.3 prints ``::ffff:808:808``, 3.10.20 / 3.11.17 / 3.13+ print
``::ffff:8.8.8.8``), so network and exploded forms are built here from integers.
"""

from __future__ import annotations

import ipaddress


def _groups(value: int) -> list[int]:
    return [(value >> shift) & 0xFFFF for shift in range(112, -1, -16)]


def ipv6_hex_compressed(value: int) -> str:
    """RFC 5952 text (lowercase, longest zero run as '::', no dotted IPv4 part)."""
    groups = _groups(value)
    best_start, best_len, start = -1, 0, None
    for i, g in enumerate(groups + [1]):  # sentinel closes a trailing run
        if g == 0 and i < 8:
            start = i if start is None else start
        elif start is not None:
            if i - start > best_len:
                best_start, best_len = start, i - start
            start = None
    parts = [f"{g:x}" for g in groups]
    if best_len < 2:  # RFC 5952 4.2.2: '::' must not shorten a single 16-bit 0 field
        return ":".join(parts)
    left = ":".join(parts[:best_start])
    right = ":".join(parts[best_start + best_len :])
    return f"{left}::{right}"


def ipv6_exploded(value: int) -> str:
    return ":".join(f"{g:04x}" for g in _groups(value))


def network_text(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Network in registry notation, e.g. '::ffff:0:0/96' on every Python version."""
    if network.version == 4:
        return str(network)
    return f"{ipv6_hex_compressed(int(network.network_address))}/{network.prefixlen}"


def display_safe(text: str) -> str:
    """Escape control and invisible format characters (ESC, BOM, zero-width...) so
    untrusted input can never drive the terminal; normal letters (e.g. Bengali) stay."""
    out = []
    for ch in text:
        if ch.isprintable() or ch == " ":
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) <= 0xFFFF:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    return "".join(out)
