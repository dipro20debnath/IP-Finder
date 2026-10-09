"""Turn raw user input into a validated IP address, with helpful error messages.

Accepted forms:
  * IPv4 / IPv6 text:           8.8.8.8, 2001:4860:4860::8888
  * IPv6 with zone (scope) ID:  fe80::1%eth0
  * with a port:                8.8.8.8:53, [2001:db8::1]:443
  * inside a URL:               https://8.8.8.8/path
  * 32/128-bit integer form:    134744072  (= 8.8.8.8)
  * Bengali or other non-ASCII digits: ৮.৮.৮.৮  (normalised to 8.8.8.8)
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ipfinder.core.special_ranges import IPAddress

_DOTTED_QUAD = re.compile(r"\d+(?:\.\d+)*", re.ASCII)
_IPV4_WITH_PORT = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)", re.ASCII)
_BRACKETED = re.compile(r"\[([^\]]+)\](?::(\d+))?", re.ASCII)
_HOSTNAME_CHARS = re.compile(r"[A-Za-z0-9.-]+", re.ASCII)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class InvalidIPError(ValueError):
    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        return f"{self.message} ({self.hint})" if self.hint else self.message


@dataclass(frozen=True)
class ParsedInput:
    raw: str
    address: IPAddress  # always without the zone/scope ID
    input_format: str  # "ipv4" | "ipv6" | "integer"
    port: int | None = None
    scope_id: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


def _normalise_digits(text: str) -> str:
    """NFKC (full-width forms) plus any Unicode decimal digit -> ASCII digit."""
    text = unicodedata.normalize("NFKC", text)
    out = []
    for ch in text:
        if not ch.isascii() and unicodedata.category(ch) == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        else:
            out.append(ch)
    return "".join(out)


def _parse_port(text: str) -> int:
    port = int(text)
    if not 0 <= port <= 65535:
        raise InvalidIPError(f"Port {port} is out of range", "a port must be 0-65535")
    return port


def _is_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def _diagnose(text: str) -> InvalidIPError:
    """Explain *why* ``text`` is not an IP address."""
    if "/" in text and _is_network(text):
        return InvalidIPError(
            f"'{text}' is a network (CIDR), not a single address",
            "give one address, e.g. the first host of the range",
        )
    if _DOTTED_QUAD.fullmatch(text):
        parts = text.split(".")
        if len(parts) != 4:
            return InvalidIPError(
                f"'{text}' has {len(parts)} part(s); an IPv4 address needs exactly 4",
                "example: 8.8.8.8",
            )
        for part in parts:
            if int(part) > 255:
                return InvalidIPError(
                    f"Octet {part} in '{text}' is out of range", "each IPv4 part must be 0-255"
                )
        for part in parts:
            if len(part) > 1 and part.startswith("0"):
                return InvalidIPError(
                    f"Leading zero in octet '{part}' of '{text}' is ambiguous",
                    "some software reads it as octal (CVE-2021-29921); remove leading zeros",
                )
    if (
        _HOSTNAME_CHARS.fullmatch(text)
        and any(c.isalpha() for c in text)
        and not set(text.replace(":", "")) <= _HEX_DIGITS
    ):
        return InvalidIPError(
            f"'{text}' looks like a hostname, not an IP address",
            "DNS resolution arrives in Phase 3; for now look up the IP, e.g. with 'nslookup'",
        )
    return InvalidIPError(f"'{text}' is not a valid IPv4 or IPv6 address")


def parse_ip(raw: str) -> ParsedInput:
    """Validate ``raw`` and return a :class:`ParsedInput`, or raise :class:`InvalidIPError`."""
    if raw is None:
        raise InvalidIPError("No input given")
    notes: list[str] = []
    text = raw.strip()
    if not text:
        raise InvalidIPError("Empty input", "type an IP address such as 8.8.8.8")

    normalised = _normalise_digits(text)
    if normalised != text:
        notes.append(f"Normalised non-ASCII characters: '{text}' -> '{normalised}'")
        text = normalised

    port: int | None = None

    if "://" in text:
        try:
            parts = urlsplit(text)
            host = parts.hostname
            url_port = parts.port
        except ValueError as exc:
            raise InvalidIPError(f"Could not parse URL '{text}'", str(exc)) from exc
        if not host:
            raise InvalidIPError(f"No host found in URL '{text}'")
        notes.append(f"Extracted host from URL: {host}")
        text, port = host, url_port

    bracketed = _BRACKETED.fullmatch(text)
    if bracketed:
        text = bracketed.group(1)
        if bracketed.group(2) is not None:
            port = _parse_port(bracketed.group(2))
    else:
        with_port = _IPV4_WITH_PORT.fullmatch(text)
        if with_port:
            text, port = with_port.group(1), _parse_port(with_port.group(2))

    if text.isascii() and text.isdigit():
        value = int(text)
        if value <= 2**32 - 1:
            address: IPAddress = ipaddress.IPv4Address(value)
        elif value <= 2**128 - 1:
            address = ipaddress.IPv6Address(value)
        else:
            raise InvalidIPError(f"Integer {value} is larger than any IPv6 address (2^128 - 1)")
        notes.append(f"Interpreted integer {value} as {address}")
        return ParsedInput(raw, address, "integer", port, None, tuple(notes))

    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise _diagnose(text) from None

    scope_id = None
    if parsed.version == 6 and parsed.scope_id:
        scope_id = parsed.scope_id
        parsed = ipaddress.IPv6Address(text.split("%", 1)[0])
        notes.append(f"Zone (scope) ID '%{scope_id}' is local to one machine and was set aside")

    fmt = "ipv4" if parsed.version == 4 else "ipv6"
    return ParsedInput(raw, parsed, fmt, port, scope_id, tuple(notes))
