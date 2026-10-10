"""Turn raw user input into a validated IP address, with helpful error messages.

Accepted forms:
  * IPv4 / IPv6 text:           8.8.8.8, 2001:4860:4860::8888
  * IPv6 with zone (scope) ID:  fe80::1%eth0
  * with a port:                8.8.8.8:53, [2001:db8::1]:443
  * inside a URL:               https://8.8.8.8/path
  * 32/128-bit integer form:    134744072  (= 8.8.8.8)
  * Bengali or other non-ASCII digits: ৮.৮.৮.৮  (normalised to 8.8.8.8)

Rejected with an explanation: CIDR networks, hostnames, and the ambiguous
inet_aton-style IPv4 forms (leading zeros, hex, shorthand) that different
software reads as different addresses (CVE-2021-29921).

Every message that repeats the input passes it through ``display_safe`` so
control characters (e.g. terminal escape sequences) are shown, not executed.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ipfinder.core.special_ranges import IPAddress
from ipfinder.core.text import display_safe

MAX_INPUT_LENGTH = 2048  # generous for a URL; anything longer is not an address

_DOTTED_DECIMAL = re.compile(r"\d+(?:\.\d+)*", re.ASCII)
_IPV4_WITH_PORT = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)", re.ASCII)
_BRACKETED = re.compile(r"\[([^\]]+)\](?::(\d+))?", re.ASCII)
_HOSTNAME_CHARS = re.compile(r"[A-Za-z0-9.-]+", re.ASCII)
_INET_ATON_PART = re.compile(r"0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*", re.ASCII)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
# WHATWG URL Standard "special" schemes: '\' is treated like '/' in these.
_SPECIAL_SCHEMES = frozenset({"http", "https", "ftp", "ws", "wss", "file"})


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
    # Bound the length first: int() of a huge digit string is slow and, past
    # 4300 digits, raises a plain ValueError on Python 3.10.7+.
    port = int(text) if len(text.lstrip("0")) <= 5 else 65536
    if not 0 <= port <= 65535:
        raise InvalidIPError(
            f"Port '{display_safe(text[:20])}' is out of range", "a port must be 0-65535"
        )
    return port


def _is_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def inet_aton(text: str) -> ipaddress.IPv4Address | None:
    """How glibc ``inet_aton`` reads ``text`` (tested against it): 1-4 dot-separated
    parts, each decimal, 0-prefixed octal or 0x-prefixed hex, the last part filling
    the remaining bytes. Returns None if it is not that form. Browsers (WHATWG URL
    parser) read the same forms, differing only in corner cases such as a bare "0x"."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        if not part or not _INET_ATON_PART.fullmatch(part):
            return None
        digits = part[2:] if part[:2] in ("0x", "0X") else part
        if len(digits.lstrip("0")) > 12:  # far beyond 32 bits; skip a costly int()
            return None
        if part[:2] in ("0x", "0X"):
            values.append(int(part[2:], 16))
        elif len(part) > 1 and part[0] == "0":
            values.append(int(part, 8))
        else:
            values.append(int(part))
    *head, last = values
    if any(v > 255 for v in head) or last >= 1 << (8 * (4 - len(head))):
        return None
    value = 0
    for v in head:
        value = (value << 8) | v
    return ipaddress.IPv4Address((value << (8 * (4 - len(head)))) | last)


def _diagnose(text: str) -> InvalidIPError:
    """Explain *why* ``text`` is not an IP address."""
    shown = display_safe(text)
    if "/" in text and _is_network(text):
        return InvalidIPError(
            f"'{shown}' is a network (CIDR), not a single address",
            "give one address, e.g. the first host of the range",
        )
    aton = inet_aton(text)
    if _DOTTED_DECIMAL.fullmatch(text):
        parts = text.split(".")
        if len(parts) != 4:
            hint = "example: 8.8.8.8"
            if aton:
                hint = f"inet_aton-style software would silently read it as {aton}; {hint}"
            return InvalidIPError(
                f"'{shown}' has {len(parts)} part(s); an IPv4 address needs exactly 4", hint
            )
        for part in parts:
            # bounded int(): zero padding does not count towards the size
            value = int(part) if len(part.lstrip("0")) <= 12 else None
            if value is None or value > 255:
                return InvalidIPError(
                    f"Octet {display_safe(part[:20])} in '{shown}' is out of range",
                    "each IPv4 part must be 0-255",
                )
        for part in parts:
            if len(part) > 1 and part.startswith("0"):
                reading = f"e.g. inet_aton reads it as {aton}" if aton else "or rejects it"
                return InvalidIPError(
                    f"Leading zero in octet '{part}' of '{shown}' is ambiguous",
                    f"some software reads it as octal ({reading}; CVE-2021-29921); "
                    "remove leading zeros",
                )
    if aton:
        return InvalidIPError(
            f"'{shown}' is a non-standard (hex/octal/shorthand) IPv4 form",
            f"inet_aton-style software reads it as {aton}; write it as dotted decimal",
        )
    if (
        _HOSTNAME_CHARS.fullmatch(text)
        and any(c.isalpha() for c in text)
        and not set(text.replace(":", "")) <= _HEX_DIGITS
    ):
        return InvalidIPError(
            f"'{shown}' looks like a hostname, not an IP address",
            "IP Finder takes IP addresses only; find the name's address first, "
            "e.g. with 'nslookup'",
        )
    return InvalidIPError(f"'{shown}' is not a valid IPv4 or IPv6 address")


_C0_AND_SPACE = "".join(chr(i) for i in range(0x21))


def _from_url(text: str, notes: list[str]) -> tuple[str, int | None]:
    # WHATWG URL Standard preprocessing, the same as browsers: strip leading and
    # trailing C0 controls/spaces and remove every tab and newline. Without it,
    # "ht\ttp://1.1.1.1\\@8.8.8.8/" would hide the special scheme below.
    cleaned = text.strip(_C0_AND_SPACE).replace("\t", "").replace("\n", "").replace("\r", "")
    if cleaned != text:
        notes.append("Removed control characters, tabs or newlines from the URL, as browsers do")
        text = cleaned
    scheme = text.split("://", 1)[0].lower()
    if "\\" in text and scheme in _SPECIAL_SCHEMES:
        # Browsers end the host at '\' for http(s) etc.; urlsplit would not, and
        # "http://1.1.1.1\@8.8.8.8/" would then wrongly resolve to 8.8.8.8.
        text = text.replace("\\", "/")
        notes.append("Treated '\\' as '/' in the URL, as browsers do (WHATWG URL Standard)")
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError as exc:
        raise InvalidIPError(f"Could not parse URL '{display_safe(text)}'", str(exc)) from exc
    if not host:
        raise InvalidIPError(f"No host found in URL '{display_safe(text)}'")
    if "@" in parts.netloc:
        notes.append("URL contains user-info before '@'; only the part after '@' is the host")
    notes.append(f"Extracted host from URL: {display_safe(host)}")
    return host, port


def parse_ip(raw: str) -> ParsedInput:
    """Validate ``raw`` and return a :class:`ParsedInput`, or raise :class:`InvalidIPError`."""
    if raw is None:
        raise InvalidIPError("No input given")
    if len(raw) > MAX_INPUT_LENGTH:
        raise InvalidIPError(
            f"Input is too long ({len(raw)} characters)",
            f"an IP address or URL fits in {MAX_INPUT_LENGTH} characters",
        )
    notes: list[str] = []
    text = raw.strip().lstrip("﻿").strip()  # also drop a UTF-8 byte-order mark
    if not text:
        raise InvalidIPError("Empty input", "type an IP address such as 8.8.8.8")

    normalised = _normalise_digits(text)
    if normalised != text:
        notes.append(
            f"Normalised non-ASCII characters: '{display_safe(text)}' -> "
            f"'{display_safe(normalised)}'"
        )
        text = normalised

    port: int | None = None
    from_url = "://" in text
    if from_url:
        text, port = _from_url(text, notes)

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
        if len(text) > 1 and text.startswith("0"):
            aton = inet_aton(text)
            reading = f"e.g. inet_aton and browsers read it as {aton}" if aton else "or rejects it"
            raise InvalidIPError(
                f"Leading zero in integer '{text[:40]}' is ambiguous",
                f"some software reads it as octal ({reading}; CVE-2021-29921); "
                "remove leading zeros",
            )
        if len(text) > 39:  # 2**128 - 1 has 39 digits
            raise InvalidIPError("Integer is larger than any IPv6 address (2^128 - 1)")
        value = int(text)
        if from_url and value > 2**32 - 1:
            raise InvalidIPError(
                f"URL host {value} is larger than any IPv4 address",
                "a URL can hold an IPv6 address only in brackets, e.g. http://[2001:db8::1]/",
            )
        if value <= 2**32 - 1:
            address: IPAddress = ipaddress.IPv4Address(value)
        elif value <= 2**128 - 1:
            address = ipaddress.IPv6Address(value)
        else:
            raise InvalidIPError("Integer is larger than any IPv6 address (2^128 - 1)")
        notes.append(f"Interpreted integer {value} as {address}")
        return ParsedInput(raw, address, "integer", port, None, tuple(notes))

    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise _diagnose(text) from None

    scope_id = None
    if parsed.version == 6 and parsed.scope_id:
        scope_id = parsed.scope_id
        if any(not ch.isprintable() or ch.isspace() for ch in scope_id):
            raise InvalidIPError(
                f"Zone ID '{display_safe(scope_id)}' contains control or whitespace characters"
            )
        parsed = ipaddress.IPv6Address(text.split("%", 1)[0])
        notes.append(f"Zone (scope) ID '%{scope_id}' is local to one machine and was set aside")

    fmt = "ipv4" if parsed.version == 4 else "ipv6"
    return ParsedInput(raw, parsed, fmt, port, scope_id, tuple(notes))
