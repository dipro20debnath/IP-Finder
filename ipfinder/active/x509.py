"""A small X.509 reader (DER) for the fields a report needs: subject, issuer,
validity, subject alternative names and serial number.

Python's ssl module only decodes a certificate it has verified, but the point of
grabbing a certificate from an IP address is to read it even when it is
self-signed or issued for a domain name, so the DER is parsed here directly
(RFC 5280 structure). Anything malformed raises ValueError.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}
_SAN = "2.5.29.17"


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """-> (tag, start of value, end of value) of the element at ``pos``."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated DER")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    while start < end:
        tag, vstart, vend = _tlv(data, start)
        if vend > end:
            raise ValueError("element overruns its parent")
        out.append((tag, vstart, vend))
        start = vend
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        raise ValueError("empty OID")
    parts = [raw[0] // 40, raw[0] % 40] if raw[0] < 80 else [2, raw[0] - 80]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", "replace")
    if tag == 0x14:  # TeletexString, in practice Latin-1
        return raw.decode("latin-1")
    return raw.decode("utf-8", "replace")  # UTF8, Printable, IA5, Visible


def _name(data: bytes, start: int, end: int) -> dict[str, str]:
    """Name -> {"CN": ..., "O": ...}; repeated attributes are joined with ", "."""
    out: dict[str, list[str]] = {}
    for _, rdn_start, rdn_end in _children(data, start, end):
        for _, atv_start, atv_end in _children(data, rdn_start, rdn_end):
            parts = _children(data, atv_start, atv_end)
            if len(parts) != 2 or parts[0][0] != 0x06:
                raise ValueError("bad name attribute")
            oid = _oid(data[parts[0][1] : parts[0][2]])
            tag, vstart, vend = parts[1]
            key = _NAMES.get(oid)
            if key:
                out.setdefault(key, []).append(_string(tag, data[vstart:vend]))
    return {key: ", ".join(values) for key, values in out.items()}


def _time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ; years 50-99 are 19xx (RFC 5280)
        year = int(text[:2])
        text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
    elif tag != 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
        raise ValueError("bad time")
    stamp = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _san(raw: bytes) -> tuple[list[str], list[str]]:
    tag, start, end = _tlv(raw, 0)
    if tag != 0x30:
        raise ValueError("bad subjectAltName")
    dns, ips = [], []
    for item_tag, vstart, vend in _children(raw, start, end):
        value = raw[vstart:vend]
        if item_tag == 0x82:  # dNSName
            dns.append(value.decode("ascii", "replace"))
        elif item_tag == 0x87 and len(value) in (4, 16):  # iPAddress
            ips.append(str(ipaddress.ip_address(value)))
    return dns, ips


def parse_certificate(der: bytes) -> dict:
    tag, start, end = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a certificate")
    cert = _children(der, start, end)
    if not cert or cert[0][0] != 0x30:
        raise ValueError("no tbsCertificate")
    tbs = _children(der, cert[0][1], cert[0][2])
    if tbs and tbs[0][0] == 0xA0:  # explicit version
        tbs = tbs[1:]
    if len(tbs) < 6:
        raise ValueError("tbsCertificate too short")
    serial, _sig, issuer, validity, subject = tbs[:5]
    times = _children(der, validity[1], validity[2])
    if len(times) != 2:
        raise ValueError("bad validity")
    result: dict = {
        "serial": der[serial[1] : serial[2]].hex(),
        "issuer": _name(der, issuer[1], issuer[2]),
        "subject": _name(der, subject[1], subject[2]),
        "not_before": _time(times[0][0], der[times[0][1] : times[0][2]]),
        "not_after": _time(times[1][0], der[times[1][1] : times[1][2]]),
        "dns_names": [],
        "ip_addresses": [],
    }
    for tag, vstart, vend in tbs[6:]:
        if tag != 0xA3:  # extensions
            continue
        (seq,) = _children(der, vstart, vend)
        for _, ext_start, ext_end in _children(der, seq[1], seq[2]):
            parts = _children(der, ext_start, ext_end)
            if parts and parts[0][0] == 0x06 and _oid(der[parts[0][1] : parts[0][2]]) == _SAN:
                value = parts[-1]
                if value[0] != 0x04:
                    raise ValueError("bad extension value")
                result["dns_names"], result["ip_addresses"] = _san(der[value[1] : value[2]])
    result["self_signed"] = result["issuer"] == result["subject"]
    return result
