"""Small DNS helper (dnspython), kept separate so tests can replace it."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """No answer: ``nxdomain`` is True when the name (or the record type) does not exist."""

    def __init__(self, message: str, nxdomain: bool = False):
        super().__init__(message)
        self.nxdomain = nxdomain


def _text(rdata, rdtype: str) -> str:
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rdtype in ("PTR", "CNAME"):
        return rdata.target.to_text(omit_final_dot=True)
    return rdata.to_text()  # A / AAAA: the address


async def resolve_records(name: str, rdtype: str = "TXT", timeout: float = 5.0) -> list[str]:
    """Records of ``name`` as plain strings (TXT text, PTR names, A/AAAA addresses)."""
    try:
        answer = await dns.asyncresolver.resolve(name, rdtype, lifetime=timeout)
    except dns.resolver.NXDOMAIN as exc:
        raise DNSLookupError(f"{name} does not exist", nxdomain=True) from exc
    except dns.resolver.NoAnswer as exc:
        raise DNSLookupError(f"{name} has no {rdtype} record", nxdomain=True) from exc
    except dns.exception.Timeout as exc:
        raise DNSLookupError(f"DNS query for {name} timed out") from exc
    except dns.exception.DNSException as exc:
        raise DNSLookupError(f"DNS error for {name}: {type(exc).__name__}") from exc
    return [_text(rdata, rdtype) for rdata in answer]
