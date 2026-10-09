"""Small DNS helper (dnspython), kept separate so tests can replace it."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """No answer: ``nxdomain`` is True when the name does not exist."""

    def __init__(self, message: str, nxdomain: bool = False):
        super().__init__(message)
        self.nxdomain = nxdomain


async def resolve_txt(name: str, timeout: float = 5.0) -> list[str]:
    """TXT records of ``name`` as plain strings."""
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=timeout)
    except dns.resolver.NXDOMAIN as exc:
        raise DNSLookupError(f"{name} does not exist", nxdomain=True) from exc
    except dns.resolver.NoAnswer as exc:
        raise DNSLookupError(f"{name} has no TXT record", nxdomain=True) from exc
    except dns.exception.Timeout as exc:
        raise DNSLookupError(f"DNS query for {name} timed out") from exc
    except dns.exception.DNSException as exc:
        raise DNSLookupError(f"DNS error for {name}: {type(exc).__name__}") from exc
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]
