"""HTTP helper for providers.

Error messages never contain the request URL: some providers (IPinfo) take the
API token as a URL parameter, and it must not leak into reports or logs.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from ipfinder.providers.base import ProviderError


def _retry_after(headers: httpx.Headers) -> float | None:
    value = headers.get("retry-after") or headers.get("x-ttl")
    if value and value.strip().isdigit():
        return float(value.strip())
    return None


async def request_json(
    session,
    method: str,
    url: str,
    *,
    limiter=None,
    params: dict | None = None,
    json: Any = None,
    headers: dict | None = None,
    ok_statuses: tuple[int, ...] = (200,),
) -> tuple[httpx.Response, Any]:
    """Send a request and decode JSON. HTTP 429 pauses ``limiter`` (if given)."""
    host = urlsplit(url).hostname
    try:
        response = await session.http.request(
            method, url, params=params, json=json, headers=headers
        )
    except httpx.TimeoutException:
        raise ProviderError(f"timed out talking to {host}") from None
    except httpx.HTTPError as exc:
        raise ProviderError(f"cannot reach {host} ({type(exc).__name__})") from None

    if response.status_code == 429:
        wait = _retry_after(response.headers) or 60.0
        if limiter is not None:
            limiter.block_for(wait)
        raise ProviderError(f"rate limited by {host} (HTTP 429); retry in {wait:.0f}s")
    if response.status_code in (401, 403) and response.status_code not in ok_statuses:
        raise ProviderError(
            f"{host} refused the request (HTTP {response.status_code}); check the API key"
        )
    if response.status_code not in ok_statuses:
        raise ProviderError(f"{host} answered HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError:
        raise ProviderError(f"{host} returned invalid JSON") from None
    return response, data
