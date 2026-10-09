"""HTTP helpers for providers.

Error messages never contain the request URL: some providers (IPinfo) take the
API token as a URL parameter, and it must not leak into reports or logs.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from ipfinder.core.errors import ProviderError


def _retry_after(headers: httpx.Headers) -> float | None:
    value = headers.get("retry-after") or headers.get("x-ttl")
    if value and value.strip().isdigit():
        return float(value.strip())
    return None


def _check_status(response: httpx.Response, host, limiter, ok_statuses) -> None:
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


async def send(
    session,
    method: str,
    url: str,
    *,
    limiter=None,
    params: dict | None = None,
    json: Any = None,
    headers: dict | None = None,
    ok_statuses: tuple[int, ...] = (200,),
    auth: httpx.Auth | tuple[str, str] | None = None,
) -> httpx.Response:
    """Send a request; any status outside ``ok_statuses`` raises ProviderError.
    HTTP 429 pauses ``limiter`` (if given)."""
    host = urlsplit(url).hostname
    try:
        response = await session.http.request(
            method,
            url,
            params=params,
            json=json,
            headers=headers,
            **({"auth": auth} if auth is not None else {}),
        )
    except httpx.TimeoutException:
        raise ProviderError(f"timed out talking to {host}") from None
    except httpx.HTTPError as exc:
        raise ProviderError(f"cannot reach {host} ({type(exc).__name__})") from None
    _check_status(response, host, limiter, ok_statuses)
    return response


def decode_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        raise ProviderError(f"{response.url.host} returned invalid JSON") from None


async def request_json(session, method: str, url: str, **kwargs) -> tuple[httpx.Response, Any]:
    """``send`` and decode the JSON body (same keyword arguments as ``send``)."""
    response = await send(session, method, url, **kwargs)
    return response, decode_json(response)


async def fetch_bytes(
    session,
    url: str,
    *,
    max_bytes: int,
    headers: dict | None = None,
    https_only: bool = True,
    auth: httpx.Auth | tuple[str, str] | None = None,
) -> tuple[bytes, httpx.Headers]:
    """Download at most ``max_bytes`` (stops reading beyond that). With
    ``https_only`` a redirect to plain HTTP is refused. httpx drops ``auth``
    when a redirect leaves the original host."""
    host = urlsplit(url).hostname
    limit = f"{max_bytes / 1e6:g} MB"
    chunks: list[bytes] = []
    extra = {"auth": auth} if auth is not None else {}
    try:
        async with session.http.stream("GET", url, headers=headers, **extra) as response:
            _check_status(response, host, None, (200,))
            if https_only and response.url.scheme != "https":
                raise ProviderError(f"{host} redirected to plain HTTP; refused")
            declared = response.headers.get("content-length", "").strip()
            if declared.isdigit() and int(declared) > max_bytes:
                raise ProviderError(f"{host} file is larger than {limit}")
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise ProviderError(f"{host} file is larger than {limit}")
                chunks.append(chunk)
            headers_out = response.headers
    except httpx.TimeoutException:
        raise ProviderError(f"timed out talking to {host}") from None
    except httpx.HTTPError as exc:
        raise ProviderError(f"cannot reach {host} ({type(exc).__name__})") from None
    return b"".join(chunks), headers_out


async def fetch_text(
    session, url: str, *, max_bytes: int, headers: dict | None = None, https_only: bool = True
) -> str:
    """``fetch_bytes`` decoded as UTF-8 (invalid bytes replaced)."""
    data, _ = await fetch_bytes(
        session, url, max_bytes=max_bytes, headers=headers, https_only=https_only
    )
    return data.decode("utf-8", "replace")
