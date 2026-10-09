"""Run every provider for an address and collect the results into an IPReport.

Order:
  1. validate the input
  2. run the offline layer (L1); it decides whether online layers may run and
     which address they should query (e.g. the IPv4 inside a 6to4 address)
  3. run the remaining providers concurrently; one failing never stops the others
"""

from __future__ import annotations

import asyncio
import time

from ipfinder.core.config import Config
from ipfinder.core.models import IPReport, ProviderResult
from ipfinder.core.validator import InvalidIPError, parse_ip
from ipfinder.providers import default_providers
from ipfinder.providers.base import LookupContext, Provider, ProviderError


async def _run(provider: Provider, ctx: LookupContext) -> ProviderResult:
    base = {"provider": provider.name, "layer": provider.layer}
    reason = provider.skip_reason(ctx)
    if reason:
        return ProviderResult(**base, ok=False, skipped=reason)
    start = time.perf_counter()
    try:
        data = await asyncio.wait_for(provider.lookup(ctx), timeout=ctx.config.timeout)
        ok, error = True, None
    except asyncio.TimeoutError:
        data, ok, error = {}, False, f"timed out after {ctx.config.timeout:g}s"
    except ProviderError as exc:
        data, ok, error = {}, False, str(exc)
    except Exception as exc:  # a bug in one provider must not sink the whole report
        data, ok, error = {}, False, f"unexpected {type(exc).__name__}: {exc}"
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    return ProviderResult(**base, ok=ok, data=data, error=error, elapsed_ms=elapsed)


async def analyze(raw: str, config: Config, providers: list[Provider] | None = None) -> IPReport:
    """Analyse one input. Raises InvalidIPError for bad input."""
    parsed = parse_ip(raw)
    providers = default_providers() if providers is None else providers
    ctx = LookupContext(parsed=parsed, config=config)

    local = [p for p in providers if not p.needs_public_ip]
    remote = [p for p in providers if p.needs_public_ip]

    results = list(await asyncio.gather(*(_run(p, ctx) for p in local)))
    offline = next((r for r in results if r.provider == "offline"), None)
    if offline is None or not offline.ok:
        detail = offline.error if offline else "offline provider missing"
        raise RuntimeError(f"Offline analysis failed: {detail}")

    lookup = offline.data["lookup"]
    ctx.target = lookup["target"]
    results += await asyncio.gather(*(_run(p, ctx) for p in remote))

    return IPReport(
        input=raw,
        ip=offline.data["ip"],
        version=offline.data["version"],
        lookup=lookup,
        results=results,
        notes=list(parsed.notes),
    )


async def analyze_many(
    inputs: list[str], config: Config, providers: list[Provider] | None = None
) -> tuple[list[IPReport], list[dict]]:
    """Analyse several inputs; invalid ones are collected as errors instead of raising."""
    reports: list[IPReport] = []
    errors: list[dict] = []
    for raw in inputs:
        try:
            reports.append(await analyze(raw, config, providers))
        except InvalidIPError as exc:
            errors.append({"input": raw, "error": exc.message, "hint": exc.hint})
    return reports, errors
