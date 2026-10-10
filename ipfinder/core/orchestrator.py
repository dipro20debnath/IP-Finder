"""Run every provider for an address and collect the results into an IPReport.

Order:
  1. validate the input
  2. stage 0 - offline analysis (L1); it decides whether online layers may run
     and which address they should query (e.g. the IPv4 inside a 6to4 address)
  3. stage 1 - independent sources run concurrently (ip-api, IPinfo, MaxMind,
     Team Cymru, RDAP, RIPEstat, reverse DNS)
  4. stage 2 - sources that need stage-1 data (PeeringDB needs the ASN, Geofeed
     needs the URL from RDAP)
  5. stage 3 - active probes (only with --active), after the passive lookups so
     their traffic does not distort the round-trip times
A provider that fails never stops the others. Results come from the cache when
fresh, and every network call passes the provider's rate limiter first.
"""

from __future__ import annotations

import asyncio
import time

from ipfinder.analysis.offline import analyze as offline_analyze
from ipfinder.analysis.summary import build_summary
from ipfinder.analysis.verdict import build_verdict
from ipfinder.core.models import IPReport, ProviderResult
from ipfinder.core.text import display_safe
from ipfinder.core.validator import InvalidIPError, parse_ip
from ipfinder.providers import default_providers
from ipfinder.providers.base import LookupContext, Provider, ProviderError


async def _run(provider: Provider, ctx: LookupContext) -> ProviderResult:
    base = {"provider": provider.name, "layer": provider.layer}
    reason = provider.skip_reason(ctx)
    if reason:
        return ProviderResult(**base, ok=False, skipped=reason)

    session = ctx.session
    key = provider.cache_key(ctx) if provider.cache_ttl else None
    if key is not None:
        cached = session.cache.get(provider.name, key)
        if cached is not None:
            return ProviderResult(**base, ok=True, data=cached, cached=True)
        error = session.cache.get_error(provider.name, key)
        if error is not None:
            return ProviderResult(**base, ok=False, error=error, cached=True)

    # Waiting for a free rate-limit slot does not count against the provider's timeout.
    try:
        await provider.wait_turn(ctx)
    except Exception as exc:  # a bug in one provider must not sink the whole report
        return ProviderResult(**base, ok=False, error=f"unexpected {type(exc).__name__}: {exc}")

    timeout = provider.timeout or ctx.config.timeout
    start = time.perf_counter()
    try:
        data = await asyncio.wait_for(provider.lookup(ctx), timeout=timeout)
        ok, error = True, None
    except asyncio.TimeoutError:
        data, ok, error = {}, False, f"timed out after {timeout:g}s"
    except ProviderError as exc:
        data, ok, error = {}, False, str(exc)
    except Exception as exc:  # a bug in one provider must not sink the whole report
        data, ok, error = {}, False, f"unexpected {type(exc).__name__}: {exc}"
    elapsed = round((time.perf_counter() - start) * 1000, 2)

    if key is not None:
        if ok and not data.get("partial_errors"):
            session.cache.put(provider.name, key, data, provider.cache_ttl)
        elif not ok:
            session.cache.put_error(provider.name, key, error)
        # A result with partial_errors is shown but not cached, so the next run retries.
    return ProviderResult(**base, ok=ok, data=data, error=error, elapsed_ms=elapsed)


async def analyze(raw: str, session, providers: list[Provider] | None = None) -> IPReport:
    """Analyse one input. Raises InvalidIPError for bad input."""
    parsed = parse_ip(raw)
    providers = default_providers() if providers is None else providers
    ctx = LookupContext(parsed=parsed, config=session.config, session=session)

    results: list[ProviderResult] = []
    for stage in sorted({p.stage for p in providers}):
        group = [p for p in providers if p.stage == stage]
        done = await asyncio.gather(*(_run(p, ctx) for p in group))
        for result in done:
            ctx.results[result.provider] = result
        results += done
        if stage == 0:
            offline = ctx.results.get("offline")
            if offline is None or not offline.ok:
                detail = offline.error if offline else "offline provider missing"
                raise RuntimeError(f"Offline analysis failed: {detail}")
            ctx.target = offline.data["lookup"]["target"]

    offline = ctx.results["offline"]
    return IPReport(
        input=raw,
        ip=offline.data["ip"],
        version=offline.data["version"],
        lookup=offline.data["lookup"],
        results=results,
        notes=list(parsed.notes),
        summary=build_summary(ctx.results),
        verdict=build_verdict(ctx.results),
    )


def _lookup_target(raw: str) -> str | None:
    try:
        return offline_analyze(parse_ip(raw))["lookup"]["target"]
    except ValueError:
        return None


async def _prefetch(inputs: list[str], session, providers: list[Provider]) -> list[str]:
    """Let providers with a batch endpoint fetch all targets at once."""
    targets = list(dict.fromkeys(t for t in map(_lookup_target, inputs) if t))
    notes = []
    if len(targets) < 2:
        return notes
    for provider in providers:
        if provider.unavailable_reason(session.config) is not None:
            continue
        try:
            await provider.prefetch(targets, session)
        except ProviderError as exc:
            notes.append(f"{provider.name} batch lookup failed ({exc}); trying one by one")
    return notes


async def analyze_many(
    inputs: list[str], session, providers: list[Provider] | None = None, on_progress=None
) -> tuple[list[IPReport], list[dict]]:
    """Analyse several inputs; invalid ones are collected as errors instead of raising.
    ``on_progress(done, total, input)`` is called after each input (for a progress bar)."""
    providers = default_providers() if providers is None else providers
    batch_notes = await _prefetch(inputs, session, providers)
    reports: list[IPReport] = []
    errors: list[dict] = []
    for done, raw in enumerate(inputs, start=1):
        if on_progress is not None:
            on_progress(done - 1, len(inputs), raw)
        try:
            report = await analyze(raw, session, providers)
        except InvalidIPError as exc:
            errors.append({"input": raw, "error": exc.message, "hint": exc.hint})
            continue
        except ValueError as exc:  # defence in depth: one bad line never sinks a batch
            errors.append(
                {
                    "input": raw,
                    "error": f"Unparseable input: {display_safe(str(exc))}",
                    "hint": None,
                }
            )
            continue
        report.notes.extend(batch_notes)
        reports.append(report)
    if on_progress is not None:
        on_progress(len(inputs), len(inputs), None)
    return reports, errors
