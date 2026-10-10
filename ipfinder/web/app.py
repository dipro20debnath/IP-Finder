"""Phase 9: a web dashboard on top of the same ipfinder package.

    pip install -e ".[web]"
    ipfinder serve                  (prints http://127.0.0.1:8000/#token=...)

One small FastAPI app serves the page and its API. Lookups go through the same
orchestrator, providers, cache and rate limiters as the CLI, and every result is
shown with the HTML report's own section and map code.

The server runs lookups with your API keys (and, if you allow it, active
probes), so it guards itself:
* it listens on 127.0.0.1 unless told otherwise;
* every API call needs the random token printed at start, sent in a header.
  The page reads it from the link's #fragment, which browsers never send to a
  server, so the token does not end up in server logs;
* the Host header must name this server, so a web page whose DNS name is
  re-pointed at 127.0.0.1 ("DNS rebinding") is refused;
* requests from other sites (Origin, Sec-Fetch-Site) are refused and there is
  no CORS, so another tab can neither use the API nor read its answers;
* active probes need ``--allow-active`` at start AND the exact "I AM
  AUTHORIZED" phrase with the lookup, for at most 20 addresses, as in the CLI;
* a strict Content-Security-Policy: scripts only from this server.
"""

from __future__ import annotations

import json
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib.resources import files
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from starlette.datastructures import Headers

from ipfinder import DISCLAIMER, __version__
from ipfinder.core.config import PROFILES, Config
from ipfinder.core.inputs import read_lines
from ipfinder.core.models import IPReport
from ipfinder.core.orchestrator import iter_analyze
from ipfinder.core.session import Session
from ipfinder.core.text import display_safe
from ipfinder.output import csv_out, html_report, json_out
from ipfinder.providers import source_overview
from ipfinder.providers.active import ACTIVE_LIMIT, ACTIVE_WARNING, CONFIRMATION
from ipfinder.providers.base import Provider, ProviderError
from ipfinder.providers.ipapi import public_ip

MAX_INPUTS = 100  # per lookup here; "ipfinder batch" has no limit
MAX_BODY = 256 * 1024  # bytes in a request body
KEEP_RUNS = 20  # finished lookups kept in memory for the download buttons
LOOPBACK = ("127.0.0.1", "localhost", "::1")

_ASSETS = files("ipfinder.output") / "assets"
_STATIC = files("ipfinder.web") / "static"
FILES = {  # everything the page loads; nothing else is served
    "leaflet.js": (_ASSETS, "text/javascript; charset=utf-8"),
    "leaflet.css": (_ASSETS, "text/css; charset=utf-8"),
    "ipfinder-map.js": (_ASSETS, "text/javascript; charset=utf-8"),
    "report.css": (_ASSETS, "text/css; charset=utf-8"),
    "world-110m.json": (_ASSETS, "application/json"),
    "app.js": (_STATIC, "text/javascript; charset=utf-8"),
    "app.css": (_STATIC, "text/css; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),  # OSM tiles want a Referer
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
]


def host_name(host_header: str) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class Gate:
    """ASGI middleware in front of everything: checks Host, origin, token and body
    size before the app reads a byte of the body, and adds the security headers
    to every response, refusals included."""

    def __init__(self, app, token: str, allowed_hosts: Iterable[str]):
        self.app = app
        self.token = f"Bearer {token}".encode()
        self.allowed_hosts = {h.lower().strip("[]") for h in allowed_hosts}

    def refusal(self, scope, headers: Headers) -> tuple[int, str] | None:
        host = headers.get("host", "")
        if host_name(host) not in self.allowed_hosts:
            return 400, (
                f"This server does not answer to the host name '{display_safe(host)}'. "
                "Open the address printed by 'ipfinder serve' (or start it with "
                "--allowed-host for another name)."
            )
        if not scope["path"].startswith("/api/"):
            return None
        if headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return 403, "Requests from other web sites are refused."
        origin = headers.get("origin")
        if origin is not None and origin != f"{scope['scheme']}://{host}":
            return 403, "Requests from other web sites are refused."
        given = headers.get("authorization", "").encode("latin-1", "replace")
        if not secrets.compare_digest(given, self.token):
            return 401, (
                "Missing or wrong token. Open the link printed by 'ipfinder serve'; it "
                "prints a new token each time it starts."
            )
        if scope["method"] == "POST":
            length = headers.get("content-length")
            if length is None or not length.isdigit():
                return 411, "The request needs a Content-Length."
            if int(length) > MAX_BODY:
                return 413, f"The request is larger than {MAX_BODY // 1024} KB."
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message.get("headers", []), *SECURITY_HEADERS]}
            await send(message)

        refused = self.refusal(scope, Headers(scope=scope))
        if refused is not None:
            status, detail = refused
            await JSONResponse({"detail": detail}, status)(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)


class LookupRequest(BaseModel):
    text: str = Field(max_length=MAX_BODY)  # one address per line, "#" = comment
    profile: Literal["quick", "standard", "full"] = "standard"
    verbose: bool = False
    active: bool = False
    confirmation: str = Field(default="", max_length=100)


@dataclass
class Run:
    reports: list[IPReport]
    errors: list[dict]
    verbose: bool
    finished: datetime


def _line(event: dict) -> bytes:
    return (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")


def create_app(
    config: Config,
    token: str,
    *,
    allow_active: bool = False,
    allowed_hosts: Iterable[str] = (),
    providers: Callable[[], list[Provider]] | None = None,
    session_factory: Callable[[Config], Session] = Session,
):
    """The dashboard as an ASGI app. ``providers`` and ``session_factory`` let
    tests replace the network; normally every source is used."""
    runs: OrderedDict[str, Run] = OrderedDict()
    static = {name: (folder / name).read_bytes() for name, (folder, _) in FILES.items()}
    index_page = (_STATIC / "index.html").read_bytes()
    state: dict = {}

    @asynccontextmanager
    async def lifespan(_app):
        # One session for the whole server: one HTTP client, cache and set of rate
        # limiters, so ip-api's 45 requests a minute hold across tabs and lookups.
        async with session_factory(config) as session:
            state["session"] = session
            yield
        state.clear()

    app = FastAPI(
        title="IP Finder",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,  # Swagger UI loads scripts from a CDN; not wanted here
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/", include_in_schema=False)
    async def index() -> Response:
        return Response(index_page, media_type="text/html; charset=utf-8")

    @app.get("/static/{name}", include_in_schema=False)
    async def static_file(name: str) -> Response:
        if name not in FILES:
            raise HTTPException(404, "Not found")
        return Response(static[name], media_type=FILES[name][1])

    @app.get("/api/info")
    async def info() -> dict:
        return {
            "version": __version__,
            "disclaimer": DISCLAIMER,
            "profiles": list(PROFILES),
            "default_profile": config.profile,
            "max_inputs": MAX_INPUTS,
            "cache": config.use_cache,
            "offline": config.offline,
            "active_allowed": allow_active,
            "active_limit": ACTIVE_LIMIT,
            "active_warning": ACTIVE_WARNING,
            "confirmation": CONFIRMATION,
        }

    @app.get("/api/sources")
    async def sources() -> list[dict]:
        return source_overview(config)

    @app.get("/api/me")
    async def me() -> dict:
        if config.offline:
            raise HTTPException(
                400, "Offline mode: finding the public IP needs ip-api, so it is switched off."
            )
        try:
            return {"ip": await public_ip(state["session"])}
        except ProviderError as exc:
            raise HTTPException(502, f"Could not find this computer's public IP: {exc}") from None

    @app.post("/api/lookup")
    async def lookup(body: LookupRequest) -> StreamingResponse:
        inputs = read_lines(body.text.splitlines())
        if not inputs:
            raise HTTPException(400, "Enter at least one IP address.")
        if len(inputs) > MAX_INPUTS:
            raise HTTPException(
                400,
                f"At most {MAX_INPUTS} addresses per lookup here ({len(inputs)} given). "
                "For more, use 'ipfinder batch FILE'.",
            )
        if body.active:
            if not allow_active:
                raise HTTPException(
                    403,
                    "Active probes are off. Start the server with 'ipfinder serve --allow-active'.",
                )
            if len(inputs) > ACTIVE_LIMIT:
                raise HTTPException(
                    400,
                    f"Active probes check at most {ACTIVE_LIMIT} addresses per run "
                    f"({len(inputs)} given). Nothing was sent.",
                )
            if body.confirmation.strip() != CONFIRMATION:
                raise HTTPException(
                    400,
                    f"Type '{CONFIRMATION}' to confirm you may test these systems. "
                    "Nothing was sent.",
                )
        session = state["session"].with_config(
            replace(config, profile=body.profile, active_mode=body.active)
        )
        run_id = secrets.token_urlsafe(9)
        chosen = providers() if providers else None

        async def events():
            started = time.monotonic()
            reports: list[IPReport] = []
            errors: list[dict] = []
            total = len(inputs)
            yield _line({"event": "start", "run": run_id, "total": total})
            yield _line({"event": "progress", "done": 0, "total": total, "input": inputs[0]})
            try:
                async for _raw, report, error in iter_analyze(inputs, session, chosen):
                    if report is not None:
                        html, data = html_report.section(
                            report, f"{run_id}-{len(reports)}", body.verbose
                        )
                        reports.append(report)
                        yield _line({"event": "report", "ip": report.ip, "html": html, "map": data})
                    else:
                        errors.append(error)
                        yield _line({"event": "error", **error})
                    done = len(reports) + len(errors)
                    current = inputs[done] if done < total else None
                    yield _line(
                        {"event": "progress", "done": done, "total": total, "input": current}
                    )
            except Exception as exc:  # show it in the page instead of cutting the stream
                detail = f"Internal error: {type(exc).__name__}: {display_safe(str(exc))}"
                yield _line({"event": "fatal", "error": detail})
                return
            runs[run_id] = Run(reports, errors, body.verbose, datetime.now(timezone.utc))
            while len(runs) > KEEP_RUNS:
                runs.popitem(last=False)
            yield _line(
                {
                    "event": "done",
                    "run": run_id,
                    "reports": len(reports),
                    "errors": len(errors),
                    "seconds": round(time.monotonic() - started, 1),
                    "cache_warning": session.cache.warning,
                }
            )

        return StreamingResponse(events(), media_type="application/x-ndjson")

    @app.get("/api/export/{run_id}")
    async def export(run_id: str, format: Literal["html", "csv", "json"] = "html") -> Response:
        run = runs.get(run_id)
        if run is None:
            raise HTTPException(
                404, f"That lookup is no longer kept (the last {KEEP_RUNS} are). Run it again."
            )
        if format == "json":
            body, media = json_out.render(run.reports, run.errors), "application/json"
        elif format == "csv":  # BOM, so Excel reads UTF-8 (as with -o in the CLI)
            body, media = "﻿" + csv_out.render(run.reports, run.errors), "text/csv"
        else:
            body = html_report.render(run.reports, run.errors, run.verbose)
            media = "text/html"
        name = f"ipfinder-{run.finished:%Y%m%d-%H%M%S}.{format}"
        return Response(
            body.encode("utf-8", "backslashreplace"),
            media_type=f"{media}; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    hosts = (*LOOPBACK, *allowed_hosts)
    return Gate(app, token, hosts)
