"""Phase 9: the web dashboard - its safeguards, the streamed lookup, downloads and
the serve command. The app is driven through httpx's ASGI transport (no server,
no network)."""

import csv
import dataclasses
import io
import json
import re

import httpx
import pytest

pytest.importorskip("fastapi")

import ipfinder.web.app as web  # noqa: E402
from ipfinder.cli import main  # noqa: E402
from ipfinder.core.session import Session  # noqa: E402
from ipfinder.providers.base import Provider  # noqa: E402
from ipfinder.providers.maxmind import MaxMindProvider  # noqa: E402
from ipfinder.providers.offline import OfflineProvider  # noqa: E402
from tests.conftest import ASN_DB, CITY_DB, run  # noqa: E402

TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
HOSTILE = '</script><img src=x onerror="alert(1)">'


class HostileGeo(Provider):
    """A source whose answer contains HTML, as a hostile registry entry could."""

    name, layer, profiles = "ip-api", "L2", ("quick", "standard", "full")

    async def lookup(self, ctx):
        return {
            "location": {"country_code": "GB", "city": HOSTILE, "latitude": 51.5, "longitude": -0.1}
        }


class ProbeRecorder(Provider):
    """Stands in for an active probe: records that it ran."""

    name, layer, stage, active = "probe", "L10", 3, True
    profiles = ("quick", "standard", "full")
    calls: list = []

    async def lookup(self, ctx):
        ProbeRecorder.calls.append(ctx.target)
        return {}


@pytest.fixture
def mm(config):
    return dataclasses.replace(config, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB)


def make_app(config, providers=None, **options):
    chosen = providers or [OfflineProvider(), MaxMindProvider()]
    return web.create_app(config, TOKEN, providers=lambda: list(chosen), **options)


def call(app, *requests, host="127.0.0.1:8000"):
    """Run the app's lifespan and send requests: (method, path, kwargs) tuples."""

    async def go():
        fastapi_app = app.app
        async with fastapi_app.router.lifespan_context(fastapi_app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=f"http://{host}") as c:
                return [await c.request(m, path, **kw) for m, path, kw in requests]

    return run(go())


def get(app, path, **kw):
    return call(app, ("GET", path, kw))[0]


def lookup_body(text, **fields):
    return {"json": {"text": text, **fields}, "headers": AUTH}


def events(response):
    return [json.loads(line) for line in response.text.splitlines()]


# ------------------------------------------------------------------ page and headers


def test_page_has_no_inline_script_and_strict_headers(config):
    app = make_app(config)
    page = get(app, "/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self';" in csp
    assert "unsafe-eval" not in csp and "frame-ancestors 'none'" in csp
    assert page.headers["x-content-type-options"] == "nosniff"
    scripts = re.findall(r"<script([^>]*)>", page.text)
    assert scripts and all("src=" in attrs for attrs in scripts)  # nothing inline
    for name in re.findall(r'(?:src|href)="/static/([^"]+)"', page.text):
        asset = get(app, f"/static/{name}")
        assert asset.status_code == 200 and asset.content, name
        assert asset.headers["content-type"] == web.FILES[name][1]
    assert get(app, "/static/world-110m.json").json()["cities"]
    for path in ("/static/app.py", "/static/..%2Fapp.py", "/docs", "/openapi.json"):
        assert get(app, path).status_code == 404, path


def test_api_needs_the_token(config):
    app = make_app(config)
    assert get(app, "/api/info").status_code == 401
    wrong = get(app, "/api/info", headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401 and "new token" in wrong.json()["detail"]
    odd = get(app, "/api/info", headers={"Authorization": "Bearer töken".encode()})
    assert odd.status_code == 401  # non-ASCII must not crash the comparison
    info = get(app, "/api/info", headers=AUTH).json()
    assert info["active_allowed"] is False and info["confirmation"] == "I AM AUTHORIZED"
    assert info["max_inputs"] == web.MAX_INPUTS == 100
    refused = get(app, "/api/info")
    assert refused.headers["content-security-policy"]  # refusals carry the headers too


@pytest.mark.parametrize(
    ("host", "allowed", "status"),
    [
        ("127.0.0.1:8000", (), 200),
        ("localhost:8000", (), 200),
        ("[::1]:8000", (), 200),
        ("evil.example:8000", (), 400),  # DNS rebinding: a foreign name for our address
        ("evil.example", (), 400),
        ("192.168.1.5:8000", (), 400),
        ("192.168.1.5:8000", ("192.168.1.5",), 200),
    ],
)
def test_host_header_must_name_this_server(config, host, allowed, status):
    app = make_app(config, allowed_hosts=allowed)
    response = call(app, ("GET", "/", {}), host=host)[0]
    assert response.status_code == status
    if status == 400:
        assert "--allowed-host" in response.json()["detail"]


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"Origin": "http://evil.example"}, 403),
        ({"Origin": "null"}, 403),
        ({"Origin": "http://127.0.0.1:9999"}, 403),
        ({"Sec-Fetch-Site": "cross-site"}, 403),
        ({"Sec-Fetch-Site": "same-site"}, 403),
        ({"Origin": "http://127.0.0.1:8000", "Sec-Fetch-Site": "same-origin"}, 200),
        ({}, 200),  # curl and scripts send neither
    ],
)
def test_requests_from_other_sites_are_refused(config, headers, status):
    app = make_app(config)
    response = call(app, ("POST", "/api/lookup", lookup_body("10.0.0.1")))[0]
    assert response.status_code == 200
    response = call(
        app,
        ("POST", "/api/lookup", {"json": {"text": "10.0.0.1"}, "headers": {**AUTH, **headers}}),
    )[0]
    assert response.status_code == status


def test_body_size_and_input_limits(config):
    app = make_app(config)
    big = call(app, ("POST", "/api/lookup", lookup_body("1.1.1.1\n" * 40000)))[0]
    assert big.status_code == 413
    many = "\n".join(f"10.0.0.{i}" for i in range(101))
    too_many = call(app, ("POST", "/api/lookup", lookup_body(many)))[0]
    assert too_many.status_code == 400 and "ipfinder batch" in too_many.json()["detail"]
    empty = call(app, ("POST", "/api/lookup", lookup_body("# only a comment\n\n")))[0]
    assert empty.status_code == 400
    profile = call(app, ("POST", "/api/lookup", lookup_body("1.1.1.1", profile="max")))[0]
    assert profile.status_code == 422


# ------------------------------------------------------------------ lookups


def test_lookup_streams_each_result_and_downloads_work(mm):
    app = make_app(mm)
    text = "81.2.69.142  # London\nnot-an-ip\n89.160.20.112\n"

    async def go():
        fastapi_app = app.app
        async with fastapi_app.router.lifespan_context(fastapi_app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8000"
            ) as c:
                response = await c.post("/api/lookup", **lookup_body(text))
                run_id = events(response)[-1]["run"]
                files = {
                    f: await c.get(f"/api/export/{run_id}", params={"format": f}, headers=AUTH)
                    for f in ("html", "csv", "json")
                }
                missing = await c.get("/api/export/nope", headers=AUTH)
                return response, files, missing

    response, files, missing = run(go())
    assert response.headers["content-type"].startswith("application/x-ndjson")
    stream = events(response)
    assert [e["event"] for e in stream] == [
        "start", "progress", "report", "progress", "error", "progress", "report", "progress",
        "done",
    ]  # fmt: skip
    run_id = stream[0]["run"]
    assert stream[0]["total"] == 3 and [e["input"] for e in stream if e["event"] == "progress"] == [
        "81.2.69.142", "not-an-ip", "89.160.20.112", None,
    ]  # fmt: skip
    london, error, linkoping = stream[2], stream[4], stream[6]
    assert london["ip"] == "81.2.69.142" and "London" in london["html"]
    assert london["html"].startswith('<section class="report">')
    assert london["map"]["id"] == f"map-{run_id}-0" and f'id="map-{run_id}-0"' in london["html"]
    assert linkoping["map"]["id"] == f"map-{run_id}-1"
    assert error["input"] == "not-an-ip" and "hostname" in error["error"]
    assert stream[-1] == {
        "event": "done", "run": run_id, "reports": 2, "errors": 1,
        "seconds": stream[-1]["seconds"], "cache_warning": None,
    }  # fmt: skip

    html = files["html"]
    assert html.status_code == 200 and html.text.startswith("<!doctype html>")
    assert "attachment" in html.headers["content-disposition"]
    assert html.text.count('class="map"') == 2 and "Linköping" in html.text
    assert files["csv"].content.startswith(b"\xef\xbb\xbf")  # Excel reads UTF-8
    rows = list(csv.DictReader(io.StringIO(files["csv"].text.lstrip("﻿"))))
    assert [r["city"] for r in rows] == ["London", "Linköping", ""]
    assert len(files["json"].json()["reports"]) == 2
    assert missing.status_code == 404 and "Run it again" in missing.json()["detail"]


def test_stream_escapes_hostile_text(config):
    app = make_app(config, providers=[OfflineProvider(), HostileGeo()])
    stream = events(call(app, ("POST", "/api/lookup", lookup_body("8.8.8.8", profile="quick")))[0])
    report = next(e for e in stream if e["event"] == "report")
    assert HOSTILE not in report["html"] and "&lt;/script&gt;&lt;img" in report["html"]
    assert HOSTILE in report["map"]["points"][0]["label"]  # data; the page inserts it as text


def test_a_run_is_kept_until_newer_ones_push_it_out(config, monkeypatch):
    monkeypatch.setattr(web, "KEEP_RUNS", 1)
    app = make_app(config)

    async def go():
        fastapi_app = app.app
        async with fastapi_app.router.lifespan_context(fastapi_app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8000"
            ) as c:
                first = events(await c.post("/api/lookup", **lookup_body("10.0.0.1")))[-1]["run"]
                kept = await c.get(f"/api/export/{first}", headers=AUTH)
                await c.post("/api/lookup", **lookup_body("10.0.0.2"))
                gone = await c.get(f"/api/export/{first}", headers=AUTH)
                return kept.status_code, gone.status_code

    assert run(go()) == (200, 404)


# ------------------------------------------------------------------ active probes


def test_active_probes_need_the_server_flag_and_the_phrase(config):
    ProbeRecorder.calls = []
    providers = [OfflineProvider(), ProbeRecorder()]
    off = make_app(config, providers=providers)
    body = lookup_body("8.8.8.8", active=True, confirmation="I AM AUTHORIZED")
    refused = call(off, ("POST", "/api/lookup", body))[0]
    assert refused.status_code == 403 and "--allow-active" in refused.json()["detail"]

    on = make_app(config, providers=providers, allow_active=True)
    responses = call(
        on,
        ("POST", "/api/lookup", lookup_body("8.8.8.8", active=True)),
        ("POST", "/api/lookup", lookup_body("8.8.8.8", active=True, confirmation="yes")),
        (
            "POST",
            "/api/lookup",
            lookup_body(
                "\n".join(f"8.8.8.{i}" for i in range(21)),
                active=True,
                confirmation="I AM AUTHORIZED",
            ),
        ),
        ("POST", "/api/lookup", lookup_body("8.8.8.8")),  # passive: the probe is skipped
    )
    assert [r.status_code for r in responses] == [400, 400, 400, 200]
    assert "Nothing was sent" in responses[0].json()["detail"]
    assert "at most 20" in responses[2].json()["detail"]
    assert ProbeRecorder.calls == []  # nothing reached a probe so far

    done = call(on, ("POST", "/api/lookup", body))[0]
    assert done.status_code == 200 and events(done)[-1]["event"] == "done"
    assert ProbeRecorder.calls == ["8.8.8.8"]


# ------------------------------------------------------------------ other endpoints


def test_sources_and_my_ip(config, fake_api):
    app = make_app(config)
    sources = get(app, "/api/sources", headers=AUTH).json()
    names = {row["name"]: row for row in sources}
    assert names["offline"]["ready"] is True and names["abuseipdb"]["ready"] is False
    assert names["abuseipdb"]["needs"] == "ABUSEIPDB_API_KEY"

    failed = get(app, "/api/me", headers=AUTH)
    assert failed.status_code == 502 and "public IP" in failed.json()["detail"]
    fake_api.json("GET", "http://ip-api.com/json/", {"status": "success", "query": "203.0.113.9"})
    assert get(app, "/api/me", headers=AUTH).json() == {"ip": "203.0.113.9"}


def test_session_views_share_everything_but_the_settings(config):
    async def go():
        async with Session(config) as session:
            view = session.with_config(dataclasses.replace(config, profile="full"))
            assert view.config.profile == "full" and session.config.profile == "standard"
            assert view.http is session.http and view.cache is session.cache
            assert view.limiter("ip-api", 45, 60) is session.limiter("ip-api", 45, 60)
            await view.close()  # must not close the shared client
            assert not session.http.is_closed
            async with view:  # nor when used as a context manager
                pass
            assert not session.http.is_closed

    run(go())


# ------------------------------------------------------------------ serve command


@pytest.fixture
def fake_uvicorn(monkeypatch):
    import uvicorn

    started = {}

    def fake_run(app, **options):
        started.update(options, app=app)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    return started


def test_serve_prints_a_link_with_a_token(fake_uvicorn, capsys):
    assert main(["serve", "--port", "8123"]) == 0
    err = capsys.readouterr().err
    token = re.search(r"Open: http://127\.0\.0\.1:8123/#token=([\w-]{32})", err).group(1)
    assert fake_uvicorn["host"] == "127.0.0.1" and fake_uvicorn["port"] == 8123
    assert "Listening on" not in err and "Active mode" not in err
    assert fake_uvicorn["app"].token == f"Bearer {token}".encode()
    assert fake_uvicorn["app"].allowed_hosts == {"127.0.0.1", "localhost", "::1"}


def test_serve_on_the_network_warns_and_needs_allowed_hosts(fake_uvicorn, capsys):
    assert main(["serve", "--host", "0.0.0.0", "--allowed-host", "192.168.1.5"]) == 0
    err = capsys.readouterr().err
    assert "plain HTTP" in err and "--allowed-host <that address>" in err
    assert fake_uvicorn["host"] == "0.0.0.0"
    assert "192.168.1.5" in fake_uvicorn["app"].allowed_hosts

    assert main(["serve", "--host", "192.168.1.5", "--allow-active"]) == 0
    err = capsys.readouterr().err
    assert "192.168.1.5" in fake_uvicorn["app"].allowed_hosts
    assert "Active mode sends packets" in err and "I AM AUTHORIZED" in err


def test_serve_reports_problems(monkeypatch, capsys):
    import uvicorn

    def cannot_bind(app, **options):
        raise SystemExit(1)

    monkeypatch.setattr(uvicorn, "run", cannot_bind)
    assert main(["serve"]) == 2
    assert "could not start" in capsys.readouterr().err
    assert main(["serve", "--port", "70000"]) == 2

    monkeypatch.setitem(__import__("sys").modules, "uvicorn", None)
    assert main(["serve"]) == 2
    assert 'pip install -e ".[web]"' in capsys.readouterr().err


def test_shared_session_survives_requests(mm):
    """Two lookups in one server run through one session (one rate limiter)."""
    seen = []

    def factory(config):
        session = Session(config)
        seen.append(session)
        return session

    app = make_app(mm, session_factory=factory)
    first, second = call(
        app,
        ("POST", "/api/lookup", lookup_body("81.2.69.142")),
        ("POST", "/api/lookup", lookup_body("89.160.20.112")),
    )
    assert first.status_code == second.status_code == 200
    assert len(seen) == 1
