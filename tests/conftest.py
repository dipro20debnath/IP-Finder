import asyncio
import ipaddress
import os
from pathlib import Path

import httpx
import pytest

import ipfinder.core.session as session_module
from ipfinder.analysis.offline import analyze as offline_analyze
from ipfinder.core.cache import Cache
from ipfinder.core.config import KNOWN_KEYS, Config
from ipfinder.core.dns import DNSLookupError
from ipfinder.core.orchestrator import analyze, analyze_many
from ipfinder.core.session import USER_AGENT, Session
from ipfinder.core.validator import parse_ip

MAXMIND_DIR = Path(__file__).parent / "data" / "maxmind"
CITY_DB = MAXMIND_DIR / "GeoLite2-City-Test.mmdb"
ASN_DB = MAXMIND_DIR / "GeoLite2-ASN-Test.mmdb"


class FakeAPI:
    """Stands in for the internet: tests register responses by method + URL prefix.
    Anything not registered fails like a blocked network (httpx.ConnectError)."""

    def __init__(self):
        self.routes = []
        self.requests: list[httpx.Request] = []

    def add(self, method: str, url_prefix: str, response):
        """``response`` is an httpx.Response or a function request -> httpx.Response."""
        self.routes.append((method.upper(), url_prefix, response))

    def json(self, method: str, url_prefix: str, payload, status=200, headers=None):
        self.add(
            method,
            url_prefix,
            lambda req: httpx.Response(status, json=payload, headers=headers or {}),
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for method, prefix, response in self.routes:
            if request.method == method and str(request.url).startswith(prefix):
                return response(request) if callable(response) else response
        raise httpx.ConnectError("network is disabled in tests", request=request)


class FakeDNS:
    """DNS records by name (TXT) or by (name, type); anything else is NXDOMAIN."""

    def __init__(self):
        self.records: dict = {}
        self.queries: list[tuple[str, str]] = []

    async def __call__(self, name: str, rdtype: str = "TXT", timeout: float = 5.0) -> list[str]:
        self.queries.append((name, rdtype))
        value = self.records.get((name, rdtype))
        if value is None and rdtype == "TXT":
            value = self.records.get(name)
        if value is None:
            raise DNSLookupError(f"{name} does not exist", nxdomain=True)
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture(autouse=True)
def fake_api(monkeypatch):
    api = FakeAPI()

    def make_client(config):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(api),
            headers={"User-Agent": USER_AGENT},
            timeout=config.timeout,
            follow_redirects=True,  # same as the real client
        )

    monkeypatch.setattr(session_module, "make_http_client", make_client)
    return api


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    dns = FakeDNS()
    monkeypatch.setattr(session_module, "default_dns_resolve", dns)
    return dns


@pytest.fixture(autouse=True)
def _isolate_environment(tmp_path, monkeypatch):
    # The CLI reads ./.env, ./data/... and API keys from the environment; isolate them.
    monkeypatch.chdir(tmp_path)
    for key in list(os.environ):
        if key in KNOWN_KEYS or key.startswith("IPFINDER_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def config(tmp_path):
    """No .env, no persistent cache, no MaxMind or OUI files unless a test adds them."""
    return Config.load(
        env={},
        dotenv_path=None,
        use_cache=False,
        oui_db_path=tmp_path / "missing-oui.csv",
        maxmind_city_db=tmp_path / "missing-city.mmdb",
        maxmind_asn_db=tmp_path / "missing-asn.mmdb",
    )


def run(coro):
    return asyncio.run(coro)


def analyze_with(raw, config, providers=None, cache=None):
    async def go():
        async with Session(config, cache=cache or Cache(None)) as session:
            return await analyze(raw, session, providers)

    return run(go())


def analyze_many_with(inputs, config, providers=None, cache=None):
    async def go():
        async with Session(config, cache=cache or Cache(None)) as session:
            return await analyze_many(inputs, session, providers)

    return run(go())


def offline(text, oui_lookup=None):
    return offline_analyze(parse_ip(text), oui_lookup)


def ip(text):
    return ipaddress.ip_address(text)
