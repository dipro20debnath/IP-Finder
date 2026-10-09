import asyncio
import ipaddress
import os

import pytest

from ipfinder.analysis.offline import analyze as offline_analyze
from ipfinder.core.config import KNOWN_KEYS, Config
from ipfinder.core.validator import parse_ip


@pytest.fixture
def config(tmp_path):
    """A config that never reads the developer's real .env or OUI file."""
    return Config.load(env={}, dotenv_path=None, oui_db_path=tmp_path / "missing-oui.csv")


@pytest.fixture(autouse=True)
def _isolate_environment(tmp_path, monkeypatch):
    # The CLI reads ./.env and API keys from the environment; isolate every test.
    monkeypatch.chdir(tmp_path)
    for key in list(os.environ):
        if key in KNOWN_KEYS or key.startswith("IPFINDER_"):
            monkeypatch.delenv(key, raising=False)


def run(coro):
    return asyncio.run(coro)


def offline(text, oui_lookup=None):
    return offline_analyze(parse_ip(text), oui_lookup)


def ip(text):
    return ipaddress.ip_address(text)
