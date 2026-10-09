from pathlib import Path

import pytest

from ipfinder.analysis.oui import load_oui_db, make_lookup
from ipfinder.core.config import Config, read_dotenv
from ipfinder.core.validator import parse_ip
from ipfinder.providers.base import LookupContext
from ipfinder.providers.offline import OfflineProvider
from tests.conftest import run


def test_read_dotenv(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "\n"
        "IPINFO_TOKEN=abc123\n"
        "export ABUSEIPDB_API_KEY = 'quoted value'\n"
        'VIRUSTOTAL_API_KEY="double # not a comment"\n'
        "OTX_API_KEY=plain # trailing comment\n"
        "NOT_A_PAIR\n"
        "EMPTY=\n",
        encoding="utf-8",
    )
    assert read_dotenv(env) == {
        "IPINFO_TOKEN": "abc123",
        "ABUSEIPDB_API_KEY": "quoted value",
        "VIRUSTOTAL_API_KEY": "double # not a comment",
        "OTX_API_KEY": "plain",
        "EMPTY": "",
    }


def test_missing_dotenv_is_fine(tmp_path):
    assert read_dotenv(tmp_path / "nope.env") == {}


def test_environment_overrides_dotenv(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("IPINFO_TOKEN=from-file\nOTX_API_KEY=file-only\n", encoding="utf-8")
    config = Config.load(env={"IPINFO_TOKEN": "from-env"}, dotenv_path=env_file)
    assert config.key_for("IPINFO_TOKEN") == "from-env"
    assert config.key_for("OTX_API_KEY") == "file-only"
    assert config.key_for("VIRUSTOTAL_API_KEY") is None


def test_unknown_variables_and_empty_keys_are_ignored():
    config = Config.load(env={"PATH": "/bin", "IPINFO_TOKEN": ""}, dotenv_path=None)
    assert dict(config.api_keys) == {}


def test_oui_path_from_environment():
    config = Config.load(env={"IPFINDER_OUI_DB": "/tmp/x.csv"}, dotenv_path=None)
    assert config.oui_db_path == Path("/tmp/x.csv")


def test_unknown_profile_rejected():
    with pytest.raises(ValueError, match="Unknown profile"):
        Config.load(env={}, dotenv_path=None, profile="turbo")


OUI_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,001A2B,"Example Vendor, Inc.",1 Example Road\n'
    "MA-L,BADROW\n"
    "MA-L,ABCDEF,Other Corp,Somewhere\n"
)


def test_oui_lookup(tmp_path):
    path = tmp_path / "oui.csv"
    path.write_text(OUI_CSV, encoding="utf-8")
    assert load_oui_db(path) == {"001A2B": "Example Vendor, Inc.", "ABCDEF": "Other Corp"}
    lookup = make_lookup(path)
    assert lookup("00:1a:2b:3c:4d:5e") == "Example Vendor, Inc."
    assert lookup("ab-cd-ef-00-00-01") == "Other Corp"
    assert lookup("11:22:33:44:55:66") is None


def test_oui_missing_file(tmp_path):
    assert load_oui_db(tmp_path / "none.csv") is None
    assert make_lookup(tmp_path / "none.csv") is None


def test_offline_provider_uses_oui_database(tmp_path, config):
    path = tmp_path / "oui.csv"
    path.write_text(OUI_CSV, encoding="utf-8")
    cfg = Config.load(env={}, dotenv_path=None, oui_db_path=path)
    ctx = LookupContext(parsed=parse_ip("2001:db8::21a:2bff:fe3c:4d5e"), config=cfg)
    data = run(OfflineProvider().lookup(ctx))
    assert data["oui_database"] == f"loaded from {path}"
    assert data["ipv6"]["interface_id"]["vendor"] == "Example Vendor, Inc."

    ctx = LookupContext(parsed=parse_ip("2001:db8::21a:2bff:fe3c:4d5e"), config=config)
    assert run(OfflineProvider().lookup(ctx))["oui_database"].startswith("no OUI list at")


@pytest.mark.parametrize(
    "line,key,value",
    [
        ('IPINFO_TOKEN="abc123" # my token', "IPINFO_TOKEN", "abc123"),
        ("ABUSEIPDB_API_KEY='k1' # comment", "ABUSEIPDB_API_KEY", "k1"),
        ("OTX_API_KEY=abc\t# tab comment", "OTX_API_KEY", "abc"),
        ("export\tSPAMHAUS_DQS_KEY=tabexport", "SPAMHAUS_DQS_KEY", "tabexport"),
        ("GREYNOISE_API_KEY=a#b", "GREYNOISE_API_KEY", "a#b"),
        ('VIRUSTOTAL_API_KEY="has # inside" # and a comment', "VIRUSTOTAL_API_KEY", "has # inside"),
    ],
)
def test_read_dotenv_quotes_and_comments(tmp_path, line, key, value):
    env = tmp_path / ".env"
    env.write_text(line + "\n", encoding="utf-8")
    assert read_dotenv(env) == {key: value}


def test_read_dotenv_with_bom(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes("\ufeffIPINFO_TOKEN=x\n".encode())
    assert read_dotenv(env) == {"IPINFO_TOKEN": "x"}
