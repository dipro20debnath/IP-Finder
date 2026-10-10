"""Phase 8: CSV and HTML reports, the batch command and progress reporting."""

import base64
import csv
import dataclasses
import hashlib
import io
import json
import re

import pytest

from ipfinder.cli import main
from ipfinder.core.cache import Cache
from ipfinder.core.models import ProviderResult
from ipfinder.core.orchestrator import analyze_many
from ipfinder.core.session import Session
from ipfinder.output import csv_out, html_report
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from tests.conftest import ASN_DB, CITY_DB, analyze_with, run

HOSTILE = '</script><img src=x onerror="alert(1)">'


@pytest.fixture
def mm(config):
    return dataclasses.replace(config, maxmind_city_db=CITY_DB, maxmind_asn_db=ASN_DB)


@pytest.fixture
def london(mm):
    return analyze_with("81.2.69.142", mm, [OfflineProvider(), MaxMindProvider()])


def tamper(report, provider, data):
    """Replace one provider's data (to inject hostile or extra values)."""
    report.results = [r for r in report.results if r.provider != provider]
    report.results.append(ProviderResult(provider, "L?", True, data))
    return report


# ------------------------------------------------------------------ CSV


def parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_row(london):
    rows = parse_csv(csv_out.render([london], []))
    assert list(rows[0]) == list(csv_out.COLUMNS)
    row = rows[0]
    assert row["ip"] == "81.2.69.142" and row["country"] == "GB" and row["city"] == "London"
    assert row["longitude"] == "-0.0931"  # a number: no apostrophe added
    assert row["location_confidence"] == "90"
    assert row["sources_ok"] == "maxmind"


def test_csv_blocks_formula_injection(london):
    tamper(london, "maxmind", {"network": {"asn": 64500, "as_name": '=HYPERLINK("http://x","y")'}})
    row = parse_csv(csv_out.render([london], []))[0]
    assert row["as_name"] == '\'=HYPERLINK("http://x","y")'
    assert row["asn"] == "64500"
    for text in ("+1", "-x", "@SUM(A1)"):
        assert csv_out._safe(text).startswith("'")
    assert csv_out._safe("\tcmd") == "\\x09cmd"  # control characters are escaped first
    assert csv_out._safe(-12.5) == -12.5 and csv_out._safe(True) == "yes"
    assert csv_out._safe(["a", "b"]) == "a; b" and csv_out._safe(None) == ""
    assert csv_out._safe("ESC\x1b[31m") == "ESC\\x1b[31m"


def test_csv_errors_and_cli(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPFINDER_MAXMIND_CITY_DB", str(CITY_DB))
    assert main(["lookup", "-f", "csv", "--no-cache", "81.2.69.142", "nonsense"]) == 1
    rows = parse_csv(capsys.readouterr().out)
    assert rows[0]["city"] == "London" and rows[1]["input"] == "nonsense"
    assert rows[1]["error"] and rows[1]["ip"] == ""

    out = tmp_path / "out.csv"
    assert main(["lookup", "-f", "csv", "-o", str(out), "--no-cache", "81.2.69.142"]) == 0
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM, so Excel reads UTF-8
    assert "Saved CSV report" in capsys.readouterr().err


# ------------------------------------------------------------------ HTML


def inline_scripts(page):
    return re.findall(r"<script>(.*?)</script>", page, flags=re.S)


def test_html_is_self_contained_with_a_strict_policy(london):
    page = html_report.render([london], [])
    assert page.startswith("<!doctype html>")
    assert "<script src" not in page and "<link" not in page  # nothing is fetched
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert (
        "default-src 'none'" in csp
        and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    )
    scripts = inline_scripts(page)
    assert len(scripts) == 2  # Leaflet and the map script; everything else is data
    for script in scripts:
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        assert f"'sha256-{digest}'" in csp  # the policy really allows exactly these
    assert "L.map(" in scripts[1] and "Leaflet 1.9.4" in page
    maps = json.loads(re.search(r'id="ipf-maps">(.*?)</script>', page, flags=re.S).group(1))
    assert maps == [
        {
            "id": "map-0",
            "points": [
                {
                    "lat": 51.5142,
                    "lon": -0.0931,
                    "color": "#1d4ed8",
                    "label": "maxmind: London, GB (accuracy radius 10 km)",
                    "radius_km": 10,
                }
            ],
        }
    ]
    world = json.loads(re.search(r'id="ipf-world">(.*?)</script>', page, flags=re.S).group(1))
    assert len(world["countries"]["features"]) == 177 and len(world["cities"]) == 243
    assert "90/100 high" in page and "Full report" in page


def test_html_escapes_hostile_text(london):
    location = {"country_code": "GB", "city": HOSTILE, "latitude": 51.5, "longitude": -0.1}
    tamper(london, "maxmind", {"location": location})
    page = html_report.render([london], [{"input": HOSTILE, "error": "bad", "hint": None}])
    assert HOSTILE not in page  # nowhere raw: not in data, cards, terminal export or errors
    assert "&lt;/script&gt;&lt;img" in page  # shown as text
    data = re.search(r'id="ipf-maps">(.*?)</script>', page, flags=re.S).group(1)
    assert "<\\/script>" in data and HOSTILE in json.loads(data)[0]["points"][0]["label"]


def test_html_without_coordinates_and_with_speed_of_light(config, london):
    private = analyze_with("192.168.1.1", config, [OfflineProvider()])
    page = html_report.render([private], [])
    assert "No source gave coordinates, so there is no map." in page
    assert "Private-Use: not reachable from the internet" in page

    london.verdict["rtt_check"] = {
        "rtt_ms": 4.0,
        "max_distance_km": 400.0,
        "checked": True,
        "plausible": True,
        "distance_km": 10.0,
        "slack_km": 20,
    }
    tamper(london, "rtt", {"min_rtt_ms": 4.0, "vantage": {"latitude": 51.4, "longitude": -0.2}})
    data = html_report.map_data(london, 0)
    assert data["speed_of_light"]["max_km"] == 400.0
    assert "must be inside this circle" in data["speed_of_light"]["label"]
    assert "Speed-of-light check" in html_report.render([london], [])


def test_html_cli(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPFINDER_MAXMIND_CITY_DB", str(CITY_DB))
    out = tmp_path / "report.html"
    assert (
        main(["lookup", "-f", "html", "-o", str(out), "--no-cache", "81.2.69.142", "89.160.20.112"])
        == 0
    )
    page = out.read_text(encoding="utf-8")
    assert page.count('class="map"') == 2 and "Linköping" in page
    assert "Saved HTML report" in capsys.readouterr().err


# ------------------------------------------------------------------ batch and progress


def test_batch_command(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPFINDER_MAXMIND_CITY_DB", str(CITY_DB))
    ips = tmp_path / "ips.txt"
    ips.write_text("81.2.69.142  # London\n\n89.160.20.112\n", encoding="utf-8")
    assert main(["batch", str(ips), "-f", "csv", "--no-cache"]) == 0
    rows = parse_csv(capsys.readouterr().out)
    assert [r["city"] for r in rows] == ["London", "Linköping"]


def test_progress_callback(mm):
    calls = []

    async def go():
        async with Session(mm, cache=Cache(None)) as session:
            return await analyze_many(
                ["81.2.69.142", "bad", "89.160.20.112"],
                session,
                [OfflineProvider()],
                on_progress=lambda done, total, raw: calls.append((done, total, raw)),
            )

    reports, errors = run(go())
    assert len(reports) == 2 and len(errors) == 1
    assert calls == [
        (0, 3, "81.2.69.142"),
        (1, 3, "bad"),
        (2, 3, "89.160.20.112"),
        (3, 3, None),
    ]
