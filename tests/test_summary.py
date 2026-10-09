from datetime import datetime, timezone

from ipfinder.analysis.summary import build_summary
from ipfinder.core.models import ProviderResult


def ok(name, **data):
    return ProviderResult(name, "L2", True, data=data)


NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def test_prefers_maxmind_for_map_and_reports_agreement():
    results = {
        "ip-api": ok(
            "ip-api",
            location={
                "country_code": "us",
                "latitude": 39.0,
                "longitude": -77.5,
                "timezone": "America/New_York",
            },
        ),
        "maxmind": ok(
            "maxmind",
            location={
                "country_code": "US",
                "latitude": 37.751,
                "longitude": -97.822,
                "accuracy_radius_km": 1000,
            },
        ),
    }
    summary = build_summary(results, now=NOW)
    assert summary["map_source"] == "maxmind"
    assert summary["coordinates"] == {
        "latitude": 37.751,
        "longitude": -97.822,
        "accuracy_radius_km": 1000,
    }
    assert summary["countries_agree"] is True
    assert summary["map_links"]["google_maps"] == "https://www.google.com/maps?q=37.751,-97.822"
    # New York on 2026-10-09 is on daylight time
    assert summary["local_time"] == {
        "timezone": "America/New_York",
        "time": "2026-10-09 08:00",
        "utc_offset": "UTC-04:00",
    }


def test_dhaka_local_time_and_asn_disagreement():
    results = {
        "ip-api": ok("ip-api", location={"timezone": "Asia/Dhaka"}, network={"asn": 24389}),
        "team-cymru": ok("team-cymru", network={"asn": 24432}),
    }
    summary = build_summary(results, now=NOW)
    assert summary["local_time"]["time"] == "2026-10-09 18:00"
    assert summary["local_time"]["utc_offset"] == "UTC+06:00"
    assert summary["asn_by_source"] == {"team-cymru": 24432, "ip-api": 24389}
    assert summary["asns_agree"] is False
    assert "map_links" not in summary


def test_failed_and_unknown_inputs_are_ignored():
    results = {
        "ip-api": ProviderResult("ip-api", "L2", False, error="down"),
        "maxmind": ok("maxmind", location={"timezone": "Not/AZone"}),
    }
    assert build_summary(results, now=NOW) == {}
