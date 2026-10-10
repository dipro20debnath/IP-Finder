"""A single, self-contained HTML report with an interactive map.

* Works offline and from disk: Leaflet and Natural Earth country outlines are
  embedded (see assets/README.md), so opening the file contacts nobody.
  OpenStreetMap's street tiles are an optional layer; their servers refuse
  requests without a Referer, which a file opened from disk cannot send.
* The map shows each source's point, MaxMind's accuracy circle, the consensus
  point and, after --active, the speed-of-light circle around you.
* The full report below each map is the terminal report, exported by rich.
* Safety: all text is HTML-escaped; map labels are inserted as text, never as
  HTML; embedded data cannot close its <script> element; a Content-Security-
  Policy allows only the two inline scripts (by hash) and OSM tile images.
"""

from __future__ import annotations

import base64
import hashlib
import html
import io
import json
from datetime import datetime, timezone
from importlib.resources import files

from rich.console import Console
from rich.terminal_theme import MONOKAI

from ipfinder import DISCLAIMER, __version__
from ipfinder.core.models import IPReport
from ipfinder.core.text import display_safe
from ipfinder.output import terminal

ASSETS = files("ipfinder.output") / "assets"
SOURCE_COLOURS = {
    "geofeed": "#2a9d8f",
    "private-relay": "#6a4c93",
    "maxmind": "#1d4ed8",
    "ip-api": "#d97706",
    "ipinfo-lite": "#0891b2",
}
NO_MAP = "No source gave coordinates, so there is no map."
FOOTER = (
    "Map: Leaflet 1.9.4 (BSD 2-Clause) and Natural Earth 1:110m (public domain), embedded "
    "in this file. Street tiles, if switched on, come from OpenStreetMap (&copy; "
    "OpenStreetMap contributors)."
)


def _asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def _world() -> str:
    """The embedded map data, made safe the same way as our own JSON."""
    return _script_json(json.loads(_asset("world-110m.json")))


def _script_json(data) -> str:
    """JSON that is safe inside <script type="application/json">: ASCII only
    (no U+2028 surprises) and no "</" or "<!--" that could end the element."""
    text = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    return text.replace("</", "<\\/").replace("<!--", "<\\!--")


def _sha256(script: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()


def _e(value) -> str:
    return html.escape(display_safe(str(value)), quote=True)


def _ok(report: IPReport, name: str) -> dict:
    result = report.result(name)
    return result.data if result is not None and result.ok else {}


def map_data(report: IPReport, index: int | str) -> dict | None:
    """Points for the map, or None when no source gave coordinates."""
    points = []
    for name, colour in SOURCE_COLOURS.items():
        loc = _ok(report, name).get("location") or {}
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue
        place = ", ".join(str(v) for v in (loc.get("city"), loc.get("country_code")) if v)
        label = f"{name}: {place or f'{lat}, {lon}'}"
        if loc.get("accuracy_radius_km") is not None:
            label += f" (accuracy radius {loc['accuracy_radius_km']} km)"
        points.append(
            {
                "lat": lat,
                "lon": lon,
                "color": colour,
                "label": display_safe(label),
                "radius_km": loc.get("accuracy_radius_km"),
            }
        )
    verdict = report.verdict or {}
    location = verdict.get("location") or {}
    data: dict = {"id": f"map-{index}", "points": points}
    if "latitude" in location and len(points) > 1:
        data["consensus"] = {
            "lat": location["latitude"],
            "lon": location["longitude"],
            "label": f"Consensus (sources up to {location.get('spread_km', 0):g} km apart)",
        }
    check = verdict.get("rtt_check") or {}
    vantage = (_ok(report, "rtt").get("vantage")) or {}
    if check.get("max_distance_km") and "latitude" in vantage:
        data["speed_of_light"] = {
            "lat": vantage["latitude"],
            "lon": vantage["longitude"],
            "max_km": check["max_distance_km"],
            "label": (
                f"{check['rtt_ms']:g} ms round trip: the address must be inside this circle "
                f"({check['max_distance_km']:,.0f} km)"
            ),
        }
    if not points and "speed_of_light" not in data:
        return None
    return data


def _level(label: str | None) -> str:
    return {"high": "good", "medium": "mid", "low": "bad"}.get(label or "", "")


def _risk(label: str | None) -> str:
    return {"none found": "good", "low": "mid", "medium": "bad", "high": "bad"}.get(label or "", "")


def _cards(report: IPReport) -> str:
    verdict = report.verdict or {}
    cards = []

    def card(key: str, value: str, css: str = "") -> None:
        cards.append(
            f'<div class="card"><div class="k">{_e(key)}</div>'
            f'<div class="v {css}">{_e(value)}</div></div>'
        )

    connection = verdict.get("connection") or {}
    if connection:
        card("Connection type", connection.get("label", "?"))
    location = verdict.get("location") or {}
    if location:
        place = ", ".join(v for v in (location.get("city"), location.get("country_code")) if v)
        card("Location (consensus)", place or "-")
    confidence = verdict.get("location_confidence")
    if confidence:
        card(
            "Location confidence",
            f"{confidence['score']}/100 {confidence['label']}",
            _level(confidence["label"]),
        )
    for key, title in (("reputation", "Reputation"), ("exposure", "Exposure")):
        score = verdict.get(key)
        if score:
            card(title, f"{score['score']}/100 {score['label']}", _risk(score["label"]))
    check = verdict.get("rtt_check") or {}
    if check.get("checked"):
        card(
            "Speed-of-light check",
            "consistent" if check["plausible"] else "impossible location",
            "good" if check["plausible"] else "bad",
        )
    return f'<div class="cards">{"".join(cards)}</div>' if cards else ""


def _legend(data: dict) -> str:
    names = [n for n, c in SOURCE_COLOURS.items() if any(p["color"] == c for p in data["points"])]
    parts = [
        f'<span><i class="dot" style="background:{SOURCE_COLOURS[n]}"></i>{_e(n)}</span>'
        for n in names
    ]
    if "consensus" in data:
        parts.append('<span><i class="dot" style="border:2px solid #111827"></i>consensus</span>')
    if "speed_of_light" in data:
        parts.append(
            '<span><i class="dot" style="background:#b42318"></i>you, and the speed-of-light '
            "circle</span>"
        )
    return f'<p class="legend muted">{"".join(parts)}</p>'


def _terminal_html(report: IPReport, verbose: bool) -> str:
    console = Console(
        record=True, width=110, file=io.StringIO(), force_terminal=True, color_system="truecolor"
    )
    console.print(terminal.render_report(report, verbose))
    return console.export_html(
        theme=MONOKAI,  # readable colours on a dark background
        inline_styles=True,
        code_format=(
            '<pre class="rich" style="background:{background};color:{foreground}">'
            "<code>{code}</code></pre>"
        ),
    )


def section(report: IPReport, index: int | str, verbose: bool = False) -> tuple[str, dict | None]:
    """One address: its HTML (cards, map container, legend, full report) and the
    map data for IPFinderMap.draw(), or None when there is nothing to draw.
    The web dashboard shows the same section."""
    data = map_data(report, index)
    parts = [f"<h2>{_e(report.ip)}</h2>", _cards(report)]
    if data:
        parts.append(f'<div class="map" id="{data["id"]}" role="img" aria-label="map"></div>')
        parts.append(_legend(data))
        if (report.verdict or {}).get("anycast", {}).get("anycast"):
            parts.append(
                '<p class="warn">Anycast: this address is served from many places; the '
                "points show where databases place it, not where you reach it.</p>"
            )
    else:
        parts.append(f'<p class="muted">{NO_MAP}</p>')
    parts.append(
        f"<details open><summary>Full report</summary>{_terminal_html(report, verbose)}</details>"
    )
    return f'<section class="report">{"".join(parts)}</section>', data


def errors_section(errors: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{_e(err['input'])}</td><td>{_e(err['error'])}"
        f"{' - ' + _e(err['hint']) if err.get('hint') else ''}</td></tr>"
        for err in errors
    )
    return (
        f'<section class="report"><h2>Inputs that are not IP addresses</h2>'
        f'<table class="errors">{rows}</table></section>'
    )


def render(reports: list[IPReport], errors: list[dict], verbose: bool = False) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    maps, sections = [], []
    for index, report in enumerate(reports):
        html_section, data = section(report, index, verbose)
        sections.append(html_section)
        if data:
            maps.append(data)
    if errors:
        sections.append(errors_section(errors))

    leaflet_js, map_js = _asset("leaflet.js"), _asset("ipfinder-map.js")
    csp = (
        "default-src 'none'; "
        f"script-src '{_sha256(leaflet_js)}' '{_sha256(map_js)}'; "
        "style-src 'unsafe-inline'; img-src data: https://tile.openstreetmap.org; "
        "base-uri 'none'; form-action 'none'"
    )
    title = "IP Finder report" + (f": {reports[0].ip}" if len(reports) == 1 else "")
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{_e(title)}</title>"
        f"<style>{_asset('leaflet.css')}</style><style>{_asset('report.css')}</style>"
        "</head><body>"
        f"<header><h1>{_e(title)}</h1>"
        f'<p class="muted">IP Finder {_e(__version__)}, generated {_e(generated)}, '
        f"{len(reports)} address(es)</p>"
        f'<p class="warn">{_e(DISCLAIMER)}</p></header>'
        f"<main>{''.join(sections)}</main>"
        f'<footer class="muted">{FOOTER}</footer>'
        f"<script>{leaflet_js}</script>"
        f'<script type="application/json" id="ipf-world">{_world()}</script>'
        f'<script type="application/json" id="ipf-maps">{_script_json(maps)}</script>'
        f"<script>{map_js}</script>"
        "</body></html>\n"
    )
