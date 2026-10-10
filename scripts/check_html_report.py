"""Open an IP Finder HTML report in a real browser and check that the map works.

    pip install playwright && playwright install chromium     (once)
    ipfinder lookup 8.8.8.8 -f html -o report.html
    python scripts/check_html_report.py report.html --screenshot report.png

Checks, with the file opened straight from disk (file://):
  * every map container was created and drew the country outlines,
  * the page logged no errors (a Content-Security-Policy violation would show here),
  * the page made no network request at all (everything is embedded).
Exit code 0 when all checks pass, 1 otherwise. Optional: not needed for the tool.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path)
    parser.add_argument("--screenshot", type=Path, help="save a screenshot of the first map")
    parser.add_argument("--browser", help="path to a Chromium executable (optional)")
    args = parser.parse_args(argv)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed: pip install playwright", file=sys.stderr)
        return 2

    problems: list[str] = []
    with sync_playwright() as p:
        options = {"executable_path": args.browser} if args.browser else {}
        browser = p.chromium.launch(**options)
        page = browser.new_page(viewport={"width": 1100, "height": 1250})
        requests: list[str] = []
        page.on("console", lambda m: m.type == "error" and problems.append(m.text))
        page.on("pageerror", lambda e: problems.append(str(e)))
        page.on("request", lambda r: r.url.startswith("http") and requests.append(r.url))
        page.goto(args.report.resolve().as_uri())
        page.wait_for_timeout(1500)
        expected = page.locator("div.map").count()
        drawn = page.locator(".map.leaflet-container").count()
        shapes = page.locator("div.map path.leaflet-interactive").count()
        if args.screenshot:
            page.screenshot(path=str(args.screenshot))
        browser.close()

    print(f"maps: {drawn} of {expected} drawn, {shapes} shapes")
    if drawn != expected or (expected and shapes == 0):
        problems.append("a map did not draw")
    if requests:
        problems.append(f"network requests made: {requests[:3]}")
    for problem in problems:
        print(f"problem: {problem}")
    print("OK" if not problems else "FAILED")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
