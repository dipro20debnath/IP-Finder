"""Start the web dashboard and use it in a real browser, as a person would.

    pip install playwright && playwright install chromium     (once)
    python scripts/check_dashboard.py --screenshot dashboard.png 8.8.8.8 1.1.1.1

It starts "ipfinder serve" on a free port (with this shell's environment, so
.env, API keys and IPFINDER_* settings apply), opens the printed link, types
the addresses, presses "Look up", waits for the result, then checks:
  * every result with coordinates drew its map,
  * the "HTML report" download works and is a report,
  * opening the page without the token shows the token form instead,
  * the page logged no errors (a Content-Security-Policy violation would show)
    and contacted no server except the dashboard itself.
Exit code 0 when all checks pass, 1 otherwise. Optional: not needed for the tool.
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int) -> tuple[subprocess.Popen, str]:
    server = subprocess.Popen(
        [sys.executable, "-m", "ipfinder", "serve", "--port", str(port), "--no-cache"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        line = server.stderr.readline()
        match = re.search(r"Open: (http://\S+)", line)
        if match:
            return server, match.group(1)
        if not line and server.poll() is not None:
            break
    server.kill()
    raise SystemExit("the server did not start (is the [web] extra installed?)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("addresses", nargs="*", default=["8.8.8.8", "1.1.1.1"])
    parser.add_argument("--screenshot", type=Path, help="save a screenshot of the result")
    parser.add_argument("--browser", help="path to a Chromium executable (optional)")
    args = parser.parse_args(argv)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed: pip install playwright", file=sys.stderr)
        return 2

    port = free_port()
    server, url = start_server(port)
    base = f"http://127.0.0.1:{port}"
    problems: list[str] = []
    try:
        with sync_playwright() as p:
            options = {"executable_path": args.browser} if args.browser else {}
            browser = p.chromium.launch(**options)
            context = browser.new_context(viewport={"width": 1100, "height": 1300})
            page = context.new_page()
            page.on("console", lambda m: m.type == "error" and problems.append(m.text))
            page.on("pageerror", lambda e: problems.append(str(e)))
            outside: list[str] = []
            page.on("request", lambda r: not r.url.startswith(base) and outside.append(r.url))

            page.goto(url)
            if "#token=" in page.url:
                problems.append("the token stayed in the address bar")
            page.wait_for_selector("#go:not([disabled])", timeout=15000)
            page.fill("#addresses", "\n".join(args.addresses))
            page.click("#go")
            # A selector, not wait_for_function: the page's CSP forbids eval (good).
            page.wait_for_selector("#status.bad, #status:text-matches('^Done')", timeout=120000)
            status = page.text_content("#status")
            sections = page.locator("#results section.report").count()
            expected = page.locator("#results div.map").count()
            drawn = page.locator("#results .map.leaflet-container").count()
            shapes = page.locator("#results path.leaflet-interactive").count()
            print(f"status: {status}")
            print(f"results: {sections}; maps: {drawn} of {expected} drawn, {shapes} shapes")
            if not status.startswith("Done"):
                problems.append(f"the lookup failed: {status}")
            if drawn != expected or (expected and shapes == 0):
                problems.append("a map did not draw")
            if args.screenshot:
                page.screenshot(path=str(args.screenshot))

            with page.expect_download() as download_info:
                page.click("#exports button[data-format=html]")
            download = download_info.value
            with tempfile.TemporaryDirectory() as tmp:
                saved = Path(tmp) / download.suggested_filename
                download.save_as(saved)
                report = saved.read_text(encoding="utf-8")
            print(f"download: {download.suggested_filename}, {len(report):,} characters")
            if not report.startswith("<!doctype html>") or report.count('class="report"') < 1:
                problems.append("the HTML report download is not a report")

            plain = context.new_page()
            plain.goto(base + "/")
            try:
                plain.wait_for_selector("#token-panel:not([hidden])", timeout=5000)
                print("without the token: the token form is shown")
            except Exception:
                problems.append("without a token the page did not ask for one")
            browser.close()
            if outside:
                problems.append(f"requests to other servers: {outside[:3]}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()

    for problem in problems:
        print(f"problem: {problem}")
    print("OK" if not problems else "FAILED")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
