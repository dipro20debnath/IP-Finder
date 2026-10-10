"""A ready-made demo of IP Finder for a presentation or viva (Phase 10).

    python scripts/demo.py --check       # check what the demo needs; runs nothing
    python scripts/demo.py               # the full demo (internet; about 10 minutes)
    python scripts/demo.py --offline     # no internet at all: local sources and
                                         #   MaxMind's test databases
    python scripts/demo.py --list        # only print the steps
    python scripts/demo.py --from 5      # start at step 5 (also --to N)

Each step shows its title, what to point at and the command as you would type
it, waits for Enter, then runs it. "s" + Enter skips a step, Ctrl+C stops.
Commands run with this Python ("python -m ipfinder ..."), so the virtual
environment does not have to be activated. docs/DEMO.md is the same demo
written out, with what to say at each step.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_DBS = ROOT / "tests" / "data" / "maxmind"
OUT = Path("demo-output")


Command = tuple[str, ...]  # ipfinder's arguments


@dataclass(frozen=True)
class Step:
    title: str
    look_at: str  # what to point at on the screen
    online: tuple[Command, ...] | None  # None = not part of this mode
    offline: tuple[Command, ...] | None
    ok_codes: tuple[int, ...] = (0,)
    kind: str = "command"  # command | serve | pytest
    opens: str | None = None  # file to open in the browser afterwards


STEPS = (
    Step(
        "One address, many layers",
        "Verdict first (connection type, location, confidence, each with its reasons), "
        "then every source with ok / skipped / error.",
        (("8.8.8.8",),),
        (("--offline", "81.2.69.142"),),
    ),
    Step(
        "Anycast: one address, many places",
        "Connection type 'Anycast service': the location is only shown to country level.",
        (("1.1.1.1",),),
        (("--offline", "8.8.8.8"),),
    ),
    Step(
        "Teredo: an IPv4 address and port hidden inside IPv6",
        "Embedded IPv4: client 8.8.8.8, port 40000, and the Teredo server; no database needed.",
        (("2001:0:4136:e378:8000:63bf:f7f7:f7f7",),),
        (("--offline", "2001:0:4136:e378:8000:63bf:f7f7:f7f7"),),
    ),
    Step(
        "EUI-64: a device's MAC address inside IPv6",
        "Interface identifier: MAC 00:1a:2b:3c:4d:5e and the privacy warning.",
        (("fe80::21a:2bff:fe3c:4d5e%eth0",),),
        (("fe80::21a:2bff:fe3c:4d5e%eth0",),),
    ),
    Step(
        "CGNAT: one public IP is not one person",
        "Shared Address Space (RFC 6598): many customers behind one address; no online lookup.",
        (("100.64.1.1",),),
        (("100.64.1.1",),),
    ),
    Step(
        "Careful input handling",
        "Each mistake is explained: octal-looking 010 (CVE-2021-29921), hex form, hostname. "
        "Exit code 1 is expected here.",
        (("lookup", "010.1.1.1", "0x7f000001", "google.com"),),
        (("lookup", "010.1.1.1", "0x7f000001", "google.com"),),
        ok_codes=(1,),
    ),
    Step(
        "Threat intelligence (full profile)",
        "Reputation and exposure scores with their reasons; sources without a key say "
        "'skipped: no API key' instead of failing.",
        (("--profile", "full", "8.8.8.8"),),
        None,
    ),
    Step(
        "Reports: HTML with a map, and CSV",
        "The HTML file opens in the browser even without internet; the CSV opens in Excel.",
        (
            ("lookup", "8.8.8.8", "1.1.1.1", "-f", "html", "-o", f"{OUT}/report.html"),
            ("lookup", "8.8.8.8", "1.1.1.1", "-f", "csv", "-o", f"{OUT}/report.csv"),
        ),
        (
            (
                "lookup",
                "--offline",
                "81.2.69.142",
                "89.160.20.112",
                "-f",
                "html",
                "-o",
                f"{OUT}/report.html",
            ),
            (
                "lookup",
                "--offline",
                "81.2.69.142",
                "89.160.20.112",
                "-f",
                "csv",
                "-o",
                f"{OUT}/report.csv",
            ),
        ),  # fmt: skip
        opens=f"{OUT}/report.html",
    ),
    Step(
        "Web dashboard",
        "Type an address, press Look up; results stream in with maps; download buttons. "
        "Press Enter here to stop the server.",
        (("serve", "--open"),),
        (("serve", "--offline", "--open"),),
        kind="serve",
    ),
    Step(
        "Responsible use: active probes need permission",
        "The warning and the 'I AM AUTHORIZED' question. Type anything else: nothing is sent.",
        (("--active", "8.8.8.8"),),
        (("--active", "192.168.1.1"),),  # private: even if confirmed, probes do not run
        ok_codes=(0, 2),
    ),
    Step(
        "Quality: the test suite",
        "Over six hundred tests, all offline (fake HTTP and DNS), including this offline demo.",
        ((),),
        ((),),
        kind="pytest",
    ),
)


def shown(step: Step, args: Command) -> str:
    """The command as a person would type it."""
    if step.kind == "pytest":
        return "python -m pytest -q"
    quoted = [a if re.fullmatch(r"[\w.:%/=+-]+", a) else f'"{a}"' for a in args]
    return " ".join(["ipfinder", *quoted])


def steps_for(offline: bool) -> list[tuple[int, Step, tuple[Command, ...] | None]]:
    return [(n, s, s.offline if offline else s.online) for n, s in enumerate(STEPS, 1)]


def environment(offline: bool) -> dict[str, str]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if offline:  # MaxMind's official test databases stand in for GeoLite2
        env["IPFINDER_MAXMIND_CITY_DB"] = str(TEST_DBS / "GeoLite2-City-Test.mmdb")
        env["IPFINDER_MAXMIND_ASN_DB"] = str(TEST_DBS / "GeoLite2-ASN-Test.mmdb")
    return env


# ------------------------------------------------------------------ checks


def check(offline: bool) -> int:
    """Everything the demo needs, without running it. 1 if something required is missing."""
    problems = 0

    def line(ok: bool | None, text: str) -> None:
        nonlocal problems
        mark = {True: "ok  ", False: "FAIL", None: "note"}[ok]
        problems += ok is False
        print(f"  [{mark}] {text}")

    print(f"Demo check ({'offline' if offline else 'online'} mode)")
    line(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (3.10 or newer)")
    try:
        import ipfinder

        line(True, f"ipfinder {ipfinder.__version__} importable")
    except ImportError:
        line(False, 'ipfinder is not installed: python -m pip install -e ".[dev]"')
        return 1
    for module, needed_for in (("fastapi", "the dashboard"), ("uvicorn", "the dashboard"),
                               ("pytest", "the test step")):  # fmt: skip
        found = importlib.util.find_spec(module) is not None
        line(found, f"{module} ({needed_for})" + ("" if found else ': pip install -e ".[dev]"'))
    if offline:
        found = (TEST_DBS / "GeoLite2-City-Test.mmdb").is_file()
        line(found, "MaxMind test databases in tests/data/maxmind")
        return 1 if problems else 0

    from ipfinder.core.config import Config
    from ipfinder.lists.specs import SPECS
    from ipfinder.lists.store import ListStore

    config = Config.load()
    line(
        config.maxmind_city_db.is_file() or None,
        f"GeoLite2 City at {config.maxmind_city_db}"
        + ("" if config.maxmind_city_db.is_file() else " (missing: city-level location is weaker)"),
    )
    store = ListStore(config.lists_dir)
    have = [name for name, spec in SPECS.items() if store.has(spec)]
    line(
        bool(have) or None,
        f"{len(have)} of {len(SPECS)} lists downloaded"
        + ("" if have else ": run 'ipfinder update-lists' before the demo"),
    )
    keys = sorted(config.api_keys)
    line(None, f"API keys in .env: {', '.join(keys) if keys else 'none (full profile will skip)'}")
    try:
        socket.create_connection(("ip-api.com", 80), timeout=3).close()
        line(True, "internet: ip-api.com reachable")
    except OSError:
        line(False, "internet: ip-api.com not reachable; use --offline")
    return 1 if problems else 0


# ------------------------------------------------------------------ running


def ipfinder(args: Command, env, interactive: bool) -> int:
    stdin = None if interactive else subprocess.DEVNULL  # rehearsals never wait for input
    return subprocess.run(
        [sys.executable, "-m", "ipfinder", *args], env=env, stdin=stdin
    ).returncode


def run_serve(args: Command, env, interactive: bool, browser: bool) -> bool:
    if not (interactive and browser):
        args = tuple(a for a in args if a != "--open")
    with socket.socket() as s:  # a free port, so a second demo never collides
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = subprocess.Popen(
        [sys.executable, "-m", "ipfinder", *args, "--port", str(port)],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        url = None
        deadline = time.monotonic() + 30
        while url is None and time.monotonic() < deadline:
            text = server.stderr.readline()
            if not text and server.poll() is not None:
                break
            sys.stderr.write(text)
            match = re.search(r"Open: (http://\S+)", text)
            url = match.group(1) if match else None
        if url is None:
            print("The dashboard did not start (is the [web] extra installed?).")
            return False
        if interactive:
            input("Dashboard running. Press Enter to stop it... ")
            return True
        # The link is printed just before the server starts listening: retry briefly.
        token = url.split("#token=", 1)[1]
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/info", headers={"Authorization": f"Bearer {token}"}
        )
        no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(30):
            try:
                with no_proxy.open(request, timeout=5) as response:
                    print(f"Dashboard answered at http://127.0.0.1:{port}/ (stopped again).")
                    return response.status == 200
            except OSError:
                time.sleep(0.5)
        print("The dashboard did not answer.")
        return False
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--offline", action="store_true", help="no internet needed")
    parser.add_argument("--list", action="store_true", help="print the steps and stop")
    parser.add_argument("--check", action="store_true", help="check what the demo needs")
    parser.add_argument("--from", dest="first", type=int, default=1, metavar="N")
    parser.add_argument("--to", dest="last", type=int, default=len(STEPS), metavar="N")
    parser.add_argument("--yes", action="store_true", help="do not pause (rehearsal, tests)")
    parser.add_argument("--no-browser", action="store_true", help="do not open browser windows")
    args = parser.parse_args(argv)
    if args.check:
        return check(args.offline)

    plan = [(n, s, c) for n, s, c in steps_for(args.offline) if args.first <= n <= args.last]
    if args.list:
        for n, step, commands in plan:
            print(f"{n:2}. {step.title}")
            for cmd in commands or ():
                print(f"    {shown(step, cmd)}")
            if commands is None:
                print("    (not part of this mode)")
            print(f"    look at: {step.look_at}")
        return 0

    env = environment(args.offline)
    interactive = not args.yes
    if args.offline:
        print("Offline demo: nothing is sent anywhere. Locations come from MaxMind's")
        print("official TEST databases (e.g. 81.2.69.142 = London), not from real data.")
    failed = []
    for n, step, commands in plan:
        rule = "=" * 78
        print(f"\n{rule}\n Step {n}/{len(STEPS)}: {step.title}\n{rule}")
        print(f" Look at: {step.look_at}")
        if commands is None:
            print(" (not part of the offline demo)")
            continue
        print("".join(f"\n $ {shown(step, cmd)}" for cmd in commands) + "\n")
        if interactive and input(" Enter = run, s = skip: ").strip().lower() == "s":
            continue
        if step.kind == "serve":
            ok = run_serve(commands[0], env, interactive, not args.no_browser)
        elif step.kind == "pytest":
            ok = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT).returncode == 0
        else:
            OUT.mkdir(exist_ok=True)
            ok = all(ipfinder(cmd, env, interactive) in step.ok_codes for cmd in commands)
            if ok and step.opens and not args.no_browser:
                webbrowser.open(Path(step.opens).resolve().as_uri())
        if not ok:
            failed.append(n)
            print(f"\n [!] Step {n} did not finish as expected.")
    print("\nDemo finished. " + (f"Problems in steps {failed}." if failed else "All steps ran."))
    return 0 if not failed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nDemo stopped.")
        raise SystemExit(130) from None
