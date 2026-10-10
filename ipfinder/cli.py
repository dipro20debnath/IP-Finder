"""Command-line interface.

    ipfinder lookup 8.8.8.8 2001:4860:4860::8888
    ipfinder lookup 8.8.8.8 -f json -o report.json
    ipfinder lookup 8.8.8.8 1.1.1.1 -f html -o report.html   (map; opens offline)
    ipfinder batch ips.txt -f csv -o results.csv             (one row per address)
    cat ips.txt | ipfinder lookup -f json
    ipfinder lookup 8.8.8.8 --profile quick --no-cache
    ipfinder lookup 8.8.8.8 --active   (ping, traceroute, TLS certificate; asks first)
    ipfinder me            (your own public IP)
    ipfinder sources
    ipfinder update-lists  (Tor, cloud, Private Relay, VPN lists; GeoLite2 with a key)
    ipfinder update-lists tor-exits --force | ipfinder update-lists --status
    ipfinder cache info | ipfinder cache clear
    ipfinder 8.8.8.8       (shorthand for "lookup")
    ipfinder               (interactive prompt, like v1.0)

Reports go to stdout; prompts, status lines and errors go to stderr, so
"ipfinder -f json > out.json" always produces valid JSON.

Exit codes: 0 success, 1 at least one input was not a valid IP (or "me" could
not find your public IP, or a list download failed),
2 usage error (bad option, unreadable input file, unwritable output file, active
mode not confirmed),
3 internal error, 130 interrupted (Ctrl+C).
"""

from __future__ import annotations

import argparse
import asyncio
import codecs
import contextlib
import io
import os
import sys
from dataclasses import replace
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from ipfinder import __version__
from ipfinder.core.cache import Cache
from ipfinder.core.config import PROFILES, Config
from ipfinder.core.orchestrator import analyze_many
from ipfinder.core.session import Session
from ipfinder.core.text import display_safe
from ipfinder.lists.maxmind import update_maxmind
from ipfinder.lists.specs import SPECS
from ipfinder.lists.store import ListStore
from ipfinder.output import csv_out, html_report, json_out, terminal
from ipfinder.providers import PLANNED_PROVIDERS, default_providers
from ipfinder.providers.base import ProviderError
from ipfinder.providers.ipapi import public_ip
from ipfinder.providers.list_base import ListProvider

EXIT_OK, EXIT_INVALID_INPUT, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3
EXIT_INTERRUPTED = 130
COMMANDS = ("lookup", "batch", "me", "sources", "cache", "update-lists")
LIST_NAMES = (*SPECS, "maxmind")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipfinder",
        description="IP Finder: learn everything that can legitimately be known about an IP.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    output = argparse.ArgumentParser(add_help=False)
    output.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "csv", "html"),
        default="text",
        help="text (default), json (everything), csv (one row per address), "
        "html (report with a map; works offline)",
    )
    output.add_argument("-o", "--output", type=Path, help="write the result to this file")
    output.add_argument(
        "-v", "--verbose", action="store_true", help="also show Python flags and all ranges"
    )
    output.add_argument("--no-color", action="store_true", help="disable colours")
    output.add_argument(
        "-p",
        "--profile",
        choices=PROFILES,
        default=None,
        help="quick = offline + ip-api; standard (default) = every source that needs no "
        "threat-intel key; full = also threat intelligence (sends the address to more services)",
    )
    output.add_argument(
        "--no-cache", action="store_true", help="do not read or write data/cache.sqlite"
    )
    output.add_argument(
        "--active",
        action="store_true",
        help="also send packets to the target (TCP/ping round trip, traceroute, TLS "
        "certificate); asks for confirmation; only for systems you may test",
    )
    output.add_argument(
        "--authorized",
        action="store_true",
        help="with --active: confirm in advance (for scripts) that you may test the targets",
    )

    lookup = sub.add_parser("lookup", parents=[output], help="analyse one or more IP addresses")
    lookup.add_argument("ips", nargs="*", metavar="IP", help="IPv4/IPv6 address(es)")
    lookup.add_argument(
        "-i", "--input-file", type=Path, help="read addresses from a file (one per line)"
    )

    batch = sub.add_parser(
        "batch", parents=[output], help="analyse every address in a file (one per line)"
    )
    batch.add_argument("file", type=Path, help="text file: one address per line, # = comment")
    sub.add_parser("me", parents=[output], help="analyse your own public IP address")
    sub.add_parser("sources", help="show data sources, their status and API-key needs")
    cache = sub.add_parser("cache", help="show or clear the local lookup cache")
    cache.add_argument("action", choices=("info", "clear"))
    update = sub.add_parser(
        "update-lists",
        help="download Tor, cloud, Private Relay and VPN lists (and GeoLite2 with a MaxMind key)",
    )
    update.add_argument(
        "names", nargs="*", metavar="NAME", help=f"only these lists: {', '.join(LIST_NAMES)}"
    )
    update.add_argument(
        "--force", action="store_true", help="download even if the local copy is still fresh"
    )
    update.add_argument(
        "--status", action="store_true", help="only show what is downloaded and how old it is"
    )
    update.add_argument("--no-color", action="store_true", help="disable colours")
    return parser


def _read_lines(lines) -> list[str]:
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _read_input_file(path: Path) -> list[str]:
    """UTF-8 (with or without BOM) or UTF-16 with BOM, e.g. from Windows PowerShell."""
    data = path.read_bytes()
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = data.decode("utf-16")
    else:
        text = data.decode("utf-8-sig")
    return _read_lines(text.splitlines())


def _prompt(message: str) -> str:
    # The prompt goes to stderr so that "ipfinder -f json > out.json" stays valid JSON.
    if sys.stdin is None:  # started with stdin closed
        raise EOFError
    sys.stderr.write(message)
    sys.stderr.flush()
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.strip()


def _collect_inputs(args) -> list[str]:
    inputs = list(args.ips)
    if args.input_file:
        inputs += _read_input_file(args.input_file)
    if not inputs and sys.stdin is not None and not sys.stdin.isatty():
        inputs = _read_lines(sys.stdin)
    if not inputs:
        inputs = [_prompt("Enter an IP address: ")]
    return inputs


def _write_output(path: Path, text: str, messages: Console) -> bool:
    """Encode first, write a temporary file, then rename it over the target, so a
    failure (bad characters, full disk, ...) never truncates an existing report."""
    data = text.encode("utf-8", "backslashreplace")  # lone surrogates from odd argv bytes
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp.unlink()
        messages.print(Text(f"[!] Cannot write {path}: {exc}", style="red"))
        return False
    return True


def _stdout_is_utf8() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return encoding in ("utf8", "utf8sig")


def _config(args) -> Config:
    return Config.load(
        profile=args.profile, use_cache=not args.no_cache, active_mode=args.active or None
    )


ACTIVE_LIMIT = 20  # active probing is for checking a few systems, not for sweeps
CONFIRMATION = "I AM AUTHORIZED"


def _confirm_active(args, count: int, messages: Console) -> bool:
    """Ask before any packet is sent to a target (ADVANCED_PLAN.md section 9.1)."""
    if count > ACTIVE_LIMIT:
        messages.print(
            Text(
                f"[!] --active probes at most {ACTIVE_LIMIT} addresses per run "
                f"({count} given). Nothing was sent.",
                style="red",
            )
        )
        return False
    messages.print(
        Text(
            "[!] Active mode sends packets directly to the target "
            "(TCP handshakes on ports 443/80, ping, traceroute, a TLS handshake).\n"
            "    Only scan systems you own or have written permission to test.",
            style="yellow",
        )
    )
    if args.authorized:
        messages.print(Text("    --authorized given: continuing.", style="yellow"))
        return True
    if sys.stdin is None or not sys.stdin.isatty():
        messages.print(
            Text(
                "[!] Cannot ask for confirmation because input is not a terminal; add "
                "--authorized if you may test these systems. Nothing was sent.",
                style="red",
            )
        )
        return False
    try:
        answer = _prompt(f"    Type '{CONFIRMATION}' to continue: ")
    except EOFError:
        answer = ""
    if answer != CONFIRMATION:
        messages.print(Text("[!] Not confirmed. Nothing was sent.", style="red"))
        return False
    return True


async def _lookup_all(inputs: list[str], config: Config, on_progress=None):
    async with Session(config) as session:
        reports, errors = await analyze_many(inputs, session, on_progress=on_progress)
        return reports, errors, session.cache.warning


def _run_with_progress(inputs: list[str], config: Config, messages: Console):
    """A progress bar on stderr for several addresses (only on a terminal, so pipes
    and files stay clean)."""
    if len(inputs) < 2 or not messages.is_terminal:
        return asyncio.run(_lookup_all(inputs, config))
    columns = (
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    with Progress(*columns, console=messages, transient=True) as progress:
        task = progress.add_task("Looking up", total=len(inputs))

        def tick(done: int, total: int, current: str | None) -> None:
            label = f"Looking up {display_safe(current)[:40]}" if current else "Done"
            progress.update(task, completed=done, description=label)

        return asyncio.run(_lookup_all(inputs, config, tick))


async def _lookup_me(config: Config):
    async with Session(config) as session:
        address = await public_ip(session)
        reports, errors = await analyze_many([address], session)
        return reports, errors, session.cache.warning


def _cmd_lookup(args, console: Console, messages: Console) -> int:
    try:
        inputs = _collect_inputs(args)
    except (OSError, UnicodeError) as exc:
        reason = "not UTF-8 or UTF-16 text" if isinstance(exc, UnicodeError) else exc
        messages.print(Text(f"[!] Cannot read {args.input_file}: {reason}", style="red"))
        return EXIT_USAGE
    except EOFError:
        messages.print(Text("[!] No IP address given.", style="red"))
        return EXIT_USAGE
    if args.active and not _confirm_active(args, len(inputs), messages):
        return EXIT_USAGE

    reports, errors, warning = _run_with_progress(inputs, _config(args), messages)
    if warning:
        messages.print(Text(f"[!] {warning}", style="yellow"))
    return _emit(args, reports, errors, console, messages)


def _cmd_me(args, console: Console, messages: Console) -> int:
    if args.active and not _confirm_active(args, 1, messages):
        return EXIT_USAGE
    try:
        reports, errors, warning = asyncio.run(_lookup_me(_config(args)))
    except ProviderError as exc:
        messages.print(Text(f"[!] Could not find your public IP: {exc}", style="red"))
        return EXIT_INVALID_INPUT
    if warning:
        messages.print(Text(f"[!] {warning}", style="yellow"))
    return _emit(args, reports, errors, console, messages)


def _cmd_cache(args, console: Console) -> int:
    config = Config.load()
    cache = Cache(config.cache_path)
    try:
        if args.action == "clear":
            removed = cache.clear()
            console.print(Text(f"Removed {removed} cached entries from {config.cache_path}"))
        else:
            info = cache.stats()
            console.print(Text(f"Cache file: {info['path']} (persistent: {info['persistent']})"))
            for name, counts in sorted((info.get("providers") or {}).items()):
                console.print(
                    Text(f"  {name}: {counts['fresh']} fresh / {counts['entries']} total")
                )
    finally:
        cache.close()
    if cache.warning:
        console.print(Text(f"[!] {cache.warning}", style="yellow"))
    return EXIT_OK


def _emit(args, reports, errors, console: Console, messages: Console) -> int:
    if args.format == "json":
        # Non-ASCII stays readable in UTF-8 files; other stdout encodings get \uXXXX.
        ascii_only = not args.output and not _stdout_is_utf8()
        rendered = json_out.render(reports, errors, ascii_only=ascii_only) + "\n"
    elif args.format == "csv":
        rendered = csv_out.render(reports, errors)
        if args.output:
            rendered = "\ufeff" + rendered  # BOM: Excel then reads the file as UTF-8
    elif args.format == "html":
        rendered = html_report.render(reports, errors, args.verbose)
    elif args.output:
        buffer = io.StringIO()
        terminal.print_reports(
            Console(file=buffer, no_color=True, width=110), reports, errors, args.verbose
        )
        rendered = buffer.getvalue()
    else:
        terminal.print_reports(console, reports, errors, args.verbose)
        rendered = None

    if rendered is not None:
        if args.output:
            # Rendered fully before opening the file, so a failure never truncates it.
            if not _write_output(args.output, rendered, messages):
                return EXIT_USAGE
            kind = {"json": "JSON", "csv": "CSV", "html": "HTML"}.get(args.format, "text")
            messages.print(Text(f"Saved {kind} report to {args.output}", style="green"))
        else:
            sys.stdout.write(rendered)

    return EXIT_INVALID_INPUT if errors else EXIT_OK


def _cmd_sources(console: Console) -> int:
    config = Config.load()
    table = Table(title="IP Finder data sources")
    for col in ("Source", "Layer", "Profiles", "Status", "Needs"):
        table.add_column(col)
    full = replace(config, profile="full")
    for p in default_providers():
        reason = p.unavailable_reason(full)
        status = Text("ready", style="green") if reason is None else Text(reason, style="yellow")
        if p.requires_key:
            needs = p.requires_key
        elif p.optional_key:
            needs = f"{p.optional_key} (optional)"
        elif p.required_files(config):
            needs = "GeoLite2 .mmdb files"
        elif isinstance(p, ListProvider):
            needs = "ipfinder update-lists"
        elif p.active:
            needs = "--active (authorised targets only)"
        else:
            needs = "-"
        table.add_row(p.name, p.layer, ", ".join(p.profiles), status, needs)
    for p in PLANNED_PROVIDERS:
        if p.key is None:
            needs = "-"
        elif config.key_for(p.key):
            needs = Text(f"{p.key} set", style="green")
        else:
            needs = Text(f"{p.key} missing", style="yellow")
        table.add_row(p.name, p.layer, "-", Text(f"planned (Phase {p.phase})", style="dim"), needs)
    console.print(table)
    return EXIT_OK


def _list_row(table: Table, name: str, info: dict | None, result: Text) -> None:
    info = info or {}
    downloaded = "-"
    if info.get("fetched"):
        downloaded = f"{info['fetched']} ({info['age_hours']:g} h ago)"
    entries = info.get("entries")
    table.add_row(
        name,
        f"{entries:,}" if isinstance(entries, int) else "-",
        display_safe(str(info.get("published") or "-")),
        downloaded,
        result,
    )


async def _update_lists(config: Config, names: list[str], force: bool) -> list[dict]:
    async with Session(config) as session:
        limit = asyncio.Semaphore(4)

        async def one(name: str) -> dict:
            async with limit:
                return await session.lists.update(SPECS[name], session, force)

        results = list(await asyncio.gather(*(one(n) for n in names if n in SPECS)))
        if "maxmind" in names:
            results += await update_maxmind(session, config, force)
        return results


def _cmd_update_lists(args, console: Console, messages: Console) -> int:
    unknown = [n for n in args.names if n not in LIST_NAMES]
    if unknown:
        messages.print(
            Text(
                f"[!] Unknown list: {display_safe(', '.join(unknown))}. "
                f"Choose from: {', '.join(LIST_NAMES)}",
                style="red",
            )
        )
        return EXIT_USAGE
    config = Config.load(use_cache=False)
    names = list(dict.fromkeys(args.names)) or list(LIST_NAMES)
    store = ListStore(config.lists_dir)
    table = Table(title=f"Lists in {config.lists_dir}")
    for column in ("List", "Entries", "List date", "Downloaded", "Result"):
        table.add_column(column, overflow="fold")

    if args.status:
        for name in names:
            if name == "maxmind":
                for path in (config.maxmind_city_db, config.maxmind_asn_db):
                    state = "present" if Path(path).is_file() else "missing"
                    table.add_row(f"maxmind {Path(path).name}", "-", "-", "-", Text(state))
                continue
            spec = SPECS[name]
            info = store.info(spec)
            if info is None:
                result = Text("not downloaded", style="yellow")
            elif info["stale"]:
                result = Text("stale: run update-lists", style="yellow")
            else:
                result = Text("ok", style="green")
            _list_row(table, name, info, result)
        console.print(table)
        return EXIT_OK

    messages.print(Text(f"Downloading {len(names)} list(s) into {config.lists_dir} ..."))
    results = asyncio.run(_update_lists(config, names, args.force))
    failed = False
    for item in results:
        status = item["status"]
        if status == "updated":
            result = Text("updated", style="green")
        elif status == "fresh":
            result = Text("already fresh", style="dim")
        elif status == "skipped":
            result = Text(f"skipped: {item.get('error')}", style="dim")
        else:
            failed = True
            result = Text(f"failed: {display_safe(str(item.get('error')))}", style="red")
        _list_row(table, item["name"], item, result)
    console.print(table)
    return EXIT_INVALID_INPUT if failed else EXIT_OK


def _harden_streams() -> None:
    """Never crash on output the terminal's encoding cannot show (e.g. Bengali
    digits on a Windows cp1252 pipe); show an escape sequence instead."""
    for name, errors in (
        ("stdout", "backslashreplace"),
        ("stderr", "backslashreplace"),
        ("stdin", "replace"),
    ):
        stream = getattr(sys, name, None)
        try:
            stream.reconfigure(errors=errors)
        except (AttributeError, ValueError, io.UnsupportedOperation):
            pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # "ipfinder 8.8.8.8" and plain "ipfinder" are shorthand for "ipfinder lookup ..."
    if not argv or argv[0] not in COMMANDS + ("-h", "--help", "--version"):
        argv = ["lookup", *argv]
    args = _build_parser().parse_args(argv)
    _harden_streams()
    no_color = getattr(args, "no_color", False)
    console = Console(no_color=no_color)  # reports
    # prompts, status and errors; soft_wrap keeps file paths on one copyable line
    messages = Console(stderr=True, no_color=no_color, soft_wrap=True)
    try:
        if args.command == "sources":
            return _cmd_sources(console)
        if args.command == "cache":
            return _cmd_cache(args, console)
        if args.command == "update-lists":
            return _cmd_update_lists(args, console, messages)
        if args.command == "me":
            return _cmd_me(args, console, messages)
        if args.command == "batch":
            args.ips, args.input_file = [], args.file
        return _cmd_lookup(args, console, messages)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:  # last-resort guard: show a clear message, not a traceback
        text = f"[!] Internal error: {type(exc).__name__}: {display_safe(str(exc))}"
        try:
            messages.print(Text(text, style="bold red"))
        except Exception:
            sys.__stderr__.write(text.encode("ascii", "backslashreplace").decode() + "\n")
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
