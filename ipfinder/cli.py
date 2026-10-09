"""Command-line interface.

    ipfinder lookup 8.8.8.8 2001:4860:4860::8888
    ipfinder lookup 8.8.8.8 -f json -o report.json
    cat ips.txt | ipfinder lookup -f json
    ipfinder lookup 8.8.8.8 --profile quick --no-cache
    ipfinder me            (your own public IP)
    ipfinder sources
    ipfinder cache info | ipfinder cache clear
    ipfinder 8.8.8.8       (shorthand for "lookup")
    ipfinder               (interactive prompt, like v1.0)

Reports go to stdout; prompts, status lines and errors go to stderr, so
"ipfinder -f json > out.json" always produces valid JSON.

Exit codes: 0 success, 1 at least one input was not a valid IP (or "me" could
not find your public IP),
2 usage error (bad option, unreadable input file, unwritable output file),
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
from rich.table import Table
from rich.text import Text

from ipfinder import __version__
from ipfinder.core.cache import Cache
from ipfinder.core.config import PROFILES, Config
from ipfinder.core.orchestrator import analyze_many
from ipfinder.core.session import Session
from ipfinder.core.text import display_safe
from ipfinder.output import json_out, terminal
from ipfinder.providers import PLANNED_PROVIDERS, default_providers
from ipfinder.providers.base import ProviderError
from ipfinder.providers.ipapi import public_ip

EXIT_OK, EXIT_INVALID_INPUT, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3
EXIT_INTERRUPTED = 130
COMMANDS = ("lookup", "me", "sources", "cache")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipfinder",
        description="IP Finder: learn everything that can legitimately be known about an IP.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("-f", "--format", choices=("text", "json"), default="text")
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
        help="quick = offline + ip-api; standard (default) and full = every available source",
    )
    output.add_argument(
        "--no-cache", action="store_true", help="do not read or write data/cache.sqlite"
    )

    lookup = sub.add_parser("lookup", parents=[output], help="analyse one or more IP addresses")
    lookup.add_argument("ips", nargs="*", metavar="IP", help="IPv4/IPv6 address(es)")
    lookup.add_argument(
        "-i", "--input-file", type=Path, help="read addresses from a file (one per line)"
    )

    sub.add_parser("me", parents=[output], help="analyse your own public IP address")
    sub.add_parser("sources", help="show data sources, their status and API-key needs")
    cache = sub.add_parser("cache", help="show or clear the local lookup cache")
    cache.add_argument("action", choices=("info", "clear"))
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
    return Config.load(profile=args.profile, use_cache=not args.no_cache)


async def _lookup_all(inputs: list[str], config: Config):
    async with Session(config) as session:
        reports, errors = await analyze_many(inputs, session)
        return reports, errors, session.cache.warning


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

    reports, errors, warning = asyncio.run(_lookup_all(inputs, _config(args)))
    if warning:
        messages.print(Text(f"[!] {warning}", style="yellow"))
    return _emit(args, reports, errors, console, messages)


def _cmd_me(args, console: Console, messages: Console) -> int:
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
            kind = "JSON" if args.format == "json" else "text"
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
        needs = p.requires_key or ("GeoLite2 .mmdb files" if p.required_files(config) else "-")
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
        if args.command == "me":
            return _cmd_me(args, console, messages)
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
