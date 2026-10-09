"""Command-line interface.

    ipfinder lookup 8.8.8.8 2001:4860:4860::8888
    ipfinder lookup 8.8.8.8 -f json -o report.json
    cat ips.txt | ipfinder lookup -f json
    ipfinder sources
    ipfinder 8.8.8.8       (shorthand for "lookup")
    ipfinder               (interactive prompt, like v1.0)

Exit codes: 0 success, 1 at least one input was not a valid IP,
2 command-line usage error, 3 internal error, 130 interrupted (Ctrl+C).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ipfinder import __version__
from ipfinder.core.config import Config
from ipfinder.core.orchestrator import analyze_many
from ipfinder.output import json_out, terminal
from ipfinder.providers import PLANNED_PROVIDERS, default_providers

EXIT_OK, EXIT_INVALID_INPUT, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3
EXIT_INTERRUPTED = 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipfinder",
        description="IP Finder: learn everything that can legitimately be known about an IP.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    lookup = sub.add_parser("lookup", help="analyse one or more IP addresses")
    lookup.add_argument("ips", nargs="*", metavar="IP", help="IPv4/IPv6 address(es)")
    lookup.add_argument(
        "-i", "--input-file", type=Path, help="read addresses from a file (one per line)"
    )
    lookup.add_argument("-f", "--format", choices=("text", "json"), default="text")
    lookup.add_argument("-o", "--output", type=Path, help="write the result to this file")
    lookup.add_argument(
        "-v", "--verbose", action="store_true", help="also show Python flags and all ranges"
    )
    lookup.add_argument("--no-color", action="store_true", help="disable colours")

    sub.add_parser("sources", help="show data sources, their phase and API-key status")
    return parser


def _read_lines(lines) -> list[str]:
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _collect_inputs(args) -> list[str]:
    inputs = list(args.ips)
    if args.input_file:
        inputs += _read_lines(args.input_file.read_text(encoding="utf-8").splitlines())
    if not inputs and not sys.stdin.isatty():
        inputs = _read_lines(sys.stdin)
    if not inputs:
        inputs = [input("Enter an IP address: ")]
    return inputs


def _cmd_lookup(args, console: Console) -> int:
    try:
        inputs = _collect_inputs(args)
    except OSError as exc:
        console.print(Text(f"[!] Cannot read {args.input_file}: {exc}", style="red"))
        return EXIT_USAGE
    except (EOFError, KeyboardInterrupt):
        console.print(Text("[!] No IP address given.", style="red"))
        return EXIT_USAGE

    config = Config.load()
    reports, errors = asyncio.run(analyze_many(inputs, config))

    if args.format == "json":
        rendered = json_out.render(reports, errors)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
            console.print(Text(f"Saved JSON report to {args.output}", style="green"))
        else:
            print(rendered)
    elif args.output:
        with args.output.open("w", encoding="utf-8") as fh:
            terminal.print_reports(
                Console(file=fh, no_color=True, width=110), reports, errors, args.verbose
            )
        console.print(Text(f"Saved text report to {args.output}", style="green"))
    else:
        terminal.print_reports(console, reports, errors, args.verbose)

    return EXIT_INVALID_INPUT if errors else EXIT_OK


def _cmd_sources(console: Console) -> int:
    config = Config.load()
    table = Table(title="IP Finder data sources")
    for col in ("Source", "Layer", "Phase", "Status", "API key"):
        table.add_column(col)
    for p in default_providers():
        table.add_row(p.name, p.layer, "1", Text("active", style="green"), "not needed")
    for p in PLANNED_PROVIDERS:
        if p.key is None:
            key = "not needed"
        elif config.key_for(p.key):
            key = Text(f"{p.key} set", style="green")
        else:
            key = Text(f"{p.key} missing", style="yellow")
        table.add_row(p.name, p.layer, str(p.phase), Text("planned", style="dim"), key)
    console.print(table)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # "ipfinder 8.8.8.8" and plain "ipfinder" are shorthand for "ipfinder lookup ..."
    if not argv or argv[0] not in ("lookup", "sources", "-h", "--help", "--version"):
        argv = ["lookup", *argv]
    args = _build_parser().parse_args(argv)
    console = Console(no_color=getattr(args, "no_color", False))
    try:
        if args.command == "sources":
            return _cmd_sources(console)
        return _cmd_lookup(args, console)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:  # last-resort guard: show a clear message, not a traceback
        console.print(Text(f"[!] Internal error: {type(exc).__name__}: {exc}", style="bold red"))
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
