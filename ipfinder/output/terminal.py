"""Human-readable terminal output built with rich.

All values go through ``Text`` objects, never markup strings, so user input such
as ``[2001:db8::1]:443`` is printed literally instead of being parsed as markup.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ipfinder import DISCLAIMER, __version__
from ipfinder.core.models import IPReport


def _yes_no(value: bool | None) -> Text:
    if value is True:
        return Text("yes", style="green")
    if value is False:
        return Text("no", style="red")
    return Text("n/a (see RFC)", style="yellow")


def _section(title: str, rows: list[tuple[str, object]]) -> Table:
    table = Table(
        title=Text(title, style="bold cyan"),
        title_justify="left",
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("field", style="bold", no_wrap=True)
    table.add_column("value", overflow="fold")
    for label, value in rows:
        if value is None or value == "":
            continue
        table.add_row(Text(label), value if isinstance(value, Text) else Text(str(value)))
    return table


def _range_label(cls: dict) -> str:
    # The catch-all classes (0.0.0.0/0, ::/0) are not real blocks; don't print them.
    return "" if cls["range"].endswith("/0") else f"{cls['range']}, "


def _summary(report: IPReport, data: dict) -> Table:
    cls = data["classification"]
    address = Text(f"{data['ip']}  (IPv{data['version']})")
    if data.get("port") is not None:
        address.append(f"  port {data['port']}")
    lookup = report.lookup
    if lookup["eligible"]:
        target = Text(lookup["target"], style="green")
        if lookup["target"] != data["ip"]:
            target.append(f"  ({lookup['reason']})", style="dim")
    else:
        target = Text(f"not applicable: {lookup['reason']}", style="yellow")
    return _section(
        "Summary",
        [
            ("Address", address),
            ("Zone ID", f"%{data['scope_id']}" if data.get("scope_id") else None),
            ("Type", f"{cls['name']}  [{_range_label(cls)}{cls['rfc']}]"),
            ("Globally reachable", _yes_no(cls["globally_reachable"])),
            ("Online lookup target", target),
        ],
    )


def _representations(data: dict) -> Table:
    labels = {
        "compressed": "Compressed",
        "exploded": "Exploded",
        "integer": "Integer",
        "hex": "Hex",
        "binary": "Binary",
        "reverse_pointer": "Reverse DNS name",
        "ipv4_mapped_ipv6": "IPv4-mapped IPv6",
        "sixtofour_prefix": "6to4 prefix",
    }
    return _section(
        "Representations",
        [(labels.get(k, k), v) for k, v in data["representations"].items()],
    )


def _ipv4(data: dict) -> list[Table]:
    v4 = data["ipv4"]
    cls = v4["historic_class"]
    tables = [
        _section(
            "IPv4 details",
            [
                ("Historic class", cls["class"]),
                ("Classful network", cls["classful_network"]),
                ("Note", Text(cls["note"], style="dim")),
            ],
        )
    ]
    mc = v4.get("multicast")
    if mc:
        tables.append(
            _section(
                "Multicast",
                [
                    ("Block", f"{mc['block']} ({mc['rfc']})"),
                    ("GLOP AS number", f"AS{mc['glop_asn']}" if "glop_asn" in mc else None),
                    ("Well-known group", mc.get("well_known")),
                ],
            )
        )
    return tables


def _ipv6(data: dict) -> list[Table]:
    v6 = data["ipv6"]
    tables = []
    st = v6.get("structure")
    if st:
        tables.append(
            _section(
                "IPv6 structure",
                [
                    ("/32 (typical ISP allocation)", st["prefix_32"]),
                    ("/48 (site)", st["prefix_48"]),
                    ("/56", st["prefix_56"]),
                    ("/64 (subnet / LAN)", st["subnet_64"]),
                    ("Interface ID", st["interface_id"]),
                ],
            )
        )
    iid = v6.get("interface_id")
    if iid:
        rows: list[tuple[str, object]] = [
            ("Type", iid["type"]),
            ("Meaning", iid["description"]),
            ("RFC", iid.get("rfc")),
        ]
        if iid["type"] == "eui64":
            rows += [
                ("MAC address", Text(iid["mac"], style="bold magenta")),
                ("OUI", iid["oui"]),
                (
                    "Vendor",
                    iid.get("vendor")
                    or iid.get("vendor_note")
                    or Text("unknown (add data/oui.csv, see data/README.md)", style="dim"),
                ),
                ("Privacy", Text(iid["privacy"], style="yellow")),
                ("Confidence", iid["confidence"]),
            ]
        elif iid["type"] in ("isatap", "possible_embedded_ipv4"):
            rows.append(("IPv4 in interface ID", iid["ipv4"]))
            rows.append(("Confidence", iid.get("confidence")))
        tables.append(_section("Interface identifier", rows))
    for entry in v6.get("embedded_ipv4", []):
        rows = [
            ("IPv4", Text(entry["address"], style="bold")),
            ("Role", entry.get("role")),
            ("Type of that IPv4", entry["category"]),
            ("Globally reachable", _yes_no(entry["globally_reachable"])),
            ("Client port", entry.get("client_port")),
            ("Cone NAT flag", entry.get("cone_nat")),
            ("RFC", entry["rfc"]),
        ]
        tables.append(_section(f"Embedded IPv4 ({entry['kind']})", rows))
    mc = v6.get("multicast")
    if mc:
        flags = ", ".join(k for k, v in mc["flags"].items() if v) or "none (permanent group)"
        tables.append(
            _section(
                "Multicast",
                [
                    ("Scope", f"{mc['scope']} ({mc['scope_value']:x})"),
                    ("Flags", flags),
                    ("Well-known group", mc.get("well_known")),
                    ("RFC", mc["rfc"]),
                ],
            )
        )
    return tables


def _verbose(data: dict) -> list[Table]:
    flags = data["python_ipaddress"]
    rows = [(k, v) for k, v in flags.items()]
    ranges = [
        (r["range"], f"{r['name']} ({r['rfc']}), reachable={r['globally_reachable']}")
        for r in data["all_matching_ranges"]
    ]
    tables = [_section("Python ipaddress flags", rows)]
    if ranges:
        tables.append(_section("All matching special ranges", ranges))
    return tables


def render_report(report: IPReport, verbose: bool = False) -> Panel:
    offline = report.result("offline")
    data = offline.data
    parts: list = [_summary(report, data), _representations(data)]
    parts += _ipv4(data) if report.version == 4 else _ipv6(data)

    notes = list(report.notes)
    if not data["python_ipaddress"].get("agrees_with_iana_table", True):
        notes.append(
            f"Python {data['python_ipaddress']['python_version']}'s ipaddress.is_global "
            "disagrees with the IANA table; IP Finder follows IANA"
        )
    others = [r for r in report.results if r.provider != "offline"]
    for r in others:
        status = "ok" if r.ok else (f"skipped: {r.skipped}" if r.skipped else f"error: {r.error}")
        notes.append(f"{r.provider} ({r.layer}): {status}")
    if notes:
        parts.append(_section("Notes", [("-", Text(n, style="dim")) for n in notes]))
    if verbose:
        parts += _verbose(data)

    return Panel(
        Group(*parts),
        title=Text(f"IP Finder {__version__} - {report.ip}", style="bold"),
        title_align="left",
        border_style="blue",
    )


def print_reports(
    console: Console, reports: list[IPReport], errors: list[dict], verbose: bool = False
) -> None:
    for report in reports:
        console.print(render_report(report, verbose))
    for err in errors:
        line = Text("[!] ", style="bold red")
        line.append(f"{err['input']!r}: {err['error']}")
        if err.get("hint"):
            line.append(f"\n    hint: {err['hint']}", style="yellow")
        console.print(line)
    if reports:
        console.print(
            Text(
                "Phase 1: offline analysis only. Geolocation, ASN and other online layers "
                "arrive in Phase 2+.",
                style="dim",
            )
        )
        console.print(Text(f"[!] {DISCLAIMER}", style="yellow"))
