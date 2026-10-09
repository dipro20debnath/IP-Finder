"""Human-readable terminal output built with rich.

All values go through ``Text`` objects, never markup strings, so user input such
as ``[2001:db8::1]:443`` is printed literally instead of being parsed as markup.
Text that comes from the network (registry remarks, hostnames, API messages) also
passes through ``display_safe``: rich would print an ESC character as is, so a
hostile record could otherwise send terminal control sequences.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ipfinder import DISCLAIMER, __version__
from ipfinder.core.models import IPReport, ProviderResult
from ipfinder.core.text import display_safe

_SIXTOFOUR_NA = Text("n/a: needs a globally unique IPv4 (RFC 3056)", style="dim")


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
        table.add_row(Text(label), value if isinstance(value, Text) else _safe(value))
    return table


def _safe(value, style: str | None = None) -> Text:
    return Text(display_safe(str(value)), style=style or "")


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
            ("Zone ID", f"%{display_safe(data['scope_id'])}" if data.get("scope_id") else None),
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
        [
            (labels.get(k, k), _SIXTOFOUR_NA if k == "sixtofour_prefix" and v is None else v)
            for k, v in data["representations"].items()
        ],
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
                    or Text(f"unknown ({data.get('oui_database', 'no OUI list')})", style="dim"),
                ),
                ("Privacy", Text(iid["privacy"], style="yellow")),
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
            ("Flags", entry.get("flags")),
            ("Cone bit (deprecated)", entry.get("cone_bit")),
            ("RFC 5991 random bits", entry.get("random_flag_bits")),
            (
                "Flags note",
                Text(entry["flags_note"], style="dim") if "flags_note" in entry else None,
            ),
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


_LOCATION_SOURCES = ("geofeed", "maxmind", "ip-api", "ipinfo-lite")
_NETWORK_SOURCES = ("team-cymru", "ripestat", "maxmind", "ipinfo-lite", "ip-api")


def _grid(title: str, columns: list[str]) -> Table:
    table = Table(
        title=Text(title, style="bold cyan"),
        title_justify="left",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        expand=False,
    )
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


def _ok(report: IPReport, name: str) -> dict | None:
    result = report.result(name)
    return result.data if result is not None and result.ok else None


def _cell(value) -> Text:
    return Text("-") if value in (None, "") else _safe(value)


def _location(report: IPReport) -> list[Table]:
    table = _grid("Location (approximate)", ["Source", "Country", "City / Region", "Coordinates"])
    for name in _LOCATION_SOURCES:
        loc = (_ok(report, name) or {}).get("location")
        if not loc:
            continue
        country = loc.get("country")
        if loc.get("country_code"):
            country = f"{country or ''} ({loc['country_code']})".strip()
        region = loc.get("region") or loc.get("region_code")
        place = ", ".join(v for v in (loc.get("city"), region) if v) or None
        coords = None
        if loc.get("latitude") is not None and loc.get("longitude") is not None:
            coords = f"{loc['latitude']}, {loc['longitude']}"
            if loc.get("accuracy_radius_km") is not None:
                coords += f" (±{loc['accuracy_radius_km']} km)"
        table.add_row(Text(name, style="bold"), _cell(country), _cell(place), _cell(coords))
    geofeed_note = (_ok(report, "geofeed") or {}).get("note")
    if not table.row_count:
        return [_section("Location", [("Geofeed", geofeed_note)])] if geofeed_note else []

    summary = report.summary
    rows: list[tuple[str, object]] = []
    geofeed = _ok(report, "geofeed")
    if geofeed and geofeed.get("prefix"):
        signed = ", signed (signature not checked)" if geofeed.get("signed") else ""
        rows.append(("Operator geofeed", f"{geofeed['prefix']} from {geofeed['url']}{signed}"))
    if summary.get("countries_agree") is False:
        detail = ", ".join(f"{k}={v}" for k, v in summary["country_by_source"].items())
        rows.append(("Warning", _safe(f"Sources disagree on the country: {detail}", "yellow")))
    registered = (_ok(report, "maxmind") or {}).get("registered_country") or {}
    loc_cc = ((_ok(report, "maxmind") or {}).get("location") or {}).get("country_code")
    if registered.get("country_code") and registered["country_code"] != loc_cc:
        rows.append(
            (
                "Registered in",
                f"{registered.get('country')} ({registered['country_code']}) "
                "- the owner's country differs from where the IP is used",
            )
        )
    if geofeed_note:
        rows.append(("Geofeed", Text(display_safe(geofeed_note), style="dim")))
    links = summary.get("map_links")
    if links:
        rows.append((f"Map ({summary.get('map_source')})", links["openstreetmap"]))
        rows.append(("", links["google_maps"]))
    local = summary.get("local_time")
    if local:
        rows.append(
            ("Local time there", f"{local['time']} ({local['timezone']}, {local['utc_offset']})")
        )
    tables = [table]
    if rows:
        extra = _section("", rows)
        extra.title = None
        tables.append(extra)
    return tables


def _network(report: IPReport) -> list[Table]:
    table = _grid("Network", ["Source", "ASN", "AS name", "ISP / Org", "Prefix", "Registry"])
    for name in _NETWORK_SOURCES:
        net = (_ok(report, name) or {}).get("network")
        if not net:
            continue
        isp_org = " / ".join(dict.fromkeys(v for v in (net.get("isp"), net.get("org")) if v))
        registry = " ".join(
            v for v in (net.get("rir"), net.get("country_code"), net.get("allocated")) if v
        )
        as_name = net.get("as_name")
        if net.get("as_domain"):
            as_name = f"{as_name or ''} ({net['as_domain']})".strip()
        table.add_row(
            Text(name, style="bold"),
            _cell(f"AS{net['asn']}" if net.get("asn") is not None else None),
            _cell(as_name),
            _cell(isp_org or None),
            _cell(net.get("prefix")),
            _cell(registry or None),
        )
    tables = [table] if table.row_count else []
    summary = report.summary
    if summary.get("asns_agree") is False:
        detail = ", ".join(f"{k}=AS{v}" for k, v in summary["asn_by_source"].items())
        tables.append(
            _section(
                "", [("Warning", Text(f"Sources disagree on the ASN: {detail}", style="yellow"))]
            )
        )

    pdb = _ok(report, "peeringdb")
    if pdb:
        info = pdb.get("network_info")
        if info:
            tables.append(
                _section(
                    f"Network type (PeeringDB, AS{pdb['asn']})",
                    [
                        ("Name", info.get("name")),
                        ("Type", ", ".join(info.get("types") or []) or None),
                        ("Scope", info.get("scope")),
                        (
                            "Traffic / ratio",
                            " / ".join(v for v in (info.get("traffic"), info.get("ratio")) if v)
                            or None,
                        ),
                        ("Peering policy", info.get("policy")),
                        ("Website", info.get("website")),
                        ("PeeringDB", info.get("url")),
                    ],
                )
            )
        else:
            tables.append(_section("Network type (PeeringDB)", [("Note", pdb.get("note"))]))
    return tables


_RPKI = {
    "valid": ("valid - a ROA authorises this origin AS for this prefix", "green"),
    "invalid_asn": (
        "INVALID - no ROA authorises this origin AS (hijack or misconfiguration?)",
        "bold red",
    ),
    "invalid_length": (
        "INVALID - the announced prefix is longer than the ROA's max length allows",
        "bold red",
    ),
    "invalid": ("INVALID", "bold red"),
    "unknown": ("not found - no ROA covers this route (not RPKI-protected)", "yellow"),
}


def _date(value) -> str | None:
    return str(value)[:10] if value else None


def _routing(report: IPReport) -> list[Table]:
    data = _ok(report, "ripestat")
    if not data:
        return []
    rows: list[tuple[str, object]] = []
    net = data.get("network")
    if data.get("announced") and net:
        origins = ", ".join(
            f"AS{o['asn']}" + (f" ({o['holder']})" if o.get("holder") else "")
            for o in data.get("origins", [])
        )
        rows.append(("BGP", f"announced as {net.get('prefix')} by {origins}"))
        if len(data.get("origins", [])) > 1:
            rows.append(
                (
                    "Note",
                    _safe("several origin ASes announce this prefix (MOAS)", style="yellow"),
                )
            )
    else:
        rows.append(("BGP", _safe("not announced (no route seen by RIPE RIS)", style="yellow")))
    for check in data.get("rpki", []):
        text, style = _RPKI.get(check["status"], (check["status"], "yellow"))
        value = _safe(text, style=style)
        roas = [
            f"{r['prefix']} max /{r['max_length']} AS{r['origin']}"
            for r in check.get("roas", [])
            if r.get("prefix") and r.get("origin") is not None
        ]
        if roas:
            value.append(display_safe(f"  (ROA {'; '.join(roas[:3])})"), style="dim")
        rows.append((f"RPKI (AS{check['origin']})", value))
    routing = data.get("routing") or {}
    vis = routing.get("visibility")
    if vis:
        share = 100 * vis["ris_peers_seeing"] / vis["total_ris_peers"]
        rows.append(
            (
                "Visibility",
                f"{vis['ris_peers_seeing']} of {vis['total_ris_peers']} RIS peers ({share:.0f}%)",
            )
        )
    if routing.get("first_seen"):
        rows.append(("First seen in BGP", _date(routing["first_seen"]["time"])))
    if routing.get("last_seen") and not data.get("announced"):
        seen = routing["last_seen"]
        detail = f" ({seen['prefix']} by AS{seen['origin']})" if seen.get("origin") else ""
        rows.append(("Last seen in BGP", f"{_date(seen['time'])}{detail}"))
    nb = data.get("neighbours") or {}
    if nb.get("upstream_side") is not None or nb.get("downstream_side") is not None:
        rows.append(
            (
                "Neighbour ASes",
                f"{nb.get('upstream_side', 0)} upstream side, "
                f"{nb.get('downstream_side', 0)} downstream side (position in AS paths)",
            )
        )
    if nb.get("top_upstream_side"):
        rows.append(("Busiest upstream side", ", ".join(f"AS{a}" for a in nb["top_upstream_side"])))
    for call, error in (data.get("partial_errors") or {}).items():
        rows.append(("Missing", _safe(f"{call}: {error}", style="yellow")))
    return [_section("Routing and RPKI (RIPEstat)", rows)]


def _registration(report: IPReport) -> list[Table]:
    data = _ok(report, "rdap")
    if not data:
        return []
    reg = data.get("registration") or {}
    holder = reg.get("registrant") or {}
    name = reg.get("name")
    if name and reg.get("handle"):
        name = f"{name} ({reg['handle']})"
    owner = holder.get("name")
    if owner and holder.get("handle"):
        owner = f"{owner} ({holder['handle']})"
    registry = " ".join(
        v for v in (data.get("rir"), f"({data['server']})" if data.get("server") else None) if v
    )
    rows = [
        ("Network name", name or reg.get("handle")),
        ("Registered to", owner),
        ("Description", "; ".join(reg.get("description") or []) or None),
        ("Range", reg.get("range")),
        ("CIDR", ", ".join(reg.get("cidrs") or []) or None),
        ("Allocation type", reg.get("type")),
        ("Registration country", reg.get("country_code")),
        ("Registered", _date(reg.get("registered"))),
        ("Last changed", _date(reg.get("last_changed"))),
        ("Status", ", ".join(reg.get("status") or []) or None),
        ("Origin AS (registry)", ", ".join(f"AS{a}" for a in reg.get("origin_asns", [])) or None),
        ("Parent block", reg.get("parent_handle")),
        ("Registry", registry or None),
        ("Geofeed", ", ".join(data.get("geofeed_urls") or []) or None),
        ("RDAP record", data.get("url")),
    ]
    return [_section("Registration (RDAP)", rows)]


def _abuse(report: IPReport) -> list[Table]:
    contacts = report.summary.get("abuse_contacts")
    if not contacts:
        return []
    rows: list[tuple[str, object]] = [
        ("E-mail", f"{c['email']}  ({', '.join(c['sources'])})") for c in contacts
    ]
    phones = [
        phone
        for contact in (_ok(report, "rdap") or {}).get("abuse_contacts", [])
        for phone in contact.get("phones", [])
    ]
    if phones:
        rows.append(("Phone", ", ".join(dict.fromkeys(phones))))
    rows.append(
        (
            "Note",
            Text(
                "Send reports of attacks or spam here. Only the network operator can tell "
                "which customer used the address.",
                style="dim",
            ),
        )
    )
    return [_section("Abuse contact", rows)]


def _reverse_dns(report: IPReport) -> list[Table]:
    data = _ok(report, "reverse-dns")
    if not data:
        return []
    if not data.get("ptr"):
        return [_section("Reverse DNS", [("PTR", _safe(data.get("note", "none"), style="dim"))])]
    rows: list[tuple[str, object]] = [("PTR", ", ".join(data["ptr"]))]
    if data.get("forward_confirmed"):
        confirmed = _safe(f"yes - {data['hostname']} resolves back to this address", "green")
    else:
        confirmed = _safe(
            "no - the name does not resolve back to this address, so it proves nothing",
            "red",
        )
    rows.append(("Forward-confirmed", confirmed))
    for hint in data.get("hints", []):
        rows.append(("Hint", f"{hint['hint']} ({hint['evidence']})"))
    return [_section("Reverse DNS", rows)]


def _flags(report: IPReport) -> list[Table]:
    data = _ok(report, "ip-api")
    if not data:
        return []
    flags = data.get("flags") or {}
    rows = [
        ("Hosting / data centre", _yes_no(flags.get("hosting")) if "hosting" in flags else None),
        ("Proxy / VPN / Tor", _yes_no(flags.get("proxy")) if "proxy" in flags else None),
        ("Mobile (cellular)", _yes_no(flags.get("mobile")) if "mobile" in flags else None),
        ("Reverse DNS", data.get("reverse_dns")),
        ("Currency", data.get("currency")),
        (
            "Note",
            Text("ip-api's own estimate; a VPN can never be detected with certainty", style="dim"),
        ),
    ]
    return [_section("Connection type (ip-api)", rows)]


def _sources(report: IPReport) -> list[Table]:
    rows = []
    for r in report.results:
        if r.provider == "offline":
            continue
        if r.ok:
            status = Text(
                "ok (cached)" if r.cached else f"ok ({r.elapsed_ms:.0f} ms)", style="green"
            )
        elif r.skipped:
            status = Text(f"skipped: {r.skipped}", style="dim")
        else:
            status = Text(f"error: {display_safe(str(r.error))}", style="red")
        rows.append((f"{r.provider} ({r.layer})", status))
    return [_section("Sources", rows)] if rows else []


def render_report(report: IPReport, verbose: bool = False) -> Panel:
    offline = report.result("offline")
    data = offline.data
    parts: list = [_summary(report, data)]
    parts += _location(report) + _network(report) + _routing(report)
    parts += _registration(report) + _abuse(report) + _reverse_dns(report) + _flags(report)
    parts.append(_representations(data))
    parts += _ipv4(data) if report.version == 4 else _ipv6(data)
    parts += _sources(report)

    notes = list(report.notes)
    if not data["python_ipaddress"].get("agrees_with_iana_table", True):
        notes.append(
            f"Python {data['python_ipaddress']['python_version']}'s ipaddress.is_global "
            "disagrees with the IANA table; IP Finder follows IANA"
        )
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
        if any((r.result("ip-api") or ProviderResult("", "", False)).ok for r in reports):
            console.print(
                Text(
                    "ip-api data travelled over plain HTTP (its free tier has no HTTPS).",
                    style="dim",
                )
            )
        console.print(Text(f"[!] {DISCLAIMER}", style="yellow"))
