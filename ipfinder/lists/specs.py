"""Every downloadable list: where it comes from, how often it changes, how to read it.

Formats (checked 2026-10):
  Tor bulk exit list      one IP per line (https://check.torproject.org/torbulkexitlist)
  Tor exit-addresses      "ExitNode <fingerprint>" / "Published" / "LastStatus" /
                          "ExitAddress <ip> <date time>" records (TorDNSEL format)
  AWS ip-ranges.json      {"createDate", "prefixes": [{"ip_prefix", "region", "service",
                          "network_border_group"}], "ipv6_prefixes": [{"ipv6_prefix", ...}]}
  Google cloud.json /     {"creationTime", "prefixes": [{"ipv4Prefix" | "ipv6Prefix",
  goog.json                "service", "scope"}]}  (goog.json: every Google range, no labels)
  Azure Service Tags      {"values": [{"name", "properties": {"region", "systemService",
                          "addressPrefixes"}}]}; the file name changes weekly, so the
                          current link is read from Microsoft's download page
  Oracle Cloud            {"last_updated_timestamp", "regions": [{"region",
                          "cidrs": [{"cidr", "tags"}]}]}
  Cloudflare API          {"success", "result": {"ipv4_cidrs", "ipv6_cidrs", "etag"}}
  Fastly API              {"addresses", "ipv6_addresses"}
  iCloud Private Relay    RFC 8805 CSV: prefix,country,region,city,postal
  X4BNet lists_vpn (MIT)  CIDR per line; ASN lists "AS9009 # M247, GB (NordVPN)"
  Feodo Tracker           [{"ip_address", "port", "status", "malware", "first_seen",
                          "last_online", "as_name", "country"}] (abuse.ch botnet C2s)
  Spamhaus DROP           newline-delimited JSON: {"cidr", "sblid", "rir"} per line and a
                          final {"type": "metadata", "timestamp", ...} line; ASN-DROP
                          lines carry "asn" (older text format "cidr ; SBLnnn" also read)
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ipfinder.lists.index import PrefixIndex

HOUR = 3600
DAY = 24 * HOUR
MB = 1_000_000


@dataclass
class Dataset:
    """A parsed list: blocks in ``index`` and/or ASNs in ``asns``."""

    index: PrefixIndex = field(default_factory=PrefixIndex)
    asns: dict[int, str] = field(default_factory=dict)
    published: str | None = None  # the list's own timestamp, when it has one

    @property
    def entries(self) -> int:
        return self.index.count + len(self.asns)


@dataclass(frozen=True)
class ListSpec:
    name: str
    title: str
    group: str  # tor | cloud | relay | vpn | threat
    url: str
    filename: str
    parse: Callable[[str], Dataset]
    min_entries: int  # fewer means a broken download (an error page, an empty file)
    refresh: float  # update-lists skips a younger file unless --force
    stale_after: float  # lookups warn when the file is older than this
    max_bytes: int = 20 * MB
    source: str = ""  # who publishes it, terms
    label: str = ""  # cloud lists: the company name shown in reports
    page_pattern: str | None = None  # the real file URL is a link on the page at ``url``
    key_header: tuple[str, str] | None = None  # (env key, header) sent when the key is set


def _check(dataset: Dataset, spec_min: int, what: str) -> Dataset:
    if dataset.entries < spec_min:
        raise ValueError(f"only {dataset.entries} entries; expected a {what} list")
    return dataset


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise ValueError("not valid JSON") from None


# ---------------------------------------------------------------- parsers


def parse_ip_lines(text: str) -> Dataset:
    """One address or CIDR per line; '#' comments."""
    dataset = Dataset()
    lines = (line.split("#", 1)[0].strip() for line in text.splitlines())
    dataset.index.add_many((line, None) for line in lines if line)
    return dataset


def parse_tor_exit_addresses(text: str) -> Dataset:
    dataset = Dataset()
    relay: dict[str, str] = {}
    for line in text.splitlines():
        key, _, rest = line.strip().partition(" ")
        if key == "ExitNode":
            relay = {"fingerprint": rest.strip()}
        elif key in ("Published", "LastStatus") and relay:
            relay[key.lower()] = rest.strip()
        elif key == "ExitAddress" and relay.get("fingerprint"):
            address, _, tested = rest.strip().partition(" ")
            dataset.index.add(address, {**relay, "tested": tested.strip()})
    return dataset


def parse_aws(text: str) -> Dataset:
    data = _json(text)
    dataset = Dataset()
    if not isinstance(data, dict):
        raise ValueError("unexpected AWS format")
    created = str(data.get("createDate") or "")
    if re.fullmatch(r"\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d", created):
        created = f"{created[:10]} {created[11:].replace('-', ':')} UTC"
    dataset.published = created or None
    for key, field_name in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for entry in data.get(key) or []:
            if isinstance(entry, dict) and isinstance(entry.get(field_name), str):
                value = (
                    entry.get("region"),
                    entry.get("service"),
                    entry.get("network_border_group"),
                )
                dataset.index.add(entry[field_name], value)
    return dataset


def parse_google(text: str) -> Dataset:
    data = _json(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected Google format")
    dataset = Dataset(published=data.get("creationTime"))
    for entry in data.get("prefixes") or []:
        if not isinstance(entry, dict):
            continue
        prefix = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if isinstance(prefix, str):
            dataset.index.add(prefix, (entry.get("service"), entry.get("scope")))
    return dataset


def parse_azure(text: str) -> Dataset:
    data = _json(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected Azure format")
    dataset = Dataset()
    change = data.get("changeNumber")
    dataset.published = f"change {change}" if change is not None else None
    for value in data.get("values") or []:
        props = value.get("properties") if isinstance(value, dict) else None
        if not isinstance(props, dict):
            continue
        label = (value.get("name"), props.get("region") or None, props.get("systemService") or None)
        for prefix in props.get("addressPrefixes") or []:
            if isinstance(prefix, str):
                dataset.index.add(prefix, label)
    return dataset


def parse_oracle(text: str) -> Dataset:
    data = _json(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected Oracle format")
    dataset = Dataset(published=data.get("last_updated_timestamp"))
    for region in data.get("regions") or []:
        if not isinstance(region, dict):
            continue
        for cidr in region.get("cidrs") or []:
            if isinstance(cidr, dict) and isinstance(cidr.get("cidr"), str):
                tags = tuple(t for t in cidr.get("tags") or [] if isinstance(t, str))
                dataset.index.add(cidr["cidr"], (region.get("region"), tags))
    return dataset


def parse_cloudflare(text: str) -> Dataset:
    data = _json(text)
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict) or data.get("success") is False:
        raise ValueError("unexpected Cloudflare format")
    dataset = Dataset()
    for prefix in (result.get("ipv4_cidrs") or []) + (result.get("ipv6_cidrs") or []):
        if isinstance(prefix, str):
            dataset.index.add(prefix)
    return dataset


def parse_fastly(text: str) -> Dataset:
    data = _json(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected Fastly format")
    dataset = Dataset()
    for prefix in (data.get("addresses") or []) + (data.get("ipv6_addresses") or []):
        if isinstance(prefix, str):
            dataset.index.add(prefix)
    return dataset


def parse_geofeed_csv(text: str) -> Dataset:
    """RFC 8805 lines; value = (country, region, city). Extra columns are ignored.
    Lists like Private Relay repeat the same location on thousands of lines, so each
    distinct location text is parsed once (and shared, which also saves memory)."""
    dataset = Dataset()
    values: dict[str, tuple] = {}

    def location(rest: str) -> tuple:
        value = values.get(rest)
        if value is None:
            row = next(csv.reader([rest])) if '"' in rest else rest.split(",")
            fields = [f.strip() for f in row[:3]] + ["", "", ""]
            value = (fields[0].upper() or None, fields[1].upper() or None, fields[2] or None)
            values[rest] = value
        return value

    def rows():
        for line in text.lstrip("\ufeff").splitlines():
            if not line or line[0] == "#":
                continue
            prefix, _, rest = line.partition(",")
            yield prefix.strip().strip('"'), location(rest)

    dataset.index.add_many(rows())
    return dataset


_ASN_LINE = re.compile(r"^\s*AS(\d{1,10})\b\s*(?:#\s*(.*))?$", re.IGNORECASE)


def parse_asn_lines(text: str) -> Dataset:
    dataset = Dataset()
    for line in text.splitlines():
        match = _ASN_LINE.match(line)
        if match:
            dataset.asns[int(match.group(1))] = (match.group(2) or "").strip()
    return dataset


def parse_feodo(text: str) -> Dataset:
    """abuse.ch Feodo Tracker botnet C2 list. It can legitimately be short or empty
    (after a takedown), so only the JSON shape is checked."""
    data = _json(text)
    if not isinstance(data, list):
        raise ValueError("unexpected Feodo Tracker format")
    dataset = Dataset()
    keys = ("port", "status", "malware", "first_seen", "last_online", "as_name", "country")
    for entry in data:
        if isinstance(entry, dict) and isinstance(entry.get("ip_address"), str):
            value = {k: entry[k] for k in keys if entry.get(k) not in (None, "")}
            dataset.index.add(entry["ip_address"], value)
    return dataset


def _ndjson(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


def _metadata_date(record: dict) -> str | None:
    stamp = record.get("timestamp")
    if isinstance(stamp, (int, float)):
        return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return None


def parse_drop(text: str) -> Dataset:
    dataset = Dataset()
    for record in _ndjson(text):
        if record.get("type") == "metadata":
            dataset.published = _metadata_date(record)
        elif isinstance(record.get("cidr"), str):
            dataset.index.add(record["cidr"], record.get("sblid"))
    for line in text.splitlines():  # the older text format: "1.10.16.0/20 ; SBL256894"
        if ";" in line and not line.lstrip().startswith(("{", ";")):
            cidr, _, sblid = line.partition(";")
            dataset.index.add(cidr.strip(), sblid.strip() or None)
    return dataset


def parse_asndrop(text: str) -> Dataset:
    dataset = Dataset()
    for record in _ndjson(text):
        if record.get("type") == "metadata":
            dataset.published = _metadata_date(record)
            continue
        asn = record.get("asn")
        if isinstance(asn, str) and asn.upper().removeprefix("AS").isdigit():
            asn = int(asn.upper().removeprefix("AS"))
        if isinstance(asn, int) and not isinstance(asn, bool):
            label = record.get("asname") or record.get("domain") or ""
            country = record.get("cc")
            if country:
                label = f"{label} ({country})".strip()
            dataset.asns[asn] = str(label)
    return dataset


# ---------------------------------------------------------------- specs

X4B = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/"
X4B_SOURCE = "X4BNet lists_vpn (MIT licence), github.com/X4BNet/lists_vpn"


def _spec(name, title, group, url, filename, parse, min_entries, what, **kwargs) -> ListSpec:
    def checked(text: str, _parse=parse) -> Dataset:
        return _check(_parse(text), min_entries, what)

    return ListSpec(name, title, group, url, filename, checked, min_entries, **kwargs)


SPECS: dict[str, ListSpec] = {
    s.name: s
    for s in (
        _spec(
            "tor-exits",
            "Tor exit relays (bulk exit list)",
            "tor",
            "https://check.torproject.org/torbulkexitlist",
            "tor-bulk-exit-list.txt",
            parse_ip_lines,
            100,
            "Tor exit",
            refresh=HOUR / 2,
            stale_after=6 * HOUR,
            max_bytes=5 * MB,
            source="The Tor Project",
        ),
        _spec(
            "tor-exit-addresses",
            "Tor exit relays (tested exit addresses)",
            "tor",
            "https://check.torproject.org/exit-addresses",
            "tor-exit-addresses.txt",
            parse_tor_exit_addresses,
            100,
            "Tor exit",
            refresh=HOUR / 2,
            stale_after=6 * HOUR,
            max_bytes=10 * MB,
            source="The Tor Project (TorDNSEL)",
        ),
        _spec(
            "aws",
            "Amazon Web Services IP ranges",
            "cloud",
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "aws-ip-ranges.json",
            parse_aws,
            1000,
            "AWS range",
            refresh=12 * HOUR,
            stale_after=14 * DAY,
            source="Amazon",
            label="Amazon Web Services",
        ),
        _spec(
            "google-cloud",
            "Google Cloud IP ranges",
            "cloud",
            "https://www.gstatic.com/ipranges/cloud.json",
            "google-cloud.json",
            parse_google,
            50,
            "Google Cloud range",
            refresh=12 * HOUR,
            stale_after=14 * DAY,
            source="Google",
            label="Google Cloud",
        ),
        _spec(
            "google",
            "All Google IP ranges (services and APIs)",
            "cloud",
            "https://www.gstatic.com/ipranges/goog.json",
            "google-all.json",
            parse_google,
            20,
            "Google range",
            refresh=12 * HOUR,
            stale_after=14 * DAY,
            source="Google",
            label="Google",
        ),
        _spec(
            "azure",
            "Microsoft Azure IP ranges and service tags",
            "cloud",
            "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
            "azure-service-tags.json",
            parse_azure,
            1000,
            "Azure range",
            refresh=DAY,
            stale_after=21 * DAY,
            max_bytes=50 * MB,
            source="Microsoft (file name changes every week)",
            label="Microsoft Azure",
            page_pattern=(
                r"https://download\.microsoft\.com/download/[\w./-]+?/ServiceTags_Public_\d{8}\.json"
            ),
        ),
        _spec(
            "oracle",
            "Oracle Cloud IP ranges",
            "cloud",
            "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
            "oracle-cloud.json",
            parse_oracle,
            50,
            "Oracle Cloud range",
            refresh=DAY,
            stale_after=21 * DAY,
            source="Oracle",
            label="Oracle Cloud",
        ),
        _spec(
            "cloudflare",
            "Cloudflare IP ranges",
            "cloud",
            "https://api.cloudflare.com/client/v4/ips",
            "cloudflare.json",
            parse_cloudflare,
            5,
            "Cloudflare range",
            refresh=DAY,
            stale_after=60 * DAY,
            source="Cloudflare",
            label="Cloudflare",
        ),
        _spec(
            "fastly",
            "Fastly IP ranges",
            "cloud",
            "https://api.fastly.com/public-ip-list",
            "fastly.json",
            parse_fastly,
            5,
            "Fastly range",
            refresh=DAY,
            stale_after=60 * DAY,
            source="Fastly",
            label="Fastly",
        ),
        _spec(
            "private-relay",
            "iCloud Private Relay egress ranges",
            "relay",
            "https://mask-api.icloud.com/egress-ip-ranges.csv",
            "icloud-private-relay.csv",
            parse_geofeed_csv,
            1000,
            "Private Relay",
            refresh=12 * HOUR,
            stale_after=14 * DAY,
            max_bytes=150 * MB,
            source="Apple",
        ),
        _spec(
            "vpn-networks",
            "Known VPN provider networks (IPv4)",
            "vpn",
            X4B + "output/vpn/ipv4.txt",
            "x4b-vpn-ipv4.txt",
            parse_ip_lines,
            100,
            "VPN network",
            refresh=DAY,
            stale_after=60 * DAY,
            source=X4B_SOURCE,
        ),
        _spec(
            "datacenter-networks",
            "Datacenter and VPN networks (IPv4)",
            "vpn",
            X4B + "output/datacenter/ipv4.txt",
            "x4b-datacenter-ipv4.txt",
            parse_ip_lines,
            100,
            "datacenter network",
            refresh=DAY,
            stale_after=60 * DAY,
            source=X4B_SOURCE,
        ),
        _spec(
            "vpn-asns",
            "ASNs of VPN providers",
            "vpn",
            X4B + "input/vpn/ASN.txt",
            "x4b-vpn-asns.txt",
            parse_asn_lines,
            5,
            "VPN ASN",
            refresh=DAY,
            stale_after=60 * DAY,
            source=X4B_SOURCE,
        ),
        _spec(
            "datacenter-asns",
            "ASNs of datacenters and hosting companies",
            "vpn",
            X4B + "input/datacenter/ASN.txt",
            "x4b-datacenter-asns.txt",
            parse_asn_lines,
            50,
            "datacenter ASN",
            refresh=DAY,
            stale_after=60 * DAY,
            source=X4B_SOURCE,
        ),
        _spec(
            "feodo",
            "abuse.ch Feodo Tracker botnet C2 servers",
            "threat",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "feodo-ipblocklist.json",
            parse_feodo,
            0,
            "Feodo Tracker",
            refresh=HOUR,
            stale_after=DAY,
            source="abuse.ch Feodo Tracker (regenerated every 5 minutes)",
            key_header=("ABUSECH_AUTH_KEY", "Auth-Key"),
        ),
        _spec(
            "spamhaus-drop-v4",
            "Spamhaus DROP (IPv4 netblocks run by criminals)",
            "threat",
            "https://www.spamhaus.org/drop/drop_v4.json",
            "spamhaus-drop-v4.json",
            parse_drop,
            100,
            "Spamhaus DROP",
            refresh=12 * HOUR,
            stale_after=7 * DAY,
            source="The Spamhaus Project",
        ),
        _spec(
            "spamhaus-drop-v6",
            "Spamhaus DROPv6 (IPv6 netblocks run by criminals)",
            "threat",
            "https://www.spamhaus.org/drop/drop_v6.json",
            "spamhaus-drop-v6.json",
            parse_drop,
            1,
            "Spamhaus DROPv6",
            refresh=12 * HOUR,
            stale_after=7 * DAY,
            source="The Spamhaus Project",
        ),
        _spec(
            "spamhaus-asndrop",
            "Spamhaus ASN-DROP (networks run by criminals)",
            "threat",
            "https://www.spamhaus.org/drop/asndrop.json",
            "spamhaus-asndrop.json",
            parse_asndrop,
            10,
            "Spamhaus ASN-DROP",
            refresh=12 * HOUR,
            stale_after=7 * DAY,
            source="The Spamhaus Project",
        ),
    )
}

CLOUD_LISTS = tuple(name for name, spec in SPECS.items() if spec.group == "cloud")
TOR_LISTS = ("tor-exits", "tor-exit-addresses")
