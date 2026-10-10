# IP Finder v2

A Python tool that finds out **everything that can legitimately be known about an IP address**: what kind of address it is, where its network is, who owns it, how it is routed, whether it belongs to a cloud, a VPN or Tor, which services it exposes, and whether it has a bad reputation. Every answer comes with its source, a confidence level and its limits.

- **27 sources in 12 layers**, from pure address analysis to threat intelligence.
- **Works with no API key.** Keys and databases only add sources.
- **Passive by default.** A fully offline mode sends nothing anywhere. Active probes run only with explicit permission.
- **Four ways to see the result:** terminal, JSON, CSV, and an HTML report with a map that opens without internet. There is also a browser dashboard.

> ⚠️ IP geolocation is approximate. An IP address does not identify a person.

![IP Finder architecture](docs/architecture.svg)

---

## Contents

1. [Quick start](#quick-start)
2. [Installation](#installation)
3. [Usage guide: basic to advanced](#usage-guide-basic-to-advanced)
   - [Level 1: first lookups](#level-1-first-lookups)
   - [Level 2: reading a report](#level-2-reading-a-report)
   - [Level 3: files, batches and output formats](#level-3-files-batches-and-output-formats)
   - [Level 4: more sources (keys, GeoLite2, lists)](#level-4-more-sources-keys-geolite2-lists)
   - [Level 5: profiles, privacy and offline mode](#level-5-profiles-privacy-and-offline-mode)
   - [Level 6: active probes](#level-6-active-probes)
   - [Level 7: the web dashboard](#level-7-the-web-dashboard)
   - [Level 8: scripting and automation](#level-8-scripting-and-automation)
   - [Level 9: using it as a Python library](#level-9-using-it-as-a-python-library)
4. [Command reference](#command-reference)
5. [Settings reference](#settings-reference)
6. [What it can tell you: the 12 layers](#what-it-can-tell-you-the-12-layers)
7. [How it works](#how-it-works)
8. [What is verified, and what is not yet](#what-is-verified-and-what-is-not-yet)
9. [Limits](#limits)
10. [Responsible use](#responsible-use)
11. [Development](#development)
12. [Documentation](#documentation)
13. [Roadmap status](#roadmap-status)

---

## Quick start

```bash
git clone https://github.com/dipro20debnath/IP-Finder.git
cd IP-Finder
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"

ipfinder 8.8.8.8                       # every layer, every source that needs no key
ipfinder --offline 100.64.1.1          # nothing leaves your computer
ipfinder lookup 8.8.8.8 1.1.1.1 -f html -o report.html   # report with a map
ipfinder serve --open                  # the web dashboard
```

---

## Installation

**Requirements:** Python **3.10 or newer** on Windows, macOS or Linux.

```bash
git clone https://github.com/dipro20debnath/IP-Finder.git
cd IP-Finder
python -m venv .venv
source .venv/bin/activate              # Windows (PowerShell or cmd): .venv\Scripts\activate
```

Then install one of these:

| Command | What you get |
|---|---|
| `python -m pip install -e .` | The command-line tool |
| `python -m pip install -e ".[web]"` | The tool and the web dashboard (FastAPI, uvicorn) |
| `python -m pip install -e ".[dev]"` | Everything, plus the test tools (pytest, ruff) |

**Dependencies:**
- `rich`: terminal output.
- `httpx`: HTTP.
- `dnspython`: DNS lookups.
- `maxminddb`: reads GeoLite2 files.
- `tzdata`: Windows only, for time zones.

**Optional extras that make results better** (all explained in [Level 4](#level-4-more-sources-keys-geolite2-lists)):
- Free MaxMind GeoLite2 databases, for city-level location with an accuracy radius.
- The downloaded lists, for Tor, cloud, VPN and Private Relay checks: `ipfinder update-lists`.
- Free API keys in a `.env` file.

**Run it from the project folder.** `.env`, the `data/` folder (databases, lists, cache) are read relative to the folder you run `ipfinder` from. To run it from anywhere, set the paths in `.env` (see [Settings reference](#settings-reference)).

Without activating the virtual environment you can also run `python -m ipfinder ...` with the venv's Python.

---

## Usage guide: basic to advanced

### Level 1: first lookups

```bash
ipfinder 8.8.8.8                       # "lookup" can be left out
ipfinder lookup 8.8.8.8 2001:4860:4860::8888   # several addresses at once
ipfinder me                            # your own public IP (asks ip-api)
ipfinder                               # no argument: asks you for an address
```

IP Finder accepts addresses in the forms people actually copy and paste. These were all tested:

| You type | It looks up |
|---|---|
| `8.8.8.8:53` | 8.8.8.8 (port removed) |
| `[2001:4860:4860::8888]:443` | 2001:4860:4860::8888 |
| `https://1.1.1.1/dns-query` | 1.1.1.1 (taken from the URL) |
| `134744072` | 8.8.8.8 (an address written as one integer) |
| `৮.৮.৮.৮` | 8.8.8.8 (Bengali digits) |
| `fe80::1%eth0` | fe80::1 (link-local, with a zone) |

It does **not** guess when input is ambiguous. It explains instead:

```text
$ ipfinder lookup 010.1.1.1 0x7f000001 google.com
[!] '010.1.1.1': Leading zero in octet '010' of '010.1.1.1' is ambiguous
    hint: some software reads it as octal (e.g. inet_aton reads it as 8.1.1.1;
CVE-2021-29921); remove leading zeros
[!] '0x7f000001': '0x7f000001' is a non-standard (hex/octal/shorthand) IPv4 form
    hint: inet_aton-style software reads it as 127.0.0.1; write it as dotted
decimal
[!] 'google.com': 'google.com' looks like a hostname, not an IP address
    hint: IP Finder takes IP addresses only; find the name's address first, e.g.
with 'nslookup'
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | At least one input was not a valid IP; or `me` could not find your IP; or a list download failed |
| `2` | Usage error: bad option, unreadable input file, unwritable output file, port in use, or active mode not confirmed |
| `3` | Internal error |
| `130` | Stopped with Ctrl+C |

The report goes to **stdout**. Prompts, progress and error messages go to **stderr**. So `ipfinder -f json 8.8.8.8 > out.json` always produces valid JSON.

### Level 2: reading a report

The terminal report is a set of sections. A section is only shown when it has something to say.

| Section | What it tells you |
|---|---|
| **Summary** | The address, its type (from IANA's special-purpose registry), whether it is globally reachable, and which address the online sources were asked about |
| **Verdict** | The combined answer: connection type, anycast, location consensus, location confidence, reputation and exposure. Each score has a `why` line listing every rule that added or removed points |
| **Location (approximate)** | Each source's country, city and coordinates side by side, MaxMind's accuracy radius, map links and the local time there |
| **Representations**, **IPv4 details** | Integer, hex, binary, reverse-DNS name, IPv4-mapped IPv6, historic class |
| **Embedded IPv4**, **Interface identifier** | IPv4 hidden inside IPv6 (6to4, Teredo with port, NAT64), and a MAC address from EUI-64 |
| **Network**, **Network type (PeeringDB)** | ASN, AS name, ISP, prefix, registry, and what kind of network it is |
| **Registration (RDAP)**, **Abuse contact** | Who the block is registered to, range, dates, and where to report abuse |
| **Routing and RPKI (RIPEstat)** | Whether the prefix is announced in BGP, by which AS, and whether RPKI says that is valid |
| **Reverse DNS** | The PTR name, and whether it is forward-confirmed (FCrDNS) |
| **Anonymity and hosting (local lists)** | Tor exit, iCloud Private Relay, cloud/CDN range, listed VPN or datacenter network |
| **Exposed services (Shodan InternetDB)** | Open ports, software, possible CVEs |
| **Threat reputation** | AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox, URLhaus, Spamhaus (full profile only) |
| **Active probes** | Round trip, traceroute, TLS certificate (only with `--active`) |
| **Sources** | Every source with `ok`, `skipped` (and why) or `error` (and why). One failing source never stops the others |

A real example, using MaxMind's official **test** database (not real GeoLite2 data):

```text
│ Verdict                                                                      │
│   Connection type        Unknown                                             │
│   Location (consensus)   London, GB  (MaxMind radius 10 km)                  │
│   Location confidence    90/100 HIGH                                         │
│     why                  only one source gave coordinates, nothing to        │
│                          cross-check (-10)                                   │
```

**Location confidence** starts at 100, and rules take points away or add them, for example:
- −25 when the sources are over 100 km apart.
- −20 for a mobile network.
- −60 for anycast.
- +10 when the operator's own geofeed agrees.

70 and over is High, 40–69 Medium, under 40 Low. These are transparent rules, not probabilities; the full table is in [docs/REPORT.md](docs/REPORT.md) §5.4.

**Reputation** (has something bad come from this address?) and **exposure** (what is open on it?) are separate scores and are never added together. When no source could be asked, no score is shown, because "0" means "nothing found", not "not checked".

Add `-v` to also see Python's own `ipaddress` flags and every IANA range the address falls in.

### Level 3: files, batches and output formats

**Many addresses from a file:** put one per line; `#` starts a comment.

```bash
ipfinder batch ips.txt                 # same as: ipfinder lookup -i ips.txt
cat ips.txt | ipfinder lookup          # from stdin
```

- Files may be UTF-8 (with or without BOM) or UTF-16, the format Windows PowerShell often writes.
- With two or more addresses in a terminal, a progress bar shows on stderr and disappears when done.
- ip-api's batch endpoint (100 addresses per request) is used automatically.

**Output formats** (`-f`) and files (`-o`):

```bash
ipfinder lookup -f json 8.8.8.8                        # everything, machine-readable
ipfinder lookup -f csv -o report.csv 8.8.8.8 1.1.1.1   # one row per address
ipfinder lookup -f html -o report.html 8.8.8.8 1.1.1.1 # report with a map
ipfinder batch ips.txt -f html -o report.html
```

| Format | Best for | Details |
|---|---|---|
| `text` (default) | Reading | Coloured panels; text from the network can never control your terminal (control characters are shown escaped). `--no-color` turns colours off |
| `json` | Programs | Every source's raw data, the summary and the verdict with each score's breakdown |
| `csv` | Excel, spreadsheets | 38 columns, one row per address; invalid inputs get a row with the reason in `error`. Text that starts with `=`, `+`, `-` or `@` gets a leading `'` so Excel never runs it as a formula. With `-o`, a UTF-8 BOM is added so Excel shows names like "Linköping" correctly |
| `html` | Sharing, presenting | One self-contained file: an interactive map (each source's point, MaxMind's accuracy circle, the consensus point) and the full report. The map library and country outlines are inside the file, so it opens without internet and contacts nobody |

Output files are written to a temporary file first and then renamed, so a failed write never destroys an existing report.

### Level 4: more sources (keys, GeoLite2, lists)

Run `ipfinder sources` to see every source, whether it is ready, and what it needs.

**1. API keys.** Copy `.env.example` to `.env` and fill in only the keys you have. Every key is optional, and the keys stay on your computer (`.env` is git-ignored).

| Key | Source | Free tier (as documented by each provider) |
|---|---|---|
| `IPINFO_TOKEN` | IPinfo Lite: country, ASN | Free, unlimited |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | Lets `update-lists` download GeoLite2 for you | Free account |
| `PEERINGDB_API_KEY` | PeeringDB: higher limits | Optional |
| `ABUSEIPDB_API_KEY` | AbuseIPDB: abuse score and reports | About 1,000 checks a day |
| `GREYNOISE_API_KEY` | GreyNoise: internet scanner or known-good service | Optional; IPv4 only; free account 50 lookups a week |
| `VIRUSTOTAL_API_KEY` | VirusTotal: security vendors' verdicts | 4 a minute, 500 a day, non-commercial |
| `OTX_API_KEY` | AlienVault OTX: threat pulses | Free account |
| `ABUSECH_AUTH_KEY` | ThreatFox and URLhaus | Free; mandatory since 30 June 2025 |
| `SPAMHAUS_DQS_KEY` | Spamhaus ZEN blocklists | Free for low-volume, non-commercial use; needed if your DNS resolver is a public one such as 8.8.8.8 |

The threat-intelligence keys are only used with `--profile full` (see [Level 5](#level-5-profiles-privacy-and-offline-mode)).

**2. MaxMind GeoLite2** (city, coordinates and accuracy radius, offline). Create a free MaxMind account, then either:
- put `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` in `.env` and run `ipfinder update-lists maxmind`, or
- download "GeoLite2 City" and "GeoLite2 ASN" in MaxMind DB (`.mmdb`) format and put them in `data/`.

Details: [data/README.md](data/README.md).

**3. Downloaded lists.** A lookup never downloads big files itself; this command does:

```bash
ipfinder update-lists                  # all lists (and GeoLite2 when the MaxMind key is set)
ipfinder update-lists tor-exits aws    # only some
ipfinder update-lists --status         # what is there and how old it is
ipfinder update-lists --force          # download even if still fresh
```

The available names are:
- **Tor:** `tor-exits`, `tor-exit-addresses`
- **Cloud and CDN:** `aws`, `google-cloud`, `google`, `azure`, `oracle`, `cloudflare`, `fastly`
- **Apple:** `private-relay`
- **VPN and datacenter (X4BNet):** `vpn-networks`, `datacenter-networks`, `vpn-asns`, `datacenter-asns`
- **Threat lists:** `feodo`, `spamhaus-drop-v4`, `spamhaus-drop-v6`, `spamhaus-asndrop`
- **MaxMind:** `maxmind`

Every download is parsed and validated before it replaces the old file, so an error page or a half-finished download never spoils a good list. The Tor lists change hourly (the report warns when they are over 6 hours old); the others change daily or weekly.

**4. MAC vendor names** (optional). For the vendor behind an EUI-64 IPv6 address, download IEEE's list:

```bash
curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

**Cache.** Online answers are stored in `data/cache.sqlite`, so looking at the same address again costs no quota. How long each answer is kept:

| Source | Kept for |
|---|---|
| Reverse DNS | 1 hour |
| RIPEstat | 6 hours |
| ip-api, IPinfo, Team Cymru, Geofeed, InternetDB | 1 day |
| RDAP, PeeringDB | 7 days |
| Local lists and GeoLite2 | Never cached (always read fresh) |

Errors are never stored on disk, so the next run tries again.

```bash
ipfinder cache info                    # where the cache is and what is in it
ipfinder cache clear                   # delete it
ipfinder lookup --no-cache 8.8.8.8     # neither read nor write the cache
```

### Level 5: profiles, privacy and offline mode

Each lookup sends the address to some outside services. You choose how many:

| Mode | What runs | Who sees the address |
|---|---|---|
| `--offline` | Address analysis, GeoLite2 files, downloaded lists | **Nobody.** Tests count zero HTTP requests and zero DNS queries |
| `--profile quick` | Address analysis and ip-api | ip-api. Its free tier is plain HTTP, so anyone on the path could see it |
| `--profile standard` (default) | Every source that needs no threat-intelligence key | ip-api, IPinfo (with a token), Team Cymru (via your DNS resolver), the right Regional Internet Registry (RDAP), RIPEstat, Shodan InternetDB. Reverse DNS reaches the address owner's DNS server through your resolver |
| `--profile full` | Also AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox, URLhaus, Spamhaus | All of the above and seven threat-intelligence services; this is why it is not the default |

```bash
ipfinder --offline 8.8.8.8             # anycast is still recognised from a built-in table
ipfinder --profile quick 8.8.8.8       # fast, one outside service
ipfinder --profile full 8.8.8.8        # adds threat intelligence (needs keys)
```

- `--offline` cannot be combined with `--active` (active means sending packets).
- `me` does not work offline, because it has to ask ip-api.
- For private, CGNAT, link-local and other non-public addresses, no online source is asked at all, whatever the mode.

The full table, taken from the code: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Level 6: active probes

Everything so far is passive: the target never notices. `--active` sends packets **directly to the target**. Use it only on systems you own or have written permission to test.

```bash
ipfinder --active 8.8.8.8                       # asks you to type the confirmation phrase
ipfinder lookup --active --authorized -i mine.txt   # in scripts: confirm in advance
```

This is what you see if the answer is not the exact phrase (real output):

```text
[!] Active mode sends packets directly to the target (TCP handshakes on ports 443/80, ping, traceroute, a TLS handshake).
    Only scan systems you own or have written permission to test.
    Type 'I AM AUTHORIZED' to continue: yes please
[!] Not confirmed. Nothing was sent.
```

| Probe | What it sends | What it tells you |
|---|---|---|
| Round trip (RTT) | 4 TCP handshakes to port 443 (else 80), and 4 pings with your system's `ping` | The lowest round-trip time, even if the port is closed |
| Traceroute | Your system's `traceroute`, `tracert` or `tracepath`, up to 30 hops | Each router on the path and its network (via Team Cymru) |
| TLS certificate | A TLS handshake on port 443 | Names on the certificate, issuer, validity, self-signed or trusted, SHA-256 and a crt.sh link |

**Rules:**
- Nothing is sent without `--active` and the phrase. Without a terminal to ask in, `--authorized` is required, or the exit code is 2.
- At most 20 addresses per run.
- Public addresses only.
- No port scan.

**Speed-of-light check:** light in fibre covers about 200 km per millisecond, so a round trip of R ms puts the address at most R/2 × 200 km away from you. If the sources claim a location farther than that, the location is wrong (or the address is anycast), and confidence loses 30 points. Set your own position for this check in `.env` as `IPFINDER_LOCATION=23.8103,90.4125` (±10 km). Otherwise your public IP's location from ip-api is used (±100 km).

**Proxy detection:** some networks (corporate firewalls, antivirus HTTPS scanning, captive portals) answer every connection themselves. Before trusting a handshake, IP Finder tries `192.0.2.1`, a documentation address that is never routed. If something answers, the timings and certificate would be the proxy's, so they are discarded and the report says why.

### Level 7: the web dashboard

```bash
python -m pip install -e ".[web]"      # once
ipfinder serve                          # prints http://127.0.0.1:8000/#token=...
ipfinder serve --open                   # also opens your browser
```

Open the printed link. In the page you can:
- Type up to 100 addresses (or load a text file), choose a profile, and press **Look up**. Results stream in one by one, each with its map and full report.
- Download the lookup as an HTML report, CSV or JSON, without running it again. The server keeps the last 20 lookups.
- See every data source and whether it is ready.

| Option | Effect |
|---|---|
| `--port 8080` | Another port |
| `--offline` | Lookups use local sources only; "My public IP" is hidden |
| `--allow-active` | Active probes from the page; every lookup still needs the phrase, at most 20 addresses |
| `-p full` | The profile selected in the page at first |
| `--host 0.0.0.0 --allowed-host 192.168.1.5` | Reachable from other computers on your network, as `http://192.168.1.5:8000/` |

**How it protects you** (it runs lookups with your API keys):
- It listens on `127.0.0.1` only, unless you say otherwise.
- Every start creates a new random token. The token sits after `#` in the link, which browsers never send to a server; every API call must carry it.
- The `Host` header is checked against DNS rebinding, and requests from other websites are refused (`Origin`, `Sec-Fetch-Site`, no CORS).
- A strict Content-Security-Policy allows scripts only from the server itself.

With `--host 0.0.0.0` the connection is plain HTTP, so only use it on a network you trust.

### Level 8: scripting and automation

**JSON structure** (from a real run):

```text
{ tool, version, generated_at, disclaimer,
  reports: [ { input, ip, version, lookup, notes,
               summary: { country_by_source, countries_agree, coordinates, map_links, local_time, ... },
               results: [ { provider, layer, ok, data, error, skipped, cached, elapsed_ms }, ... ],
               verdict: { connection, anycast, location, location_confidence,
                          reputation, exposure, rtt_check } } ],     # each only when it applies
  errors:  [ { input, error, hint } ] }
```

Examples with [jq](https://jqlang.github.io/jq/), all tested:

```bash
# one line per address: IP, connection type, country
ipfinder lookup -f json 8.8.8.8 1.1.1.1 \
  | jq -r '.reports[] | [.ip, .verdict.connection.label, (.verdict.location.country_code // "-")] | @tsv'

# the confidence score with every reason
ipfinder lookup -f json 8.8.8.8 | jq '.reports[0].verdict.location_confidence'

# which sources answered
ipfinder lookup -f json 8.8.8.8 | jq -r '.reports[0].results[] | select(.ok) | .provider'

# inputs that were not IP addresses
ipfinder batch ips.txt -f json | jq -r '.errors[] | "\(.input): \(.error)"'
```

The first one, run as `ipfinder lookup --offline -f json 81.2.69.142 8.8.8.8 100.64.1.1 | jq ...` with MaxMind's test database (tab-separated):

```text
81.2.69.142	Unknown	GB
8.8.8.8	Anycast service (Google Public DNS)	-
100.64.1.1	Shared Address Space (CGNAT): not reachable from the internet	-
```

**In shell scripts:**
- Test the exit code: `1` means some inputs were not IP addresses, `2` a usage problem.
- Keep stdout for data; messages go to stderr.
- For active probes in scripts, add `--authorized` only when you really are allowed to test the targets.

**Large batches:** `ipfinder batch big-list.txt -f csv -o results.csv`. The rate limiters keep every source within its published limit: for ip-api that is 45 single lookups and 15 batch requests (of up to 100 addresses) a minute, with a half-second safety margin. The cache makes repeated runs fast.

### Level 9: using it as a Python library

The same engine can be called from Python. This example was run as written:

```python
import asyncio

from ipfinder.core.config import Config
from ipfinder.core.orchestrator import analyze_many
from ipfinder.core.session import Session


async def main():
    config = Config.load(offline=True)  # or profile="standard", "full"
    async with Session(config) as session:
        reports, errors = await analyze_many(["81.2.69.142", "100.64.1.1", "bad"], session)
    for report in reports:
        verdict = report.verdict
        place = verdict.get("location", {}).get("city", "-")
        print(report.ip, "|", verdict["connection"]["label"], "|", place)
    for error in errors:
        print("not an IP:", error["input"], "-", error["error"])


asyncio.run(main())
```

Output (with MaxMind's test database):

```text
81.2.69.142 | Unknown | London
100.64.1.1 | Shared Address Space (CGNAT): not reachable from the internet | -
not an IP: bad - 'bad' is not a valid IPv4 or IPv6 address
```

Other useful entry points:
- `report.to_dict()`: the JSON form.
- `ipfinder.core.orchestrator.iter_analyze()`: yields each result as soon as it is ready.
- `ipfinder.output.html_report.render(reports, errors)`: the HTML report.
- `ipfinder.output.csv_out.render(reports, errors)`: the CSV.

---

## Command reference

| Command | Purpose |
|---|---|
| `ipfinder lookup IP...` (or just `ipfinder IP...`) | Analyse addresses |
| `ipfinder batch FILE` | Analyse every address in a file |
| `ipfinder me` | Analyse your own public IP |
| `ipfinder sources` | Every source, whether it is ready, what it needs |
| `ipfinder update-lists [NAME...] [--status] [--force]` | Download or check lists and GeoLite2 |
| `ipfinder cache info` / `ipfinder cache clear` | Show or delete the cache |
| `ipfinder serve [options]` | Start the web dashboard |
| `ipfinder --version` | Show the version |

Options for `lookup`, `batch` and `me` (they may come before or after the command):

| Option | Effect |
|---|---|
| `-f, --format text\|json\|csv\|html` | Output format |
| `-o, --output FILE` | Write to a file |
| `-i, --input-file FILE` | Read addresses from a file (`lookup` only) |
| `-p, --profile quick\|standard\|full` | Which sources run |
| `--offline` | Local sources only |
| `--active` / `--authorized` | Active probes / confirm them in advance |
| `--no-cache` | Neither read nor write the cache |
| `-v, --verbose` | Python flags and all matching ranges |
| `--no-color` | No colours |

## Settings reference

All settings live in `.env` (or real environment variables, which win). The file is git-ignored.

| Setting | Default | Meaning |
|---|---|---|
| API keys | none | See the [table in Level 4](#level-4-more-sources-keys-geolite2-lists) |
| `IPFINDER_MAXMIND_CITY_DB` | `data/GeoLite2-City.mmdb` | GeoLite2 City file |
| `IPFINDER_MAXMIND_ASN_DB` | `data/GeoLite2-ASN.mmdb` | GeoLite2 ASN file |
| `IPFINDER_LISTS_DIR` | `data/lists` | Downloaded lists |
| `IPFINDER_CACHE` | `data/cache.sqlite` | Lookup cache |
| `IPFINDER_OUI_DB` | `data/oui.csv` | IEEE vendor list |
| `IPFINDER_LOCATION` | not set | Your `latitude,longitude`, for the speed-of-light check |

---

## What it can tell you: the 12 layers

| Layer | Question | Sources |
|---|---|---|
| L1 | What kind of address is it? | Built-in IANA table, IPv6 decoding (6to4, Teredo, NAT64, EUI-64) |
| L2 | Where is its network? | ip-api, IPinfo Lite, MaxMind GeoLite2, Geofeed (the operator's own data) |
| L3 | Who runs the network? | Team Cymru, PeeringDB, MaxMind ASN |
| L4 | Who is it registered to, and the abuse contact? | RDAP (IANA bootstrap, then the right registry) |
| L5 | Is it announced in BGP, is RPKI valid? | RIPEstat |
| L6 | What is its name? | Reverse DNS with forward confirmation |
| L7 | Anonymity or hosting? | Tor exit list, iCloud Private Relay, AWS/Google/Azure/Oracle/Cloudflare/Fastly ranges, X4BNet VPN and datacenter lists |
| L8 | Which services are exposed? | Shodan InternetDB |
| L9 | Any threat reputation? | AbuseIPDB, GreyNoise, VirusTotal, AlienVault OTX, ThreatFox, URLhaus, Spamhaus ZEN, Feodo Tracker, Spamhaus DROP |
| L10 | Does it answer, and how fast? | Round trip, traceroute, TLS certificate (`--active` only) |
| L11 | What do the sources add up to? | Location consensus, confidence, connection type, anycast, reputation and exposure scores |
| L12 | How is it reported? | Terminal, JSON, CSV, HTML map, web dashboard |

---

## How it works

1. **Validator.** Turns the text you typed into an address, or a clear error.
2. **Stage 0 (offline analysis).** Decides whether online lookups apply, and for which address. For example, Teredo or 6to4 addresses are looked up by the IPv4 address inside them.
3. **Stage 1.** All independent sources run at once.
4. **Stage 2.** Sources that need stage-1 data: PeeringDB needs the ASN, Geofeed needs the RDAP record.
5. **Stage 3.** Active probes (only with permission), after the passive lookups so their traffic does not distort the timings.
6. **Analysis engine.** Combines everything into the verdict.

All of this shares one session (HTTP client, cache, rate limiters). The web dashboard keeps one session for the whole server, so ip-api's limit holds across browser tabs.

**Why its own IANA table?** Python's `ipaddress.is_global` disagrees with IANA's registry on some addresses, and the answer changes between Python versions. Tested on Python 3.10–3.14:
- `5f00::1` (SRv6, not globally reachable) is `True` in Python.
- `2001:1::3` (globally reachable) is `False` in Python.
- `3fff::1` (documentation) is `True` only in Python 3.12.3.

So IP Finder uses a table built from IANA's registry (`ipfinder/core/special_ranges.py`) and reports where Python disagrees.

More: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (diagram, data flow, provider contract) and [docs/REPORT.md](docs/REPORT.md) (algorithms with formulas).

---

## What is verified, and what is not yet

The development environment could not reach most outside services, so the status is stated plainly.

**Verified for real:**
- Address analysis against IANA's registry, on Python 3.10, 3.11, 3.12, 3.13 and 3.14.
- AWS `ip-ranges.json` (17,570 prefixes) and the X4BNet VPN and datacenter lists, downloaded live.
- MaxMind's official test databases.
- The built-in X.509 certificate reader, matched against CPython on 128 real CA certificates.
- The HTML report and the dashboard in a real browser (Chromium): maps drawn, no Content-Security-Policy errors, no requests to outside servers.
- `--offline` makes no HTTP request and no DNS query (counted in tests).
- The dashboard on the oldest and newest allowed versions (FastAPI 0.115.0 and 0.143.0, uvicorn 0.30.0 and 0.54.0).

**Not yet run against the live service** (tested against each service's documented response format):
- ip-api, IPinfo, Team Cymru, RDAP, RIPEstat, reverse DNS, Geofeed, Shodan InternetDB.
- The threat-intelligence APIs.
- The Tor, Apple, Google, Azure, Oracle, Cloudflare and Fastly lists.
- Real ping and traceroute output.

To record real responses on a connected computer:

```bash
cp .env.example .env               # add only the keys you have
python scripts/capture_fixtures.py --list
python scripts/capture_fixtures.py # 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888
python scripts/demo.py --check     # what is ready for a demo
```

---

## Limits

- **Geolocation is approximate.** It locates the network, never a person. VPN, Tor, CGNAT and mobile networks move it further away.
- **A listing is suspicion, not proof.** Shared addresses (CGNAT, cloud, VPN) carry other people's history. One or two VirusTotal engines flagging an address is common.
- **VPN lists are community-made.** "Listed VPN network" means the network is known as one, not that a given connection used a VPN. VPNs not on the list are not detected. Tor's list has no IPv6 addresses.
- **Free tiers have terms.** ip-api, VirusTotal and Shodan InternetDB are free for non-commercial use only, and ip-api's free tier is plain HTTP.
- **The confidence rules are not calibrated** on a dataset of known locations yet.

---

## Responsible use

- Default lookups are passive and never touch the target.
- Active probes need `--active` and the exact phrase `I AM AUTHORIZED`. They are limited to 20 public addresses per run, with no port scan.
- **Bangladesh:** the Cyber Security Ordinance 2025 (Ordinance No. 25 of 2025) makes entering or interfering with a computer system without permission an offence. Check the latest status in the official Gazette before relying on this. Details: [ADVANCED_PLAN.md §9](ADVANCED_PLAN.md#9-security-ethics-ও-আইন).
- API keys live only in `.env`, and error messages never contain request URLs (IPinfo puts its token in the URL).
- The cache and lists stay in `data/`, which is git-ignored, so no lookup history is ever committed.

---

## Development

```bash
python -m pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest -q
```

**Tests.** 631 tests run with no internet and no API keys:
- Online sources are tested with a fake HTTP layer and a fake DNS resolver.
- The MaxMind part uses MaxMind's official test databases.
- The whole offline demo runs end to end inside the suite, behind a dead proxy that would expose any network use.
- GitHub Actions runs everything on Python 3.10 to 3.14 on every push.

**Helper scripts:**

| Script | Purpose |
|---|---|
| `scripts/demo.py` | Guided 11-step demo (`--offline`, `--check`, `--list`, `--from N`, `--yes`) |
| `scripts/capture_fixtures.py` | Record real API responses for tests (keys are never written) |
| `scripts/check_html_report.py` | Open an HTML report in Chromium and check the maps (needs Playwright) |
| `scripts/check_dashboard.py` | Start the dashboard and use it in Chromium (needs Playwright) |
| `scripts/build_world_map.py` | Rebuild the embedded Natural Earth map data |

**Adding a source.**
1. Write a class that extends `Provider` in `ipfinder/providers/`.
2. Set its name, layer, stage, profiles, key, `local`/`active`, cache time and rate limit, and implement `lookup()`.
3. Add it to `default_providers()` in `ipfinder/providers/__init__.py`.

The orchestrator, cache, rate limiter, `sources` command and reports handle the rest.

**Project structure:**

```text
IP-Finder/
├── ipfinder/
│   ├── cli.py            # the command line
│   ├── core/             # validator, IANA table, config, session, cache, rate limiter, orchestrator
│   ├── providers/        # the 27 sources (base.py is the contract)
│   ├── lists/            # downloadable lists: specs, safe storage, prefix index, GeoLite2 download
│   ├── analysis/         # offline analysis, consensus, classification, scores, speed-of-light check
│   ├── active/           # active probes and a small X.509 reader
│   ├── output/           # terminal, JSON, CSV, HTML report (+ embedded Leaflet and Natural Earth)
│   └── web/              # the web dashboard (FastAPI app and its page)
├── scripts/              # demo, fixture capture, browser checks, map data builder
├── tests/                # pytest suite (offline)
├── docs/                 # architecture, report, demo, viva notes, phase notes, screenshots
├── data/                 # downloaded databases, lists and cache (git-ignored)
├── .env.example          # every setting and key
└── ADVANCED_PLAN.md      # the full plan (Bengali)
```

---

## Documentation

The project documents are in Bengali, with technical terms in English.

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagram, the path of a lookup, the provider contract, who sees the address in each mode |
| [docs/REPORT.md](docs/REPORT.md) | Project report: goals, design, algorithms, testing, results, limits, references |
| [docs/DEMO.md](docs/DEMO.md) | A 10-minute demo script with talking points, online and offline |
| [docs/VIVA.md](docs/VIVA.md) | 35 viva questions with answers and code pointers |
| [docs/PHASE_NOTES.md](docs/PHASE_NOTES.md) | Detailed notes for each development phase, with real outputs |
| [ADVANCED_PLAN.md](ADVANCED_PLAN.md) | The full plan, data-source checks and roadmap |
| [data/README.md](data/README.md) | Which data files exist and how to get them |

Screenshots: [HTML report](docs/html-report-example.png) and [dashboard](docs/dashboard-example.png). Both use MaxMind's test database, not real GeoLite2 data.

---

## Roadmap status

| Phase | Topic | Status |
|---|---|---|
| 0 | Setup, `.env`, CI, fixture capture script | 🟡 Script ready; real API fixtures still to be recorded |
| 1 | Validator, offline analysis, CLI | ✅ |
| 2 | ip-api, IPinfo Lite, MaxMind, Team Cymru, PeeringDB; cache; rate limiter | ✅ (first live run pending) |
| 3 | RDAP, RIPEstat (BGP/RPKI), reverse DNS, Geofeed | ✅ (first live run pending) |
| 4 | Tor, Private Relay, cloud ranges, VPN lists, InternetDB; `update-lists` | ✅ (AWS and X4BNet verified live) |
| 5 | Threat intelligence and offline threat lists | ✅ (first live run pending) |
| 6 | Analysis engine: consensus, confidence, connection type, scores | ✅ |
| 7 | Active mode with confirmation and proxy detection | ✅ |
| 8 | CSV, HTML report with offline map, batch, progress bar | ✅ |
| 9 | Web dashboard | ✅ |
| 10 | Architecture, report, demo, viva notes; `--offline` | ✅ |
