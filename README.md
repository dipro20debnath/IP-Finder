# IP Finder v2 (Phase 0–2)

একটি IP address থেকে **আইনসঙ্গতভাবে যা যা জানা সম্ভব**, তা ধাপে ধাপে বের করার Python tool। পুরো roadmap: [ADVANCED_PLAN.md](ADVANCED_PLAN.md)।

এই version-এ আছে **Phase 0 (setup)**, **Phase 1 (offline analysis)** আর **Phase 2 (location ও network: ip-api, IPinfo Lite, MaxMind GeoLite2, Team Cymru, PeeringDB)**। কোনো API key ছাড়াই চলে; key বা database যোগ করলে আরও source যুক্ত হয়। RDAP, BGP/RPKI, DNS আসবে Phase 3-এ।

> ⚠️ IP geolocation আনুমানিক। একটি IP address কোনো ব্যক্তিকে শনাক্ত করে না।

---

## Phase 2: location ও network

| Source | কী দেয় | Key / file | সীমা ও শর্ত |
|---|---|---|---|
| **ip-api** | দেশ, অঞ্চল, শহর, ZIP, lat/lon, timezone, ISP, org, ASN, reverse DNS, mobile/proxy/hosting flag | লাগে না | 45 req/min (single), batch 100টি IP × 15 req/min; free tier শুধু HTTP, non-commercial |
| **IPinfo Lite** | দেশ, মহাদেশ, ASN, AS name ও domain | `IPINFO_TOKEN` (free) | Unlimited (IPinfo-র দাবি) |
| **MaxMind GeoLite2** | শহর, lat/lon **± accuracy radius**, timezone, registered country, ASN | `data/GeoLite2-City.mmdb`, `data/GeoLite2-ASN.mmdb` (free account) | Offline; database-এর build date report-এ দেখায় |
| **Team Cymru** | BGP-তে announce করা prefix, origin ASN, RIR, allocation date, AS name | লাগে না (DNS) | Fair use |
| **PeeringDB** | ASN-টা কেমন network: ISP / Content / Education, scope, peering policy | ঐচ্ছিক `PEERINGDB_API_KEY` | ASN জানা গেলে তবেই চলে |

- **Cache:** online উত্তর `data/cache.sqlite`-এ জমা থাকে (ip-api, IPinfo, Team Cymru ১ দিন, PeeringDB ৭ দিন), তাই একই IP বারবার দেখলে free quota খরচ হয় না।
- **Rate limiter:** ip-api-র ৪৫/মিনিট সীমা কখনো পার হয় না। নিরাপত্তার জন্য ০.৫ সেকেন্ড margin রাখা আছে, আর `X-Rl`/`X-Ttl` header ও HTTP 429 মানা হয়। একাধিক IP দিলে ip-api-র batch endpoint ব্যবহার হয়।
- **একাধিক source পাশাপাশি:** দেশ বা ASN নিয়ে source-গুলো একমত না হলে সতর্কবার্তা দেখায়। MaxMind-এর "registered country" আর "location country" আলাদা হলেও জানায়।
- **Map ও সময়:** OpenStreetMap ও Google Maps link (accuracy radius থাকায় MaxMind-কে প্রাধান্য), আর ওই এলাকার এখনকার local time।
- **নিরাপত্তা:** IPinfo-র token URL-এ যায়, তাই কোনো error বার্তা বা report-এ URL লেখা হয় না।
- **সৎ বার্তা:** DNS blocked থাকলে Team Cymru "not announced" বলে না; আগে যাচাই করে বলে যে DNS-এ সমস্যা।

### আসল output (সংক্ষেপিত): MaxMind-এর test database দিয়ে

```text
$ ipfinder 89.160.20.112
│ Location (approximate)                                                       │
│   Source    Country       City / Region             Coordinates              │
│   maxmind   Sweden (SE)   Linköping, Östergötland   58.4167, 15.6167 (±76    │
│                           County                    km)                      │
│   Registered in      Germany (DE) - the owner's country differs from where   │
│                      the IP is used                                          │
│   Map (maxmind)      https://www.openstreetmap.org/?mlat=58.4167&mlon=15.6   │
│                      167#map=11/58.4167/15.6167                              │
│   Local time there   2026-10-09 19:14 (Europe/Stockholm, UTC+02:00)          │
│ Network                                                                      │
│   Source    ASN       AS name        ISP / Org   Prefix          Registry    │
│   maxmind   AS29518   Bredband2 AB   -           89.160.0.0/17   -           │
│ Sources                                                                      │
│   ip-api (L2/L3/L7)     error: cannot reach ip-api.com (ConnectError)        │
│   ipinfo-lite (L2/L3)   skipped: no API key (IPINFO_TOKEN in .env)           │
│   maxmind (L2/L3)       ok (0 ms)                                            │
│   team-cymru (L3)       error: your DNS resolver cannot reach                │
│                         asn.cymru.com (blocked or filtered), so BGP origin   │
│                         is unknown                                           │
```

এই output এমন একটা environment-এ নেওয়া, যেখানে বাইরের internet বন্ধ ছিল। তাই ip-api আর Team Cymru-র অংশে error দেখাচ্ছে, আর MaxMind-এর ফল এসেছে MaxMind-এর নিজস্ব *test* database থেকে (এই data আসল internet-এর নয়)। আপনার computer-এ সব source একসাথে দেখা যাবে।

> **যাচাইয়ের অবস্থা:** ip-api, IPinfo, PeeringDB আর Team Cymru-র code প্রতিটা provider-এর documentation-এ দেওয়া response format দিয়ে test করা। আসল API-র বিরুদ্ধে প্রথমবার চালানো হবে আপনার computer-এ (`python scripts/capture_fixtures.py`)। MaxMind অংশ MaxMind-এর official test database দিয়ে test করা।

---

## Phase 1: offline analysis

| বিষয় | উদাহরণ |
|---|---|
| Validation ও পরিষ্কার error | `010.1.1.1` → leading zero ambiguous, inet_aton পড়ে `8.1.1.1` (CVE-2021-29921); `0x7f000001` → hex রূপ, আসলে `127.0.0.1`; `http://017700000001/` → leading zero, browser পড়ে `127.0.0.1`; URL-এর `\`, tab বা control character browser-এর নিয়মে পড়া হয়; `8.8.8.0/24` → CIDR, single IP নয়; `google.com` → hostname |
| Flexible input | `8.8.8.8:53`, `[2001:db8::1]:443`, `https://8.8.8.8/x`, `fe80::1%eth0`, integer `134744072`, **বাংলা সংখ্যা `৮.৮.৮.৮`** |
| IANA special-purpose classification | `100.64.1.1` → Shared Address Space (CGNAT), RFC 6598; `3fff::1` → Documentation, RFC 9637 |
| Online lookup চলবে কি না, কোন IP-তে | Private/CGNAT → না; `2002:808:808::1` (6to4) → embedded `8.8.8.8` |
| Representations | Integer, hex, binary, reverse-DNS name, IPv4-mapped IPv6, 6to4 prefix |
| IPv4 details | Historic class (A/B/C/D/E), multicast block, **GLOP থেকে AS number** (RFC 3180); 6to4 prefix শুধু public IPv4-এর জন্য (RFC 3056) |
| IPv6 embedded IPv4 | IPv4-mapped, NAT64 (RFC 6052), 6to4, **Teredo client IP + port + flags** (RFC 4380/5991) |
| IPv6 interface ID | **EUI-64 → MAC address → vendor** (group-bit যাচাই সহ), IANA-reserved ID (RFC 5453, Proxy Mobile IPv6), ISATAP, subnet-router ও RFC 2526 anycast, manual, random/privacy |
| IPv6 structure | /32, /48, /56, /64 prefix ও interface ID |
| IPv6 multicast | Scope (link/site/global…), flags, well-known group, solicited-node |

### কেন নিজস্ব IANA table? (বাস্তব পরীক্ষার ফল)

Python-এর `ipaddress.is_global` সব জায়গায় IANA registry-র সাথে মেলে না। Python version ভেদে ফলও বদলায়। এই repo-তে Python 3.10.20, 3.11.17, 3.12.3, 3.13.16 ও 3.14.6-এ পরীক্ষা করে পাওয়া গেছে:

| Address | IANA / RFC অনুযায়ী | Python `is_global` |
|---|---|---|
| `5f00::1` | SRv6 SID (RFC 9602), globally reachable **নয়** | `True` (সব version) |
| `2001:1::3` | DNS-SD SRP anycast (RFC 9665), globally reachable | `False` (সব version) |
| `fec0::1` | Site-local, RFC 3879-এ বাতিল; IANA address-space registry-তে reserved | `True` (সব version) |
| `4000::1` | `2000::/3`-এর বাইরে, unallocated | `True` (সব version) |
| `::808:808` | IPv4-compatible, deprecated (RFC 4291) | `True` (সব version) |
| `100:0:0:1::1` | Dummy IPv6 Prefix (RFC 9780, 2025), globally reachable **নয়** | `True` (সব version) |
| `192.88.99.2` | 6a44-relay anycast (RFC 6751), globally reachable **নয়** | `True` (সব version) |
| `3fff::1` | Documentation (RFC 9637) | 3.12.3-এ `True`; বাকিগুলোতে `False` |

তাই IP Finder IANA registry থেকে নিজস্ব table (`ipfinder/core/special_ranges.py`, 2025-10-09-এর registry অনুযায়ী) ব্যবহার করে। Python যেখানে ভিন্ন কথা বলে, report-এ সেটা জানায় (`-v` দিলে Python-এর সব flag দেখায়)।

একই কারণে IPv4-mapped address-এর লেখাও (`::ffff:8.8.8.8`) tool নিজে বানায়। CPython 3.12.3 এটা `::ffff:808:808` লেখে, আর 3.10.20/3.11.17/3.13+ লেখে `::ffff:8.8.8.8`।

---

## Installation

```bash
git clone https://github.com/dipro20debnath/IP-Finder.git
cd IP-Finder
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Python **3.10 বা নতুন** লাগবে। Runtime dependency: `rich` (terminal output), `httpx` (HTTP), `dnspython` (Team Cymru-র DNS), `maxminddb` (GeoLite2 file পড়া), আর Windows-এ `tzdata` (time zone)।

ঐচ্ছিক, তবে ভালো ফলের জন্য দরকারি: MaxMind GeoLite2 database (free account লাগে); কীভাবে নামাবেন তা [data/README.md](data/README.md)-তে আছে। IPinfo Lite-এর free token `.env`-এ `IPINFO_TOKEN=` হিসেবে বসান (`.env.example` দেখুন)।

ঐচ্ছিক: EUI-64 MAC-এর vendor নাম দেখাতে IEEE OUI list নামাতে পারেন:

```bash
curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

---

## ব্যবহার

```bash
ipfinder 8.8.8.8                          # "lookup" না লিখলেও চলে
ipfinder lookup 8.8.8.8 2001:4860:4860::8888
ipfinder lookup "৮.৮.৮.৮"                  # বাংলা সংখ্যা
ipfinder lookup -v 2001:1::1              # Python flags ও সব matching range সহ
ipfinder lookup -f json 8.8.8.8           # JSON output
ipfinder lookup -f json -o report.json 8.8.8.8
ipfinder lookup -i ips.txt -f json        # file থেকে (প্রতি লাইনে একটি IP, # = comment)
cat ips.txt | ipfinder lookup -f json     # stdin থেকে
ipfinder lookup --profile quick 8.8.8.8   # শুধু offline + ip-api (দ্রুত)
ipfinder lookup --no-cache 8.8.8.8        # cache না পড়ে, না লিখে
ipfinder me                               # নিজের public IP
ipfinder sources                          # প্রতিটা source প্রস্তুত কি না, কী লাগবে
ipfinder cache info                       # cache-এ কী আছে
ipfinder cache clear                      # cache মুছে ফেলা
ipfinder                                  # v1.0-এর মতো interactive prompt
python -m ipfinder 8.8.8.8                # repo folder থেকে, rich install থাকলে
```

**Exit codes:** `0` সফল, `1` অন্তত একটি input বৈধ IP নয় (বা `me` নিজের IP খুঁজে পায়নি), `2` usage ভুল (ভুল option, input file পড়া যায়নি, output file লেখা যায়নি), `3` internal error, `130` Ctrl+C।

Report যায় **stdout**-এ। Prompt, status ও error বার্তা যায় **stderr**-এ, তাই `ipfinder -f json > out.json` সবসময় বৈধ JSON দেয়। Input file UTF-8 (BOM সহ বা ছাড়া) বা UTF-16 হতে পারে, যেমন Windows PowerShell-এর তৈরি file।

**কোন folder থেকে চালাবেন:** `.env`, `data/` folder-এর database আর `data/cache.sqlite` **যে folder থেকে command চালাচ্ছেন সেখান থেকে** পড়া হয় (সাধারণত repo-র root)। অন্য জায়গা থেকে চালালে `IPFINDER_MAXMIND_CITY_DB`, `IPFINDER_MAXMIND_ASN_DB`, `IPFINDER_OUI_DB`, `IPFINDER_CACHE` দিয়ে path দিন।

### আসল output (সংক্ষেপিত): Teredo address থেকে লুকানো client IP ও port

```text
$ ipfinder 2001:0:4136:e378:8000:63bf:f7f7:f7f7
╭─ IP Finder 2.0.0a1 - 2001:0:4136:e378:8000:63bf:f7f7:f7f7 ───────────────────╮
│ Summary                                                                      │
│   Address                2001:0:4136:e378:8000:63bf:f7f7:f7f7  (IPv6)        │
│   Type                   Teredo  [2001::/32, RFC 4380]                       │
│   Globally reachable     n/a (see RFC)                                       │
│   Online lookup target   8.8.8.8  (Using the IPv4 address embedded in this   │
│                          Teredo address (teredo_client, RFC 4380, RFC        │
│                          5991))                                              │
│ ...                                                                          │
│ Embedded IPv4 (teredo_client)                                                │
│   IPv4                    8.8.8.8                                            │
│   Role                    client's public (NAT) IPv4                         │
│   Client port             40000                                              │
│   Flags                   0x8000                                             │
│   Cone bit (deprecated)   True                                               │
│   RFC 5991 random bits    False                                              │
│ Embedded IPv4 (teredo_server)                                                │
│   IPv4                 65.54.227.120                                         │
│   Role                 Teredo server                                         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### আসল output (সংক্ষেপিত): IPv6 address থেকে device-এর MAC

```text
$ ipfinder fe80::21a:2bff:fe3c:4d5e%eth0
│   Type                   Link-Local Unicast  [fe80::/10, RFC 4291]           │
│   Online lookup target   not applicable: Link-Local Unicast (RFC 4291) is    │
│                          not globally reachable, so public geolocation and   │
│                          registry data do not apply                          │
│ Interface identifier                                                         │
│   Type          eui64                                                        │
│   MAC address   00:1a:2b:3c:4d:5e                                            │
│   OUI           00:1a:2b                                                     │
│   Privacy       This MAC can identify and track the same device across       │
│                 networks                                                     │
```

---

## Project structure

```text
IP-Finder/
├── ipfinder/
│   ├── cli.py                  # argparse CLI (lookup, me, sources, cache)
│   ├── core/
│   │   ├── validator.py        # input → validated address, helpful errors
│   │   ├── text.py             # version-independent IPv6 text, safe display of input
│   │   ├── special_ranges.py   # IANA special-purpose tables + longest-prefix classify
│   │   ├── models.py           # ProviderResult, IPReport
│   │   ├── config.py           # .env + environment, API keys, paths, profile
│   │   ├── session.py          # one run: HTTP client, DNS, cache, rate limiters
│   │   ├── cache.py            # memory + SQLite cache with per-provider TTL
│   │   ├── ratelimit.py        # sliding-window limiter + server-driven pauses
│   │   ├── http.py             # JSON requests; errors never contain the URL/token
│   │   ├── dns.py              # TXT lookups (dnspython)
│   │   └── orchestrator.py     # stage 0 offline → stage 1 sources → stage 2 (PeeringDB)
│   ├── providers/
│   │   ├── base.py             # Provider interface (profile, key, files, cache, limits)
│   │   ├── offline.py          # L1
│   │   ├── ipapi.py            # ip-api single + batch
│   │   ├── ipinfo_lite.py      # IPinfo Lite
│   │   ├── maxmind.py          # GeoLite2 City + ASN (.mmdb)
│   │   ├── cymru.py            # Team Cymru IP-to-ASN over DNS
│   │   ├── peeringdb.py        # PeeringDB network type
│   │   ├── common.py           # shared normalisation helpers
│   │   └── __init__.py         # registry + planned providers (Phase 3–7)
│   ├── analysis/
│   │   ├── addressing.py       # representations, IPv4 class, multicast, Python flags
│   │   ├── ipv6_insights.py    # embedded IPv4, EUI-64/ISATAP, structure, multicast
│   │   ├── oui.py              # IEEE OUI vendor lookup
│   │   ├── offline.py          # combines L1 + online-lookup decision
│   │   └── summary.py          # map pin, local time, agreement between sources
│   └── output/
│       ├── terminal.py         # rich panels (user input never parsed as markup)
│       └── json_out.py
├── scripts/capture_fixtures.py # Phase 0: record real API responses for tests
├── tests/                      # pytest; runs offline (fake HTTP + DNS)
│   └── data/maxmind/           # MaxMind's official test databases (MIT licence)
├── data/                       # downloaded databases + cache (git-ignored)
├── .env.example                # every API key and path setting
└── .github/workflows/ci.yml    # lint + tests on Python 3.10–3.14
```

---

## Tests

```bash
ruff check . && ruff format --check .
pytest -q
```

সব test offline চলে, কোনো API key লাগে না: online source-গুলো fake HTTP ও fake DNS দিয়ে test করা হয়, আর MaxMind অংশ MaxMind-এর official test database দিয়ে। CI প্রতিটি push-এ Python 3.10, 3.11, 3.12, 3.13 ও 3.14-এ চালায়।

---

## Phase 0: আসল API response সংরক্ষণ (আপনার নিজের computer-এ)

Phase 2+-এর provider বানানোর আগে প্রতিটি API আসলে কী ফেরত দেয়, তা `tests/fixtures/`-এ রেখে দিন:

```bash
cp .env.example .env              # যে key আছে শুধু সেগুলো বসান (কোনোটাই বাধ্যতামূলক নয়)
python scripts/capture_fixtures.py --list
python scripts/capture_fixtures.py                  # 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888
python scripts/capture_fixtures.py 8.8.8.8 --only ip-api rdap   # IP আগে, তারপর --only
```

- Key ছাড়া চলে: ip-api, RDAP, RIPEstat, Shodan InternetDB, GreyNoise Community (key ঐচ্ছিক)।
- Key লাগে: IPinfo Lite, AbuseIPDB, VirusTotal (key না থাকলে skip হয়)।
- API key কখনো fixture file-এ লেখা হয় না (URL redact করা হয়, request header save হয় না)।
- Rate limit মানা হয়: ip-api-তে 45/min (`X-Rl`/`X-Ttl` header পড়ে অপেক্ষা করে), VirusTotal-এ 4/min।

> এই script লেখার environment থেকে external API-তে network access ছিল না, তাই এটি mock দিয়ে test করা হয়েছে। আসল API-র বিরুদ্ধে প্রথমবার চালানো হবে আপনার computer-এ।

---

## Roadmap অবস্থা

| Phase | বিষয় | অবস্থা |
|---|---|---|
| 0 | Setup, `.env`, CI, fixture capture script | 🟡 script প্রস্তুত; আসল API fixture এখনও রেকর্ড করা বাকি (নিচে দেখুন) |
| 1 | Validator, L1 offline analysis, models, CLI | ✅ |
| 2 | ip-api, IPinfo Lite, MaxMind, Team Cymru, PeeringDB; cache, rate limiter | ✅ (code ও test; আসল API-তে প্রথম চালানো বাকি) |
| 3 | RDAP, RIPEstat (BGP/RPKI), DNS/FCrDNS, Geofeed | ⏳ |
| 4–10 | Anonymity, threat intel, scoring, active mode, reports, dashboard | ⏳ |

`ipfinder sources` চালালে প্রতিটি data source-এর phase ও API-key অবস্থা দেখা যায়।

---

## দায়িত্বশীল ব্যবহার

- Phase 1 পুরোপুরি passive ও offline। কোনো packet কোথাও পাঠায় না।
- Active probing (Phase 7) default-এ বন্ধ থাকবে এবং শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত system-এ চালানো যাবে।
- বাংলাদেশে সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ প্রযোজ্য; বিস্তারিত [ADVANCED_PLAN.md §9](ADVANCED_PLAN.md#9-security-ethics-ও-আইন)।
