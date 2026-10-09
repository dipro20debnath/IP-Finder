# IP Finder v2 (Phase 0–1)

একটি IP address থেকে **আইনসঙ্গতভাবে যা যা জানা সম্ভব**, তা ধাপে ধাপে বের করার Python tool। পুরো roadmap: [ADVANCED_PLAN.md](ADVANCED_PLAN.md)।

এই version-এ আছে **Phase 0 (project setup)** ও **Phase 1 (offline analysis, layer L1)**। Internet ছাড়াই কাজ করে, কোনো API key লাগে না। Geolocation, ASN, RDAP ইত্যাদি online layer আসবে Phase 2 থেকে।

> ⚠️ IP geolocation আনুমানিক। একটি IP address কোনো ব্যক্তিকে শনাক্ত করে না।

---

## Phase 1-এ কী কী বের হয়

| বিষয় | উদাহরণ |
|---|---|
| Validation ও পরিষ্কার error | `010.1.1.1` → leading zero ambiguous (CVE-2021-29921); `8.8.8.0/24` → CIDR, single IP নয়; `google.com` → hostname |
| Flexible input | `8.8.8.8:53`, `[2001:db8::1]:443`, `https://8.8.8.8/x`, `fe80::1%eth0`, integer `134744072`, **বাংলা সংখ্যা `৮.৮.৮.৮`** |
| IANA special-purpose classification | `100.64.1.1` → Shared Address Space (CGNAT), RFC 6598; `3fff::1` → Documentation, RFC 9637 |
| Online lookup চলবে কি না, কোন IP-তে | Private/CGNAT → না; `2002:808:808::1` (6to4) → embedded `8.8.8.8` |
| Representations | Integer, hex, binary, reverse-DNS name, IPv4-mapped IPv6, 6to4 prefix |
| IPv4 details | Historic class (A/B/C/D/E), multicast block, **GLOP থেকে AS number** (RFC 3180) |
| IPv6 embedded IPv4 | IPv4-mapped, NAT64 (RFC 6052), 6to4, **Teredo client IP + port + cone flag** |
| IPv6 interface ID | **EUI-64 → MAC address → vendor**, ISATAP, subnet-router anycast, RFC 2526 anycast, manual, random/privacy |
| IPv6 structure | /32, /48, /56, /64 prefix ও interface ID |
| IPv6 multicast | Scope (link/site/global…), flags, well-known group, solicited-node |

### কেন নিজস্ব IANA table? (বাস্তব পরীক্ষার ফল)

Python-এর `ipaddress.is_global` সব জায়গায় IANA registry-র সাথে মেলে না। Python version ভেদে ফলও বদলায়। এই repo-তে Python 3.10.20, 3.11.17, 3.12.3, 3.13.16 ও 3.14.6-এ পরীক্ষা করে পাওয়া গেছে:

| Address | IANA / RFC অনুযায়ী | Python `is_global` |
|---|---|---|
| `5f00::1` | SRv6 SID (RFC 9602), globally reachable **নয়** | `True` (সব version) |
| `2001:1::3` | DNS-SD SRP anycast (RFC 9665), globally reachable | `False` (সব version) |
| `fec0::1` | Site-local, deprecated (RFC 3879) | `True` (সব version) |
| `4000::1` | `2000::/3`-এর বাইরে, unallocated | `True` (সব version) |
| `::808:808` | IPv4-compatible, deprecated (RFC 4291) | `True` (সব version) |
| `3fff::1` | Documentation (RFC 9637) | 3.12.3-এ `True`; বাকিগুলোতে `False` |

তাই IP Finder IANA registry থেকে নিজস্ব table (`ipfinder/core/special_ranges.py`) ব্যবহার করে। Python যেখানে ভিন্ন কথা বলে, `-v` দিলে report-এ সেটা দেখায়।

---

## Installation

```bash
git clone https://github.com/dipro20debnath/IP-Finder.git
cd IP-Finder
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Python **3.10 বা নতুন** লাগবে। শুধু একটি runtime dependency: `rich` (রঙিন terminal output)।

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
ipfinder sources                          # কোন data source কোন phase-এ, key আছে কি না
ipfinder                                  # v1.0-এর মতো interactive prompt
python -m ipfinder 8.8.8.8                # install ছাড়াও চলে
```

**Exit codes:** `0` সফল, `1` অন্তত একটি input বৈধ IP নয়, `2` command-line ভুল, `3` internal error, `130` Ctrl+C।

### আসল output (সংক্ষেপিত): Teredo address থেকে লুকানো client IP ও port

```text
$ ipfinder 2001:0:4136:e378:8000:63bf:f7f7:f7f7
╭─ IP Finder 2.0.0a1 - 2001:0:4136:e378:8000:63bf:f7f7:f7f7 ───────────────────╮
│ Summary                                                                      │
│   Address                2001:0:4136:e378:8000:63bf:f7f7:f7f7  (IPv6)        │
│   Type                   Teredo  [2001::/32, RFC 4380]                       │
│   Globally reachable     n/a (see RFC)                                       │
│   Online lookup target   8.8.8.8  (Using the IPv4 address embedded in this   │
│                          Teredo address (teredo_client, RFC 4380))           │
│ ...                                                                          │
│ Embedded IPv4 (teredo_client)                                                │
│   IPv4                 8.8.8.8                                               │
│   Role                 client's public (NAT) IPv4                            │
│   Client port          40000                                                 │
│   Cone NAT flag        True                                                  │
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
│   ├── cli.py                  # argparse CLI (lookup, sources)
│   ├── core/
│   │   ├── validator.py        # input → validated address, helpful errors
│   │   ├── special_ranges.py   # IANA special-purpose tables + longest-prefix classify
│   │   ├── models.py           # ProviderResult, IPReport
│   │   ├── config.py           # .env + environment, API keys
│   │   └── orchestrator.py     # L1 first, then online providers concurrently
│   ├── providers/
│   │   ├── base.py             # Provider interface (skip rules: key, public IP, --active)
│   │   ├── offline.py          # L1 provider
│   │   └── __init__.py         # registry + planned providers (Phase 2–7)
│   ├── analysis/
│   │   ├── addressing.py       # representations, IPv4 class, multicast, Python flags
│   │   ├── ipv6_insights.py    # embedded IPv4, EUI-64/ISATAP, structure, multicast
│   │   ├── oui.py              # IEEE OUI vendor lookup
│   │   └── offline.py          # combines L1 + online-lookup decision
│   └── output/
│       ├── terminal.py         # rich panels (user input never parsed as markup)
│       └── json_out.py
├── scripts/capture_fixtures.py # Phase 0: record real API responses for tests
├── tests/                      # pytest; runs offline
├── data/                       # downloaded datasets (git-ignored)
├── .env.example                # every API key the roadmap uses
└── .github/workflows/ci.yml    # lint + tests on Python 3.10–3.14
```

---

## Tests

```bash
ruff check . && ruff format --check .
pytest -q
```

সব test offline চলে, কোনো API key লাগে না। CI প্রতিটি push-এ Python 3.10, 3.11, 3.12, 3.13 ও 3.14-এ চালায়।

---

## Phase 0: আসল API response সংরক্ষণ (আপনার নিজের computer-এ)

Phase 2+-এর provider বানানোর আগে প্রতিটি API আসলে কী ফেরত দেয়, তা `tests/fixtures/`-এ রেখে দিন:

```bash
cp .env.example .env              # যে key আছে শুধু সেগুলো বসান (কোনোটাই বাধ্যতামূলক নয়)
python scripts/capture_fixtures.py --list
python scripts/capture_fixtures.py                  # 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888
python scripts/capture_fixtures.py --only ip-api rdap 8.8.8.8
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
| 0 | Setup, `.env`, CI, fixture capture script | ✅ |
| 1 | Validator, L1 offline analysis, models, CLI | ✅ |
| 2 | ip-api, IPinfo Lite, MaxMind, Team Cymru, PeeringDB; cache, rate limiter | ⏳ |
| 3 | RDAP, RIPEstat (BGP/RPKI), DNS/FCrDNS, Geofeed | ⏳ |
| 4–10 | Anonymity, threat intel, scoring, active mode, reports, dashboard | ⏳ |

`ipfinder sources` চালালে প্রতিটি data source-এর phase ও API-key অবস্থা দেখা যায়।

---

## দায়িত্বশীল ব্যবহার

- Phase 1 পুরোপুরি passive ও offline। কোনো packet কোথাও পাঠায় না।
- Active probing (Phase 7) default-এ বন্ধ থাকবে এবং শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত system-এ চালানো যাবে।
- বাংলাদেশে সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ প্রযোজ্য; বিস্তারিত [ADVANCED_PLAN.md §9](ADVANCED_PLAN.md#9-security-ethics-ও-আইন)।
