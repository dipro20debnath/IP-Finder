# IP Finder — Advanced Plan (v2.0)

> **লক্ষ্য:** একটি public IP address দিলে বর্তমানে **আইনসঙ্গত ও প্রযুক্তিগতভাবে যা যা বের করা সম্ভব**, সব একটি tool-এ এনে প্রতিটি তথ্যের **উৎস, নির্ভরযোগ্যতা (confidence) ও সীমাবদ্ধতা** সহ দেখানো।
>
> Basic version (v1.0) শুধু `ip-api.com` থেকে location দেখায়। এই plan সেটিকে **১২ স্তরের (layer) একটি multi-source IP intelligence tool**-এ রূপান্তর করে।

Data source-গুলোর তথ্য (free/key, rate limit, 2025-এর পরিবর্তন) **অক্টোবর 2026**-এ যাচাই করা হয়েছে। তবে provider-রা যেকোনো সময় নিয়ম বদলাতে পারে, তাই Phase 0-তে প্রতিটি source আবার পরীক্ষা করতে হবে (§8)।

---

## সূচিপত্র

0. [এক নজরে](#0-এক-নজরে)
1. [বাস্তবতা যাচাই: IP থেকে কী জানা যায়, কী যায় না](#1-বাস্তবতা-যাচাই)
2. [Information Map: ১২টি layer](#2-information-map-১২টি-layer)
3. [Data Source Matrix (যাচাইকৃত)](#3-data-source-matrix)
4. [System Architecture](#4-system-architecture)
5. [Core Algorithms](#5-core-algorithms)
6. [CLI Design ও Output](#6-cli-design-ও-output)
7. [Roadmap (Phase-wise)](#7-roadmap)
8. [Testing Strategy](#8-testing-strategy)
9. [Security, Ethics ও আইন](#9-security-ethics-ও-আইন)
10. [Advanced Viva প্রশ্ন](#10-advanced-viva-প্রশ্ন)
11. [Sources](#11-sources)

---

## 0. এক নজরে

| স্তর | কী বের হবে | Network লাগে? | API key লাগে? |
|---|---|---|---|
| L1 Offline Analysis | Version, type (private/CGNAT/…), binary/hex/int, reverse pointer, IPv6-এর ভিতরে লুকানো IPv4/MAC | না | না |
| L2 Geolocation | Country → city, lat/lon, timezone, currency, accuracy radius | হ্যাঁ | কিছু provider-এ |
| L3 Network Owner | ISP, organization, ASN, AS name, AS domain | হ্যাঁ | না / ঐচ্ছিক |
| L4 Registration (RDAP) | Net range, CIDR, RIR, allocation date, registrant org, **abuse email** | হ্যাঁ | না |
| L5 BGP Routing | Announced prefix, origin AS, **RPKI valid/invalid**, upstream/peer AS | হ্যাঁ | না |
| L6 DNS | PTR hostname, forward-confirmed rDNS, hostname থেকে connection type অনুমান | হ্যাঁ | না |
| L7 Connection Type / Anonymity | Hosting/cloud (AWS/GCP/Azure/Cloudflare…), mobile, proxy, **Tor exit**, **iCloud Private Relay** | হ্যাঁ | না |
| L8 Exposed Services (passive) | খোলা port, CPE (software), known CVE, tags | হ্যাঁ | না (Shodan InternetDB) |
| L9 Threat Reputation | Abuse report score, scanner/benign classification, blocklist listing | হ্যাঁ | হ্যাঁ (free key) |
| L10 Active Probing ⚠️ | Ping RTT, traceroute, TLS certificate (domain নাম) | হ্যাঁ | না, **কিন্তু authorization লাগবে** |
| L11 Derived Intelligence | Location confidence score, risk score, anycast সনাক্তকরণ, local time, দূরত্ব | না | না |
| L12 Reporting | Terminal, JSON, CSV, HTML report (interactive map), batch mode | না | না |

---

## 1. বাস্তবতা যাচাই

### 1.1 যা নির্ভরযোগ্যভাবে জানা যায়

| তথ্য | নির্ভরযোগ্যতা | কেন |
|---|---|---|
| IP valid কি না, কোন type | **১০০%** | গাণিতিক/IANA registry ভিত্তিক |
| কোন ASN/network announce করছে | **খুব উচ্চ** | BGP routing table থেকে সরাসরি |
| কোন সংস্থার নামে registered, abuse contact | **খুব উচ্চ** | RIR (APNIC/ARIN/RIPE…) registry থেকে |
| Country | **সাধারণত উচ্চ** | তবে VPN/অনেক দেশে ছড়ানো network-এ ভুল হতে পারে |
| City | **মাঝারি থেকে নিম্ন** | Database অনুমান; mobile ও CGNAT-এ প্রায়ই ভুল |
| Lat/Lon | **নিম্ন** | প্রায়ই শহরের কেন্দ্রবিন্দু বা ISP gateway-এর অবস্থান |

### 1.2 যা জানা যায় না (এবং tool কখনো দাবি করবে না)

- ব্যক্তির নাম, ফোন নম্বর, বাড়ির ঠিকানা: এগুলো শুধু ISP-এর subscriber record-এ থাকে, যা আইনি প্রক্রিয়া ছাড়া পাওয়া যায় না।
- Live location, Street View-লেভেলের অবস্থান।
- VPN ব্যবহার করছে কি না, শতভাগ নিশ্চিতভাবে (শুধু সম্ভাবনা দেখানো যায়)।

### 1.3 বাস্তব কিছু সমস্যা, যা advanced tool-কে সামলাতে হবে

1. **Anycast IP:** `8.8.8.8` বা `1.1.1.1` একই সাথে বিশ্বের বহু data center থেকে serve হয়। এদের জন্য "একটি শহর" দেখানো অর্থহীন। Tool-কে এটা সনাক্ত করে জানাতে হবে (§5.7)। Basic notes-এ 8.8.8.8-এর জন্য "Mountain View" দেখানো হয়েছে, কিন্তু বিভিন্ন database একই IP-এর জন্য ভিন্ন শহর দেখায়। এটাই anycast-এর প্রভাব।
2. **CGNAT (Carrier-Grade NAT):** বাংলাদেশসহ অনেক দেশের mobile operator হাজারো গ্রাহককে একটি public IP-এর পেছনে রাখে। তাই location প্রায়ই operator-এর gateway শহর (যেমন ঢাকা) দেখায়, ব্যবহারকারী অন্য জেলায় থাকলেও।
3. **Provider-দের মধ্যে অমিল:** দুটি database একই IP-কে ঢাকা ও চট্টগ্রাম দেখাতে পারে (দূরত্ব ≈ 214 km)। Tool সব provider-এর উত্তর পাশাপাশি দেখাবে এবং অমিল (spread) মাপবে (§5.2)।
4. **IPv6 privacy:** আধুনিক OS-গুলো IPv6 privacy extension (random interface ID) ব্যবহার করে। পুরোনো/embedded device-গুলো EUI-64 ব্যবহার করে, যার ভিতর থেকে device-এর MAC address বের করা যায় (§5.1)।

---

## 2. Information Map: ১২টি layer

প্রতিটি layer একটি আলাদা **provider module** হিসেবে বানানো হবে (§4)।

### L1: Offline Analysis (`ipaddress` module, network লাগে না)

| Field | উদাহরণ (`8.8.8.8`) |
|---|---|
| Version | IPv4 |
| Classification | global / private / loopback / link-local / multicast / reserved / **CGNAT `100.64.0.0/10`** / documentation |
| Integer form | `134744072` |
| Hex / Binary | `0x08080808` / `00001000.00001000.00001000.00001000` |
| Reverse pointer | `8.8.8.8.in-addr.arpa` |
| IPv6 embedded IPv4 | `::ffff:8.8.8.8` → `8.8.8.8` (IPv4-mapped), `2002::/16` → 6to4 IPv4, `2001::/32` → Teredo server + client IPv4 |
| IPv6 EUI-64 → MAC | `…:021a:2bff:fe3c:4d5e` → MAC `00:1a:2b:3c:4d:5e` → IEEE OUI থেকে **device-এর নির্মাতা** |
| IPv6 structure | /48 (site) ও /64 (subnet) prefix আলাদা করে দেখানো |

> ⚠️ **Implementation-এর জরুরি বিষয় (Python 3.13-এ পরীক্ষিত):** Python `2002::/16` (6to4) ও `2001::/32` (Teredo)-কে `is_global == False` ধরে। তাই v1.0-এর মতো "not global হলে বাদ" নিয়ম রাখলে এসব address বাদ পড়ে যাবে। **আগে embedded IPv4 বের করতে হবে, তারপর classify করতে হবে।**
>
> **Phase 1-এ পাওয়া আরও তথ্য (Python 3.10–3.14-এ পরীক্ষিত):** Python-এর `is_global` কয়েকটি address-এ IANA registry-র সাথে মেলে না (যেমন `5f00::1` SRv6, `2001:1::3` RFC 9665, `4000::1` unallocated)। Python 3.12.3 `3fff::/20` (RFC 9637) চেনেই না। তাই implementation-এ IANA registry থেকে নিজস্ব table রাখা হয়েছে (`ipfinder/core/special_ranges.py`, বিস্তারিত README-তে)।

### L2: Geolocation (multi-provider consensus)

| Field | Provider |
|---|---|
| Continent, country, country code | ip-api, IPinfo Lite, MaxMind GeoLite2 |
| Region, city, district, ZIP | ip-api, MaxMind GeoLite2 City |
| Latitude/Longitude | ip-api, MaxMind |
| **Accuracy radius (km)** | MaxMind GeoLite2 (`location.accuracy_radius`) |
| Timezone, UTC offset | ip-api (`timezone`, `offset`) |
| Currency | ip-api (`currency`) |
| **Operator-declared location (Geofeed)** | RFC 8805 geofeed file; RDAP/WHOIS-এর `geofeed:` বা `remarks: Geofeed <url>` থেকে খুঁজে বের করা হয় (RFC 9632) |

**Geofeed** একটি advanced কিন্তু বাস্তব কৌশল। অনেক ISP নিজেরাই নিজেদের prefix কোন শহরে, তা একটি CSV file-এ publish করে। এটা commercial database-এর চেয়ে বেশি নির্ভরযোগ্য হতে পারে।

### L3: Network Owner

| Field | Source |
|---|---|
| ISP, Organization | ip-api (`isp`, `org`) |
| ASN, AS name | ip-api (`as`, `asname`), IPinfo Lite (`asn`, `as_name`, `as_domain`) |
| ASN cross-check (DNS-based) | Team Cymru: `dig +short TXT 8.8.8.8.origin.asn.cymru.com` → `ASN \| prefix \| CC \| RIR \| date` |
| Network type | PeeringDB: `https://www.peeringdb.com/api/net?asn=15169` → info type (NSP / Content / Cable/DSL/ISP / Enterprise / Educational…) |

### L4: Registration (RDAP, WHOIS-এর আধুনিক JSON রূপ)

| Field | উদাহরণ |
|---|---|
| Network range / CIDR | `8.8.8.0 - 8.8.8.255` |
| Network name / handle | `GOGL` |
| RIR | ARIN / APNIC (বাংলাদেশ) / RIPE / LACNIC / AFRINIC |
| Registration ও last-changed date | RDAP `events` |
| Registrant organization | RDAP `entities` |
| **Abuse contact email** | RDAP `entities[roles=abuse]`; RIPEstat `abuse-contact-finder` |
| Allocation type | ALLOCATED PA / ASSIGNED PI ইত্যাদি |

Implementation: `ipwhois` library (`IPWhois(ip).lookup_rdap()`) অথবা `https://rdap.org/ip/<ip>` (সঠিক RIR-এ redirect করে)।

### L5: BGP Routing (RIPEstat Data API, free, key লাগে না)

| Field | RIPEstat endpoint (`https://stat.ripe.net/data/<name>/data.json?resource=<ip>&sourceapp=ip-finder`) |
|---|---|
| Announced prefix + origin AS | `prefix-overview` |
| **RPKI status** (valid / invalid / unknown) | `rpki-validation` (`resource=<ASN>&prefix=<prefix>`) |
| Routing visibility, প্রথম/শেষ দেখা | `routing-status` |
| Upstream/peer AS | `asn-neighbours` |
| Abuse contact | `abuse-contact-finder` |

RPKI **invalid** মানে prefix-টি ভুল AS থেকে announce হচ্ছে। এটা BGP hijack বা misconfiguration-এর লক্ষণ হতে পারে, তাই security analysis-এ এটা গুরুত্বপূর্ণ।

### L6: DNS

| Field | পদ্ধতি |
|---|---|
| PTR (reverse DNS) | `dnspython`: `dns.reversename.from_address(ip)` → PTR query |
| **FCrDNS** (forward-confirmed) | PTR hostname → A/AAAA lookup → মূল IP ফিরে আসে কি না। মিললে hostname বিশ্বাসযোগ্য |
| Hostname heuristics | `dynamic`, `dhcp`, `pool`, `dsl`, `ppp`, `cable` → residential; `static` → business; `aws`, `googleusercontent`, `vultr` → hosting |
| একই IP-তে hosted domains (reverse IP) | API key লাগে (SecurityTrails, VirusTotal relations); ঐচ্ছিক |

### L7: Connection Type ও Anonymity Detection

| সনাক্তকরণ | Source | পদ্ধতি |
|---|---|---|
| Hosting/Datacenter | ip-api `hosting` field | Boolean flag |
| **কোন Cloud** (AWS region/service সহ) | AWS `ip-ranges.json`, GCP `cloud.json`, Azure Service Tags, Cloudflare `ips-v4`/`ips-v6`, Oracle, DigitalOcean-এর publish করা range | Local CIDR matching (দিনে একবার download) |
| Mobile (cellular) | ip-api `mobile` field | Boolean flag |
| Proxy/VPN/Tor | ip-api `proxy` field | Boolean flag (সম্ভাবনা, নিশ্চয়তা নয়) |
| **Tor exit node** | Tor Project: `https://check.torproject.org/torbulkexitlist` | Exact IP match; খুব নির্ভরযোগ্য |
| **iCloud Private Relay** | Apple: `https://mask-api.icloud.com/egress-ip-ranges.csv` | CIDR match। এটা VPN নয়, তাই আলাদা label দিতে হবে |
| Known VPN provider | ASN/org নাম matching (যেমন M247, Datacamp, Packethub…) | Heuristic list |

### L8: Exposed Services (Passive)

**Shodan InternetDB**: `https://internetdb.shodan.io/<ip>`: free, key লাগে না, non-commercial।

| Field | অর্থ |
|---|---|
| `ports` | Internet scan-এ দেখা খোলা port |
| `hostnames` | rDNS ও certificate থেকে পাওয়া hostname |
| `cpes` | চলমান software (CPE format) |
| `vulns` | CVE তালিকা (**verified ও unverified দুটোই**, তাই "সম্ভাব্য" বলতে হবে) |
| `tags` | যেমন `cloud`, `vpn`, `self-signed`, `honeypot` |

Database সাপ্তাহিক update হয়, তাই এটা "সাম্প্রতিক scan-এর snapshot", live অবস্থা নয়।

### L9: Threat Reputation

| Source | কী দেয় | Access |
|---|---|---|
| **AbuseIPDB** | Abuse confidence score (0–100), report সংখ্যা, category, usage type | Free key, দিনে ~1,000 check |
| **GreyNoise Community** | `noise` (internet scanner কি না), `riot` (পরিচিত benign service), `classification` (benign/malicious/unknown) | Free; অফিসিয়াল docs অনুযায়ী free account-এ সপ্তাহে ~50 lookup; শুধু IPv4 |
| **VirusTotal** | কতগুলো security vendor IP-কে malicious বলছে | Free key: 4 req/min, 500/day, non-commercial |
| **AlienVault OTX** | Threat "pulse"-এ উল্লেখ আছে কি না | Free key |
| **abuse.ch** (ThreatFox, URLhaus, Feodo Tracker) | Malware C2 / botnet IOC | **30 June 2025 থেকে free `Auth-Key` বাধ্যতামূলক** |
| **Spamhaus ZEN** (DNSBL) | Spam/exploit source listing | নিজের resolver বা free **DQS key** লাগবে। 8.8.8.8/1.1.1.1-এর মতো public resolver দিয়ে query করলে `127.255.255.254` (blocked) আসে, যাকে listing ভাবা যাবে না |
| **Feodo Tracker / Spamhaus DROP** | Botnet C2 ও অপরাধীদের netblock/ASN list | Free download, local match (`update-lists`); কাউকে address পাঠায় না, তাই `standard` profile-এও চলে |

### L10: Active Probing ⚠️ (default OFF)

| কাজ | কী জানা যায় | ঝুঁকি |
|---|---|---|
| Ping (ICMP RTT) | Latency; **speed-of-light check** দিয়ে geolocation যাচাই (§5.6) | কম |
| Traceroute | পথের router, কোন দেশ/ISP দিয়ে যায় | কম |
| TLS certificate grab (port 443) | Certificate-এর **SAN-এ থাকা domain নাম**, issuer, মেয়াদ | কম, কিন্তু target-এর সাথে সরাসরি সংযোগ |
| Port scan (nmap) | Live service | **শুধু নিজের/লিখিত অনুমতিপ্রাপ্ত system-এ** |

Active mode চালু করতে `--active` flag এবং একটি স্পষ্ট confirmation prompt লাগবে (§9)।

**বাস্তবায়নে যোগ হয়েছে (Phase 7):** RTT মাপা হয় TCP handshake দিয়েও, কারণ এতে privilege লাগে না আর সব OS-এ চলে। Transparent proxy ধরার জন্য প্রথমে `192.0.2.1`-এ (RFC 5737, কখনো route হয় না) canary handshake করা হয়: কেউ উত্তর দিলে TCP সময় আর TLS certificate target-এর নয় বলে ধরা হয়। এক run-এ সর্বোচ্চ ২০টা address, শুধু public address, আর port scan ইচ্ছা করে রাখা হয়নি।

### L11: Derived Intelligence

- **Location Confidence Score** (0–100) এবং label: High/Medium/Low (§5.4)
- **Reputation Risk Score** (0–100), যা **Exposure Score** থেকে আলাদা (§5.5)
- **Connection type verdict:** Residential / Mobile / Business / Hosting / Anonymizer / Anycast (§5.3)
- IP-এর timezone-এ **বর্তমান local time**
- ব্যবহারকারীর নিজের অবস্থান থেকে **দূরত্ব** (haversine)
- Google Maps / OpenStreetMap link + **accuracy radius-এর বৃত্ত**

### L12: Reporting

- Terminal (রঙিন table, `rich`)
- JSON (machine-readable, সব raw data সহ)
- CSV (batch-এর জন্য)
- **HTML report**: Leaflet map, প্রতিটি provider-এর marker, accuracy circle (বাস্তবায়নে `folium`-এর বদলে Leaflet ও Natural Earth file-এর ভেতরেই রাখা হয়েছে; কারণ নিচে Phase 8-এ)
- Batch mode: file থেকে হাজারো IP (ip-api batch endpoint: এক request-এ সর্বোচ্চ 100 IP)

---

## 3. Data Source Matrix

| Source | Endpoint | Key | Free limit | License | অবস্থা |
|---|---|---|---|---|---|
| ip-api.com | `http://ip-api.com/json/{ip}` | না | 45 req/min (single), batch 15 req/min × 100 IP | Non-commercial; free-তে HTTPS নেই | ✅ |
| IPinfo Lite | `https://api.ipinfo.io/lite/{ip}?token=…` | Free token | Unlimited (শুধু country + ASN) | Commercial use with attribution | ✅ (May 2025 থেকে) |
| MaxMind GeoLite2 | Local `.mmdb` file (`geoip2` library) | Free account + license key | Offline, unlimited | GeoLite2 EULA | ✅ |
| RDAP | IANA bootstrap (`data.iana.org/rdap/ipv4.json`) → RIR server; fallback `https://rdap.org/ip/{ip}` | না | LACNIC: 10/min ও 1,000/ঘণ্টা; বাকি RIR সংখ্যা প্রকাশ করে না | Public registry data | ✅ |
| RIPEstat | `https://stat.ripe.net/data/…` | না (`sourceapp` param দিন) | একটি IP থেকে একসাথে সর্বোচ্চ ৮টি request | Free | ✅ |
| Team Cymru | DNS: `origin.asn.cymru.com` | না | Fair use | Free | ✅ |
| PeeringDB | `https://www.peeringdb.com/api/net?asn=…` | না (key দিলে limit বাড়ে) | Anonymous-এ কম | Free | ✅ |
| Shodan InternetDB | `https://internetdb.shodan.io/{ip}` | না | উচ্চ | Non-commercial | ✅ |
| GreyNoise Community | `https://api.greynoise.io/v3/community/{ip}` | ঐচ্ছিক | ~50/week (free) | Free tier | ✅ |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/check` | Free key | ~1,000/day | Free tier | ✅ |
| VirusTotal | `https://www.virustotal.com/api/v3/ip_addresses/{ip}` | Free key | 4/min, 500/day | Non-commercial | ✅ |
| abuse.ch | ThreatFox/URLhaus API | **Free Auth-Key (2025 থেকে বাধ্যতামূলক)** | Fair use | Free | ✅ |
| Spamhaus | DNSBL / DQS | DQS key বা নিজের resolver | Fair use | Free (non-commercial) | ✅ |
| Tor exit list | `https://check.torproject.org/torbulkexitlist` | না | ঘণ্টায় একবার download | Free | ✅ |
| iCloud Private Relay | `https://mask-api.icloud.com/egress-ip-ranges.csv` | না | দিনে একবার download | Free | ✅ |
| Cloud ranges | AWS/GCP/Azure/Cloudflare JSON/TXT | না | দিনে একবার download | Free | ✅ |

> **Rate-limit handling:** ip-api response header-এ `X-Rl` (বাকি request) ও `X-Ttl` (reset হতে কত সেকেন্ড) পাঠায়। Tool এগুলো পড়ে নিজে থেকে অপেক্ষা করবে। HTTP 429 এলে exponential backoff ব্যবহার করবে।

---

## 4. System Architecture

### 4.1 Pipeline

```text
                ┌─────────────┐
 IP input ────► │  Validator  │──► invalid → error
                └──────┬──────┘
                       ▼
                ┌─────────────┐
                │ L1 Offline  │──► private/CGNAT/loopback → local report only
                └──────┬──────┘    (6to4/Teredo/mapped → embedded IPv4 দিয়ে আবার শুরু)
                       ▼
            ┌───────────────────────┐
            │ Orchestrator (asyncio) │◄── Cache (SQLite, TTL)
            │  + Rate limiter        │◄── Config (.env API keys, profile)
            └──────────┬────────────┘
     ┌────────┬────────┼────────┬─────────┬──────────┐
     ▼        ▼        ▼        ▼         ▼          ▼
   L2 Geo  L3 ASN   L4 RDAP  L5 BGP   L6 DNS ...  L9 Threat   (সমান্তরালভাবে)
     └────────┴────────┴────┬───┴─────────┴──────────┘
                            ▼
                ┌──────────────────────┐
                │ L11 Analysis Engine  │ consensus, classify, scores, anycast
                └──────────┬───────────┘
                           ▼
                ┌──────────────────────┐
                │ L12 Output           │ terminal / JSON / CSV / HTML map
                └──────────────────────┘
```

একটি provider fail করলে বাকিরা চলতে থাকবে। Report-এ সেই provider "unavailable" দেখাবে।

### 4.2 Folder Structure

```text
IP-Finder/
├── ipfinder/
│   ├── __init__.py
│   ├── __main__.py            # python -m ipfinder
│   ├── cli.py                 # argparse CLI
│   ├── core/
│   │   ├── models.py          # IPReport, ProviderResult dataclasses
│   │   ├── validator.py
│   │   ├── orchestrator.py    # async fan-out
│   │   ├── cache.py           # SQLite TTL cache
│   │   ├── ratelimit.py       # token bucket per provider
│   │   └── config.py          # .env + profiles
│   ├── providers/
│   │   ├── base.py            # Provider interface
│   │   ├── offline.py         # L1
│   │   ├── ipapi.py           # L2/L3/L7
│   │   ├── ipinfo_lite.py     # L2/L3
│   │   ├── maxmind.py         # L2 (offline mmdb)
│   │   ├── geofeed.py         # L2 (RFC 8805/9632)
│   │   ├── cymru.py           # L3
│   │   ├── peeringdb.py       # L3
│   │   ├── rdap.py            # L4
│   │   ├── ripestat.py        # L5
│   │   ├── dns_lookup.py      # L6
│   │   ├── cloud_ranges.py    # L7
│   │   ├── tor.py             # L7
│   │   ├── private_relay.py   # L7
│   │   ├── internetdb.py      # L8
│   │   ├── greynoise.py       # L9
│   │   ├── abuseipdb.py       # L9
│   │   ├── virustotal.py      # L9
│   │   └── spamhaus.py        # L9
│   ├── active/                # L10 (opt-in)
│   │   ├── ping.py
│   │   ├── traceroute.py
│   │   └── tls_cert.py
│   ├── analysis/              # L11
│   │   ├── consensus.py
│   │   ├── classify.py
│   │   ├── scoring.py
│   │   ├── anycast.py
│   │   └── ipv6_insights.py
│   └── output/                # L12
│       ├── terminal.py
│       ├── json_out.py
│       ├── csv_out.py
│       └── html_report.py
├── data/                      # downloaded lists, mmdb, cache (gitignored)
├── tests/
│   ├── fixtures/              # recorded API responses
│   └── test_*.py
├── .env.example
├── pyproject.toml
├── requirements.txt
└── README.md
```

### 4.3 Provider Interface ও Data Model

```python
# ipfinder/core/models.py
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ProviderResult:
    provider: str            # "ip-api", "rdap", ...
    layer: str               # "L2", "L4", ...
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cached: bool = False
    elapsed_ms: float = 0.0

@dataclass
class IPReport:
    ip: str
    version: int
    classification: str
    results: list[ProviderResult] = field(default_factory=list)
    verdict: dict[str, Any] = field(default_factory=dict)  # scores, type, consensus
```

```python
# ipfinder/providers/base.py
from abc import ABC, abstractmethod
import httpx
from ipfinder.core.models import ProviderResult

class Provider(ABC):
    name: str
    layer: str
    requires_key: bool = False
    active: bool = False        # True হলে শুধু --active mode-এ চলবে
    cache_ttl: int = 86400      # seconds

    def enabled(self, config) -> bool:
        if self.active and not config.active_mode:
            return False
        return not self.requires_key or bool(config.key_for(self.name))

    @abstractmethod
    async def lookup(self, ip: str, client: httpx.AsyncClient, config) -> ProviderResult:
        ...
```

### 4.4 Libraries

| Library | কাজ |
|---|---|
| `httpx` | Async HTTP (একসাথে অনেক provider-এ request) |
| `ipaddress` (built-in) | Validation, classification, CIDR matching |
| `dnspython` | PTR, FCrDNS, Team Cymru, Spamhaus DNS query |
| `ipwhois` | RDAP parsing |
| `geoip2` | MaxMind GeoLite2 `.mmdb` পড়া |
| `rich` | সুন্দর terminal table |
| `argparse` (built-in) | CLI (extra dependency ছাড়া) |
| নিজস্ব `.env` parser (`core/config.py`) | API key `.env` থেকে পড়া (extra dependency ছাড়া) |
| ~~`folium`~~ → embedded Leaflet 1.9.4 + Natural Earth | HTML map (offline; folium CDN থেকে script নামায়) |
| `pytest`, `respx` | Test ও HTTP mocking |

### 4.5 Cache ও Privacy

- SQLite cache: key = `(provider, ip)`, value = JSON, সাথে `expires_at`।
- TTL: geolocation 24h, threat intel 6h, Tor list 1h, cloud ranges 24h।
- `--no-cache` flag; `ipfinder cache clear` command।
- Cache file `.gitignore`-এ থাকবে। কোনো lookup history repo-তে push হবে না।

---

## 5. Core Algorithms

### 5.1 Offline Analysis (Python 3.13-এ পরীক্ষিত)

> **Phase 1 আপডেট:** নিচের `classify()` প্রাথমিক নকশা, যা Python-এর `is_*` flag-এর উপর নির্ভর করে। বাস্তবায়নে এটা বদলে IANA registry-ভিত্তিক `ipfinder/core/special_ranges.classify()` করা হয়েছে, কারণ Python-এর flag কয়েকটি address-এ IANA-র সাথে মেলে না (যেমন `2001:1::3`, `5f00::1`; বিস্তারিত README-তে)। `embedded_ipv4()` ও `eui64_mac()`-এর ধারণা এখনও প্রযোজ্য; আসল code-এ group-bit ও IANA-reserved ID যাচাইও যোগ হয়েছে।

```python
import ipaddress

CGNAT = ipaddress.ip_network("100.64.0.0/10")

def classify(ip):
    if ip.version == 4 and ip in CGNAT:
        return "CGNAT (RFC 6598)"
    for name in ("is_loopback", "is_link_local", "is_multicast",
                 "is_unspecified", "is_reserved", "is_private"):
        if getattr(ip, name):
            return name[3:]
    return "global" if ip.is_global else "special"

def embedded_ipv4(ip):
    """IPv6-এর ভিতরে লুকানো IPv4 বের করে (classify করার আগে চালাতে হবে)।"""
    if ip.version != 6:
        return {}
    out = {}
    if ip.ipv4_mapped:
        out["ipv4_mapped"] = ip.ipv4_mapped
    if ip.sixtofour:
        out["6to4"] = ip.sixtofour
    if ip.teredo:
        out["teredo_server"], out["teredo_client"] = ip.teredo
    return out

def eui64_mac(ip):
    """SLAAC EUI-64 IPv6 address থেকে MAC address বের করে।"""
    if ip.version != 6:
        return None
    iid = ip.packed[8:]
    if iid[3:5] != b"\xff\xfe":
        return None
    mac = bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:8]   # U/L bit flip
    return ":".join(f"{b:02x}" for b in mac)
```

পরীক্ষার ফলাফল:

| Input | ফলাফল |
|---|---|
| `100.64.1.1` | `CGNAT (RFC 6598)` |
| `fe80::21a:2bff:fe3c:4d5e` | MAC `00:1a:2b:3c:4d:5e` |
| `::ffff:8.8.8.8` | IPv4-mapped → `8.8.8.8` |
| `2001:0:4136:e378:8000:63bf:3fff:fdd2` | Teredo server `65.54.227.120`, client `192.0.2.45` |

MAC-এর প্রথম 3 byte (OUI) IEEE-র public list (`https://standards-oui.ieee.org/oui/oui.csv`)-এর সাথে মিলিয়ে নির্মাতার নাম (যেমন Cisco, TP-Link) পাওয়া যায়।

### 5.2 Geolocation Consensus

```python
from math import radians, sin, cos, asin, sqrt
from statistics import median

def haversine_km(lat1, lon1, lat2, lon2):
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    return 2 * 6371 * asin(sqrt(a))

def consensus(points):
    """points: [(provider, lat, lon), ...] → (median_lat, median_lon, spread_km)"""
    lat = median(p[1] for p in points)
    lon = median(p[2] for p in points)
    spread = max(haversine_km(lat, lon, p[1], p[2]) for p in points)
    return lat, lon, round(spread, 1)
```

- Country: **majority vote**। Geofeed থাকলে সেটির weight বেশি।
- City: যে শহর বেশি provider বলছে। সমান হলে MaxMind-এর accuracy radius ছোট হলে সেটা।
- `spread_km` report-এ দেখানো হবে। উদাহরণ: ঢাকা বনাম চট্টগ্রাম ≈ 214 km।

### 5.3 Connection Type Classification (Decision Tree)

```text
Tor exit list-এ আছে?              → "Anonymizer: Tor"
iCloud Private Relay range-এ?      → "Privacy Relay (Apple)"  (VPN নয়)
Anycast সনাক্ত?                    → "Anycast service"
Cloud range বা hosting=true?       → "Hosting/Cloud: <provider/region>"
  + proxy=true বা VPN ASN?          → "Likely VPN/Proxy on hosting"
mobile=true?                       → "Mobile (cellular, likely CGNAT)"
PTR-এ dynamic/pool/dsl/ppp?        → "Residential broadband"
PeeringDB = Educational/Research?   → "Education/Research"
PeeringDB = Enterprise?            → "Business"
অন্যথায়                            → "Unknown / ISP"
```

### 5.4 Location Confidence Score (heuristic, পরীক্ষিত)

```python
def location_confidence(spread_km, hosting, anonymizer, mobile,
                        anycast, rtt_violation, geofeed_match):
    score = 100
    if spread_km > 500:   score -= 40
    elif spread_km > 100: score -= 25
    if hosting:       score -= 30   # data center-এর অবস্থান, user-এর নয়
    if anonymizer:    score -= 50   # আসল user অজানা
    if mobile:        score -= 20   # CGNAT gateway
    if anycast:       score -= 60   # একাধিক অবস্থান
    if rtt_violation: score -= 30   # পদার্থবিজ্ঞানের সাথে অসঙ্গত
    if geofeed_match: score += 10   # operator নিজে নিশ্চিত করেছে
    return max(0, min(100, score))
```

Label: **≥70 High**, **40–69 Medium**, **<40 Low**।
উদাহরণ: বাংলাদেশি mobile IP, provider-দের মধ্যে 214 km অমিল → 100 − 25 − 20 = **55 (Medium)**।

### 5.5 Risk Score: দুটি আলাদা জিনিস

একটি IP "খারাপ কাজ করছে" (reputation) আর "দুর্বল/উন্মুক্ত" (exposure) সম্পূর্ণ আলাদা বিষয়। তাই দুটি score:

**Reputation Score (0–100):**

| Signal | Points |
|---|---|
| AbuseIPDB confidence | × 0.4 (সর্বোচ্চ 40) |
| GreyNoise `classification = malicious` | +25 |
| VirusTotal malicious vendor count | প্রতি vendor +5 (সর্বোচ্চ 25) |
| Spamhaus/abuse.ch/FireHOL listing | +20 |
| Tor exit | +10 (Tor নিজে অপরাধ নয়, শুধু ঝুঁকির সংকেত) |
| GreyNoise `riot = true` (পরিচিত benign service) | −30 |

**Exposure Score (0–100):** খোলা port-এর সংখ্যা, risky port (23 Telnet, 445 SMB, 3389 RDP, 5900 VNC, 6379 Redis, 9200 Elasticsearch), CVE সংখ্যা (InternetDB)।

### 5.5.1 বাস্তবায়নে যা যোগ বা বদল হয়েছে (Phase 6)

কাজ করতে গিয়ে plan-এর heuristic-এ কয়েকটা জিনিস স্পষ্ট করতে হয়েছে। প্রতিটার কারণ নিচে:

- **Spread** = যেকোনো দুটো source-এর মধ্যে সর্বোচ্চ দূরত্ব (median বিন্দু থেকে নয়)। Plan-এর নিজের উদাহরণে ঢাকা থেকে চট্টগ্রাম 214 km-কে spread ধরা হয়েছে; median থেকে মাপলে সেটা 107 km হতো।
- **MaxMind-এর accuracy radius** spread-এর চেয়ে বড় হলে সেটাই uncertainty। একটা database-ও নিজে অনেক ভুল হতে পারে।
- **নতুন নিয়ম:** একটাই coordinate source → −10; কোনো coordinate নেই → −20; source-রা দেশ নিয়ে একমত নয় → −20।
- **Private Relay**-কে anonymizer (−50) না ধরে −20। কারণ Apple ইচ্ছা করে user-এর মোটামুটি এলাকা রাখে।
- **Reputation label:** 0 = কিছু পাওয়া যায়নি, 1–29 Low, 30–59 Medium, 60+ High। Spamhaus PBL listing point পায় না, কারণ এটা policy, abuse নয়। কোনো source না চললে score দেখানো হয় না।
- **Exposure:** প্রতি খোলা port +2 (সর্বোচ্চ 20), প্রতি প্রায়ই-আক্রান্ত service +15 (সর্বোচ্চ 45), প্রতি সম্ভাব্য CVE +5 (সর্বোচ্চ 35)।
- **Classification:** "Possible VPN or proxy" (hosting ছাড়া) আর AbuseIPDB-এর usage type নতুন signal। হেরে যাওয়া signal-ও "other signals" হিসেবে দেখানো হয়।

### 5.6 RTT Plausibility (Speed-of-Light Check)

Fiber-এ আলো প্রতি millisecond-এ প্রায় **200 km** যায়। তাই:

```text
সর্বোচ্চ সম্ভাব্য দূরত্ব (km) ≈ RTT (ms) / 2 × 200 = RTT × 100
```

যদি আপনার অবস্থান থেকে IP-এর **RTT = 5 ms** হয়, IP **500 km-এর বেশি দূরে থাকতে পারে না**। Database যদি সেটাকে অন্য মহাদেশে দেখায়, তাহলে geolocation **ভুল** অথবা IP-টা **anycast**। এটা একটি বাস্তব, পদার্থবিজ্ঞান-ভিত্তিক যাচাই (active mode লাগবে)।

### 5.7 Anycast Detection

- পরিচিত anycast prefix list (Google Public DNS, Cloudflare `1.1.1.0/24`, Quad9 ইত্যাদি)
- RTT অস্বাভাবিক কম, কিন্তু geolocation অনেক দূরে (§5.6)
- InternetDB/GreyNoise RIOT tag (DNS resolver, CDN)
- (Advanced, ঐচ্ছিক) **RIPE Atlas**: বিশ্বের বিভিন্ন জায়গার probe থেকে ping। সব জায়গা থেকে কম RTT মানেই anycast। এর জন্য RIPE Atlas account ও credit লাগে।

---

## 6. CLI Design ও Output

### 6.1 Commands

```bash
python -m ipfinder lookup 8.8.8.8                    # standard profile
python -m ipfinder lookup 8.8.8.8 --profile quick     # শুধু L1–L3 (দ্রুত, key ছাড়া)
python -m ipfinder lookup 8.8.8.8 --profile full      # L1–L9 + L11
python -m ipfinder lookup 203.0.113.5 --active        # L10 (confirmation চাইবে)
python -m ipfinder lookup 8.8.8.8 -f json -o out.json
python -m ipfinder lookup 8.8.8.8 -f html -o report.html
python -m ipfinder batch ips.txt -f csv -o results.csv
python -m ipfinder me                                 # নিজের public IP
python -m ipfinder sources                            # কোন provider চালু/বন্ধ, key আছে কি না
python -m ipfinder update-lists                       # Tor, cloud ranges, Private Relay, MaxMind
```

### 6.2 Profiles

| Profile | Layers | Key লাগে? | সময় (আনুমানিক) |
|---|---|---|---|
| `quick` | L1, L2 (ip-api), L3 | না | ~1 s |
| `standard` | L1–L8, L11 | না | ~2–4 s |
| `full` | L1–L9, L11 | ঐচ্ছিক (যত key, তত বেশি data) | ~3–6 s |
| `--active` | + L10 | না, কিন্তু authorization লাগবে | +5–30 s (traceroute) |

### 6.3 নমুনা Output (illustrative; বাস্তব মান ভিন্ন হতে পারে)

```text
╭──────────────────── IP FINDER v2.0 — 8.8.8.8 ────────────────────╮
│ Type        : IPv4 · global · anycast (Google Public DNS)         │
│ Verdict     : Anycast service · Hosting/Cloud (Google)            │
│ Location    : United States (country only — anycast)              │
│ Confidence  : 10/100  LOW  — served from many locations           │
╰───────────────────────────────────────────────────────────────────╯
 NETWORK      ASN AS15169 · Google LLC · google.com
              Prefix 8.8.8.0/24 · RIR ARIN · RPKI: valid
 DNS          PTR dns.google  (forward-confirmed ✔)
 GEO (raw)    ip-api   : <city>, <region>, US
              MaxMind  : <city>, US  (±<radius> km)
              IPinfo   : US
              Spread   : <n> km
 EXPOSURE     Ports 53, 443 · CVEs 0
 REPUTATION   GreyNoise: RIOT benign (Google Public DNS)
              AbuseIPDB: <score>/100 · VirusTotal: <n> vendors malicious
 ABUSE        network-abuse@google.com
 MAP          https://www.openstreetmap.org/?mlat=..&mlon=..

[!] Location is approximate. An IP is not a person.
```

---

## 7. Roadmap

| Phase | সময় | কাজ | Definition of Done |
|---|---|---|---|
| **0. Setup ও source যাচাই** 🟡 (script প্রস্তুত, fixture রেকর্ড বাকি) | ১–২ দিন | Repo structure, `pyproject.toml`, venv, `.env.example`; প্রতিটি API একবার হাতে চালিয়ে response `tests/fixtures/`-এ সংরক্ষণ | সব source-এর fixture আছে; key-গুলো `.env`-এ, git-এ নয় |
| **1. Core + Offline** ✅ | ৩–৪ দিন | Validator, L1 (classify, CGNAT, embedded IPv4, EUI-64), models, CLI skeleton | Private/CGNAT/IPv6 test সব pass |
| **2. Geo + Network** ✅ (code ও test; আসল API-তে প্রথম চালানো বাকি) | ১ সপ্তাহ | ip-api (single+batch), IPinfo Lite, MaxMind, Team Cymru, PeeringDB; rate limiter; cache | `quick` profile কাজ করে; 45/min limit কখনো ভাঙে না |
| **3. Registry + Routing + DNS** ✅ (code ও test; আসল API-তে প্রথম চালানো বাকি) | ১ সপ্তাহ | RDAP, RIPEstat (prefix, RPKI, neighbours, abuse), PTR + FCrDNS, Geofeed | Abuse email ও RPKI status দেখায় |
| **4. Anonymity + Exposure** ✅ (code ও test; AWS ও X4BNet list live দিয়ে যাচাই) | ১ সপ্তাহ | Cloud ranges, Tor, Private Relay, VPN-ASN list, InternetDB; `update-lists` | Tor exit IP সঠিকভাবে চিহ্নিত হয় |
| **5. Threat Intel** ✅ (code ও test; আসল API-তে প্রথম চালানো বাকি) | ১ সপ্তাহ | AbuseIPDB, GreyNoise, VirusTotal, OTX, abuse.ch, Spamhaus DQS | Key না থাকলে provider "skipped (no key)" দেখায়, crash করে না |
| **6. Analysis Engine** ✅ (প্রতিটা score-এর unit test আছে; §5.5.1-এ বাস্তবায়নের পার্থক্য) | ১ সপ্তাহ | Consensus, classification, confidence, reputation/exposure score, anycast | Score-গুলোর unit test আছে |
| **7. Active Mode** ✅ (`--active` ছাড়া কখনো চলে না; test-এ যাচাই করা) | ৩–৪ দিন | Ping, traceroute, TLS cert, RTT plausibility; confirmation prompt | `--active` ছাড়া কখনো চলে না |
| **8. Reporting** ✅ (Chromium-এ disk থেকে খুলে map আঁকা ও শূন্য network request যাচাই করা) | ১ সপ্তাহ | Rich terminal, JSON, CSV, HTML + folium map, batch progress bar | HTML report browser-এ map সহ খোলে |
| **9. (ঐচ্ছিক) Web Dashboard** | ১–২ সপ্তাহ | FastAPI backend + Leaflet frontend; একই `ipfinder` package reuse | Browser থেকে lookup |
| **10. Docs + Presentation** | ৩ দিন | README, architecture diagram, report, viva প্রস্তুতি | Demo script প্রস্তুত |

**মোট: ~৮–১০ সপ্তাহ** (একজন student part-time কাজ করলে)। Phase 1–3 শেষ হলেই v1.0-এর চেয়ে অনেক শক্তিশালী একটি demo দেওয়া যাবে।

---

## 8. Testing Strategy

### 8.1 Test IP Matrix

| IP | উদ্দেশ্য | প্রত্যাশিত আচরণ |
|---|---|---|
| `8.8.8.8` | Anycast, IPv4 | Anycast flag, low confidence |
| `1.1.1.1` | Anycast, Cloudflare | Cloudflare range match |
| `2001:4860:4860::8888` | IPv6 global | Lookup চলে |
| `192.168.1.10` | Private | Network call হয় না |
| `100.64.1.1` | CGNAT | "CGNAT" দেখায়, lookup হয় না |
| `127.0.0.1`, `::1` | Loopback | Lookup হয় না |
| `169.254.1.1` | Link-local | Lookup হয় না |
| `192.0.2.1`, `2001:db8::1` | Documentation (RFC 5737/3849) | Lookup হয় না |
| `::ffff:8.8.8.8` | IPv4-mapped | `8.8.8.8`-এ রূপান্তর |
| `fe80::21a:2bff:fe3c:4d5e` | EUI-64 | MAC `00:1a:2b:3c:4d:5e` |
| `999.1.1.1`, `abc`, `""` | Invalid | পরিষ্কার error, crash নয় |
| Tor list থেকে runtime-এ একটি IP | Tor detection | "Anonymizer: Tor" |
| AWS `ip-ranges.json` থেকে একটি IP | Cloud detection | "AWS <region>" |

### 8.2 পদ্ধতি

- **Unit tests:** প্রতিটি provider-এর parser recorded fixture দিয়ে পরীক্ষা (network ছাড়া)। `respx` দিয়ে HTTP mock।
- **Failure tests:** timeout, 429, 5xx, invalid JSON, key ছাড়া চালানো। Tool কখনো crash করবে না।
- **Rate-limit test:** 100টি IP-এর batch ip-api-তে ঠিক 1টি request-এ যায় কি না।
- **Live smoke test** (ঐচ্ছিক, `pytest -m live`): সপ্তাহে একবার আসল API-তে, schema বদলেছে কি না ধরতে।
- **CI:** GitHub Actions: `ruff` (lint) + `pytest` (live test বাদে)।

---

## 9. Security, Ethics ও আইন

### 9.1 Passive বনাম Active

| Mode | কী করে | Target জানতে পারে? | অনুমতি লাগবে? |
|---|---|---|---|
| Passive (L1–L9) | তৃতীয় পক্ষের database/API query করে | না | সাধারণত না (তবে API ToS মানতে হবে) |
| Active (L10) | Target-এ সরাসরি packet পাঠায় | হ্যাঁ | Ping/traceroute সাধারণত গ্রহণযোগ্য; **port scan শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত system-এ** |

`--active` চালালে tool এই prompt দেখাবে:

```text
[!] Active mode sends packets directly to the target.
    Only scan systems you own or have written permission to test.
    Type 'I AM AUTHORIZED' to continue:
```

### 9.2 আইনি দিক (বাংলাদেশ)

- **সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ (Cyber Security Ordinance 2025, Ordinance No. 25 of 2025)** 21 May 2025-এ Gazette প্রকাশের মাধ্যমে কার্যকর হয়েছে এবং **Cyber Security Act 2023 বাতিল** করেছে। অনুমতি ছাড়া কোনো computer system-এ প্রবেশ বা হস্তক্ষেপ এখনও অপরাধ। তাই active scanning-এ সতর্ক থাকতে হবে। (Ordinance পরে সংসদে আইন হিসেবে পাস হয়েছে কি না বা বদলেছে কি না, তা project জমা দেওয়ার আগে Gazette/আইন মন্ত্রণালয়ের website-এ আবার দেখে নিতে হবে।)
- ip-api (free), Shodan InternetDB, VirusTotal (public) **non-commercial use**-এর জন্য। Academic project-এর জন্য ঠিক আছে, বিক্রি করা product-এর জন্য নয়।

### 9.3 Privacy ও Safe Coding

- API key শুধু `.env`-এ; `.env` `.gitignore`-এ; repo-তে শুধু `.env.example`।
- ip-api free endpoint HTTP (encrypted নয়)। Report-এ এটা উল্লেখ থাকবে। Sensitive investigation-এ HTTPS provider ব্যবহার করতে হবে।
- Cache local; কোনো lookup history কোথাও upload হবে না।
- প্রতিটি report-এ disclaimer: *"IP geolocation is approximate. An IP address does not identify a person."*
- Downloaded list (Tor, cloud ranges) parse করার সময় strict validation। Malformed line skip করতে হবে, `eval` কখনো নয়।

---

## 10. Advanced Viva প্রশ্ন

| প্রশ্ন | সংক্ষিপ্ত উত্তর |
|---|---|
| RDAP কী, WHOIS থেকে পার্থক্য? | RDAP হলো WHOIS-এর আধুনিক উত্তরসূরি: structured JSON, HTTPS, standardized query। WHOIS free-text, format একেক RIR-এ একেক রকম। |
| ASN কী? | Autonomous System Number: একটি network (ISP/company)-এর পরিচয় নম্বর, যা BGP routing-এ ব্যবহৃত হয়। যেমন Google = AS15169। |
| BGP ও RPKI কী? | BGP দিয়ে network-গুলো একে অপরকে জানায় কোন IP prefix কোন পথে পৌঁছানো যায়। RPKI cryptographically যাচাই করে prefix-টি সঠিক AS থেকে announce হচ্ছে কি না। |
| Anycast কী, geolocation-এ সমস্যা কেন? | একই IP একাধিক জায়গা থেকে announce হয়; user কাছের server-এ যায়। তাই একটি নির্দিষ্ট শহর বলা যায় না। |
| CGNAT কী? | ISP অনেক গ্রাহককে একটি public IP-এর পেছনে রাখে (`100.64.0.0/10` internal range)। তাই একটি public IP ≠ একজন user। |
| FCrDNS কী? | PTR hostname-এর A record আবার মূল IP-তে ফিরলে hostname-টি বিশ্বাসযোগ্য। |
| RTT দিয়ে geolocation কীভাবে যাচাই করা যায়? | আলো fiber-এ ~200 km/ms যায়, তাই দূরত্ব ≤ RTT × 100 km। এর বেশি দূরে database দেখালে সেটা ভুল। |
| EUI-64 privacy সমস্যা কী? | IPv6 address-এর শেষ 64 bit-এ device-এর MAC থাকে, ফলে device track করা যায়। তাই আধুনিক OS privacy extension ব্যবহার করে। |
| Geofeed কী? | ISP নিজে publish করা CSV (RFC 8805), যেখানে prefix ও তার শহর লেখা থাকে। RFC 9632 অনুযায়ী RIR database-এর `geofeed:` attribute দিয়ে খুঁজে পাওয়া যায়। |
| iCloud Private Relay কি VPN? | না। Apple-এর privacy relay, যা Apple public CSV-তে প্রকাশ করে। এটাকে VPN-এর মতো block করলে সাধারণ iPhone user-রা ক্ষতিগ্রস্ত হয়। |
| Reputation আর Exposure score আলাদা কেন? | খোলা port থাকা মানে vulnerable হতে পারে (exposure)। Abuse report থাকা মানে IP থেকে খারাপ কাজ হয়েছে (reputation)। দুটো আলাদা প্রশ্নের উত্তর। |
| কেন একাধিক provider? | কোনো database ১০০% সঠিক নয়। একাধিক উৎসের মিল-অমিল দেখে confidence বের করা যায়। |

---

## 11. Sources

**Official / Primary**
- Python `ipaddress`: https://docs.python.org/3/library/ipaddress.html
- ip-api JSON & batch docs: https://ip-api.com/docs/api:json, https://ip-api.com/docs/api:batch
- IPinfo Lite: https://ipinfo.io/lite · Launch press release (6 May 2025): https://secure.businesswire.com/news/home/20250506409714/en/IPinfo-Launches-IPinfo-Lite-Unlimited-Country-level-Geolocation-API-Database-Download
- Shodan InternetDB: https://internetdb.shodan.io/ · https://blog.shodan.io/introducing-the-internetdb-api/
- GreyNoise Community API: https://docs.greynoise.io/docs/using-the-greynoise-community-api
- VirusTotal Public vs Premium API: https://docs.virustotal.com/reference/public-vs-premium-api
- Spamhaus: public resolver ও DQS: https://www.spamhaus.com/resource-center/successfully-accessing-spamhauss-free-block-lists-using-a-public-dns/
- RFC 9632 (Finding and Using Geofeed Data): https://www.rfc-editor.org/rfc/rfc9632.html
- PeeringDB Network Type: https://docs.peeringdb.com/blog/network_type_what_why_how/
- Apple Private Relay egress list: https://mask-api.icloud.com/egress-ip-ranges.csv
- Tor exit list: https://check.torproject.org/torbulkexitlist
- AWS IP ranges: https://ip-ranges.amazonaws.com/ip-ranges.json

**Secondary (cross-check করা)**
- abuse.ch Auth-Key requirement (June 2025): https://www.elastic.co/guide/en/integrations/current/ti_abusech.html
- AbuseIPDB free tier limits: https://wiki.iphoster.net/wiki/AbuseIPDB_-_IP_reputation_check_-_2026
- Cyber Security Ordinance 2025 (Bangladesh): https://digitalpolicyalert.org/event/38587-cyber-security-ordinance-2025-ordinance-no-25-of-2025-enters-into-force · https://www.observerbd.com/news/526794
