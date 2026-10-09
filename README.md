# IP Finder v2 (Phase 0–4)

একটি IP address থেকে **আইনসঙ্গতভাবে যা যা জানা সম্ভব**, তা ধাপে ধাপে বের করার Python tool। পুরো roadmap: [ADVANCED_PLAN.md](ADVANCED_PLAN.md)।

এই version-এ আছে **Phase 0 (setup)**, **Phase 1 (offline analysis)**, **Phase 2 (location ও network: ip-api, IPinfo Lite, MaxMind GeoLite2, Team Cymru, PeeringDB)**, **Phase 3 (registry, routing ও DNS: RDAP, RIPEstat BGP/RPKI, reverse DNS + FCrDNS, Geofeed)** আর **Phase 4 (anonymity ও exposure: Tor exit, iCloud Private Relay, cloud/CDN range, VPN/datacenter list, Shodan InternetDB; `update-lists`)**। কোনো API key ছাড়াই চলে; key বা database যোগ করলে আরও source যুক্ত হয়। Threat intelligence (AbuseIPDB, GreyNoise…) আসবে Phase 5-এ।

> ⚠️ IP geolocation আনুমানিক। একটি IP address কোনো ব্যক্তিকে শনাক্ত করে না।

---

## Phase 4: anonymity, hosting ও exposed service

| Source | কী দেয় | কোথা থেকে | কত ঘন ঘন বদলায় |
|---|---|---|---|
| **Tor exit list** | Address-টা Tor exit relay কিনা, relay-র fingerprint, শেষ কবে exit হিসেবে দেখা গেছে, Tor Relay Search link | Tor Project: `torbulkexitlist` ও `exit-addresses` | প্রতি ঘণ্টায় (৬ ঘণ্টার পুরোনো হলে সতর্ক করে) |
| **iCloud Private Relay** | Apple-এর egress address কিনা, আর Apple কোন এলাকার user-দের জন্য সেটা ব্যবহার করে | Apple: `egress-ip-ranges.csv` (RFC 8805) | Apple নিয়মিত বদলায় |
| **Cloud / CDN range** | AWS (region ও service যেমন EC2), Google Cloud (region), Google-এর নিজস্ব service, Azure (region ও service tag), Oracle Cloud, Cloudflare, Fastly | প্রতিটা কোম্পানির নিজের প্রকাশ করা list | দিনে বা সপ্তাহে |
| **VPN / datacenter list** | পরিচিত VPN provider-এর network (যেমন M247, Mullvad, ProtonVPN-এর ASN) আর datacenter network (home বা mobile line নয়) | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) (MIT licence): IPv4 block আর ASN list (ASN দিয়ে IPv6-ও ধরা পড়ে) | মাঝে মাঝে |
| **Shodan InternetDB** | খোলা port, software (CPE), সম্ভাব্য CVE, tag, hostname; ঝুঁকিপূর্ণ port (Telnet, SMB, RDP, VNC, Redis, MongoDB…) আলাদা করে দেখায় | `internetdb.shodan.io/{ip}`, key লাগে না | Shodan সাপ্তাহিক update করে |

**List download করা:** Lookup নিজে কখনো বড় list download করে না। সেটা করে আলাদা command:

```bash
ipfinder update-lists              # সব list (আর .env-এ MaxMind key থাকলে GeoLite2-ও)
ipfinder update-lists tor-exits    # শুধু একটা
ipfinder update-lists --force      # তাজা হলেও আবার নামাও
ipfinder update-lists --status     # কোনটা আছে, কত পুরোনো
```

- Download করা file আগে পুরোপুরি parse করে যাচাই করা হয়, তারপর পুরোনোটার জায়গায় বসে। ফলে error page বা আধা-নামা file কখনো ভালো list নষ্ট করে না।
- যে list তাজা (যেমন Tor ৩০ মিনিটের কম পুরোনো, AWS ১২ ঘণ্টার কম), `--force` ছাড়া সেটা আবার নামানো হয় না।
- Azure-এর file-এর নাম প্রতি সপ্তাহে বদলায়, তাই Microsoft-এর download page থেকে আসল link খুঁজে নেওয়া হয়। Page-এর গঠন বদলালে পরিষ্কার error দেখায়।
- **MaxMind:** `.env`-এ `MAXMIND_ACCOUNT_ID` আর `MAXMIND_LICENSE_KEY` থাকলে GeoLite2 City ও ASN download হয়। পদ্ধতিটা MaxMind-এর নিজের `geoipupdate` tool-এর source code মিলিয়ে বানানো। নতুন build না থাকলে (MD5 মিলে গেলে) কিছু নামায় না, আর download-এর checksum মিলিয়ে দেখে।

**সৎ সীমাবদ্ধতা:**
- Tor-এর list-এ IPv6 address নেই, তাই IPv6 Tor exit চেনা যায় না। Report-এ সেটা বলা থাকে।
- VPN list community-র বানানো। List-এ থাকা মানে "এই network VPN হিসেবে পরিচিত", কোনো নির্দিষ্ট connection VPN দিয়ে এসেছে তার প্রমাণ নয়। List-এ নেই এমন VPN ধরা পড়ে না।
- Private Relay VPN নয়। একটা egress address অনেক Apple user ভাগ করে নেয়।
- InternetDB-র CVE-এর মধ্যে software version দেখে অনুমান করা (unverified) CVE-ও আছে, আর data সাপ্তাহিক snapshot, live নয়। InternetDB শুধু non-commercial কাজে free।

### আসল output (সংক্ষেপিত): AWS ও X4BNet-এর live list দিয়ে

এই environment থেকে AWS-এর `ip-ranges.json` (17,570 prefix) আর X4BNet-এর list সত্যিই download করা গেছে। নিচের ফল সেই আসল list থেকে। Tor, Apple, Google, Azure, Oracle, Cloudflare, Fastly আর Shodan-এর server এখান থেকে পৌঁছানো যায়নি, তাই সেগুলোর code test হয়েছে documentation-এর format দিয়ে।

```text
$ ipfinder update-lists aws vpn-networks datacenter-networks vpn-asns datacenter-asns
│ aws                 │ 17,570  │ 2026-10-09 15:37:06 UTC │ 2026-10-09 19:16 UTC (0 h ago) │ updated │
│ vpn-networks        │ 11,054  │ -                       │ 2026-10-09 19:16 UTC (0 h ago) │ updated │
│ datacenter-networks │ 44,471  │ -                       │ 2026-10-09 19:16 UTC (0 h ago) │ updated │

$ ipfinder 3.80.1.1
│ Anonymity and hosting (local lists)
│   Cloud / CDN          Amazon Web Services - us-east-1 - EC2 (3.80.0.0/12)
│   Listed VPN network   no
│   Listed datacenter    yes - 3.64.0.0/10

$ ipfinder 2.26.157.1
│   Listed VPN network   yes - 2.26.157.0/24
│   Listed datacenter    yes - 2.26.157.0/24
```

---

## Phase 3: registry, routing ও DNS

| Source | কী দেয় | Key | সীমা ও শর্ত |
|---|---|---|---|
| **RDAP** (RFC 9083) | Network-এর নাম ও handle, registered range ও CIDR, কার নামে registered, allocation type, registration ও last-changed তারিখ, parent block, **abuse e-mail ও phone**, geofeed link | লাগে না | কোন RIR-কে জিজ্ঞেস করতে হবে তা IANA bootstrap file (RFC 9224) থেকে বের করে; সেটা না পেলে `rdap.org`। LACNIC: 10/min, বাকি server-এ ভদ্রভাবে 30/min |
| **RIPEstat** | BGP-তে announced কিনা, prefix ও origin AS, **RPKI status**, কতগুলো RIS peer prefix-টা দেখে, প্রথম/শেষ কবে BGP-তে দেখা গেছে, পাশের AS-গুলো, abuse e-mail | লাগে না | একসাথে সর্বোচ্চ ৮টি request (IP Finder ৫টির বেশি পাঠায় না); `sourceapp=ip-finder` |
| **Reverse DNS** | PTR hostname, **forward-confirmed** কিনা (FCrDNS), hostname থেকে ইঙ্গিত (home line, mobile, cloud, hosting, mail server...) | লাগে না | নিজের DNS resolver |
| **Geofeed** (RFC 8805 / 9632) | Network operator নিজে যে location প্রকাশ করে: দেশ, ISO 3166-2 region, শহর | লাগে না | শুধু HTTPS, file ≤ 10 MB; RDAP record-এ link থাকলে তবেই চলে |

**RPKI status-এর মানে:**

| Status | মানে |
|---|---|
| `valid` | একটি ROA এই origin AS-কে এই prefix announce করার অনুমতি দেয় |
| `invalid_asn` | কোনো ROA এই origin AS-কে অনুমতি দেয় না: hijack বা ভুল configuration হতে পারে |
| `invalid_length` | Announce করা prefix ROA-র max length-এর চেয়ে বেশি specific |
| `unknown` | কোনো ROA এই route cover করে না (RPKI দিয়ে সুরক্ষিত নয়; এটা ভুল নয়) |

- **Abuse contact:** RDAP আর RIPEstat দুই জায়গা থেকেই e-mail নিয়ে মিলিয়ে দেখায়, কোনটা কোন source থেকে এসেছে সহ। Attack বা spam-এর report সেখানেই পাঠাতে হয়; কোন customer address-টা ব্যবহার করেছিল, তা শুধু network operator জানে।
- **FCrDNS কেন:** Reverse zone যার হাতে, সে যেকোনো নাম বসাতে পারে (এমনকি `mail.google.com`)। নামটা আবার resolve করে একই address পাওয়া গেলে তবেই নামটা বিশ্বাসযোগ্য। Mail server-গুলো ঠিক এটাই যাচাই করে।
- **Hostname-এর ইঙ্গিত শুধু ইঙ্গিত:** `pool-71-...fios.verizon.net` বা `ec2-...amazonaws.com` জাতীয় নাম থেকে network-এর ধরন আন্দাজ করা যায়, কিন্তু operator নাম ইচ্ছেমতো রাখতে পারে। `tor1` জাতীয় নাম প্রায়ই Toronto বোঝায়, তাই একা "tor" শব্দকে Tor ধরা হয় না।
- **Geofeed-এর নিয়ম (RFC 9632):** File-এর কোনো entry তখনই ব্যবহার হয়, যখন সেটা geofeed-এর link দেওয়া registered network-এর ভেতরে পড়ে। নাহলে যে কেউ অন্যের address-এর location লিখে দিতে পারত। HTTP-তে redirect হলে download বাতিল হয়। RPKI signature থাকলে জানায়, কিন্তু যাচাই করে না।
- **Terminal নিরাপত্তা:** Registry remark, hostname বা API বার্তায় terminal control character (যেমন ESC) থাকলে তা `\x1b` হিসেবে দেখায়, কখনো terminal-কে নিয়ন্ত্রণ করতে দেয় না।
- **সৎ বার্তা:** DNS resolver সব নামকে "নেই" বললে reverse DNS "PTR নেই" বলে না; আগে একটা সবসময়-থাকা PTR record দিয়ে যাচাই করে। RIPEstat-এর কোনো একটা অংশ fail করলে বাকিটা দেখায়, কী বাদ গেল তা জানায়, আর সেই অসম্পূর্ণ ফল cache করে না।

### Test data দিয়ে output (সংক্ষেপিত)

এখানে RDAP অংশের field-গুলো ARIN-এর 8.8.8.8 record-এর গঠন মেনে বানানো। কিন্তু RIPEstat-এর সংখ্যা (330 of 333 peer, neighbour সংখ্যা) আর geofeed **উদাহরণ মাত্র, আসল data নয়**। এই environment থেকে বাইরের internet-এ যাওয়া যায় না।

```text
│ Routing and RPKI (RIPEstat)
│   BGP                     announced as 8.8.8.0/24 by AS15169 (GOOGLE - Google LLC)
│   RPKI (AS15169)          valid - a ROA authorises this origin AS for this prefix
│                           (ROA 8.8.8.0/24 max /24 AS15169)
│   Visibility              330 of 333 RIS peers (99%)
│   Busiest upstream side   AS1299, AS174, AS3356
│ Registration (RDAP)
│   Network name      GOGL (NET-8-8-8-0-2)
│   Registered to     Google LLC (GOGL)
│   Range             8.8.8.0 - 8.8.8.255
│   Allocation type   DIRECT ALLOCATION
│   Registered        2023-12-28
│   Registry          ARIN (rdap.arin.net)
│ Abuse contact
│   E-mail   network-abuse@google.com  (rdap, ripestat)
│ Reverse DNS
│   PTR                 dns.google
│   Forward-confirmed   yes - dns.google resolves back to this address
```

> **যাচাইয়ের অবস্থা:** RDAP, RIPEstat, reverse DNS আর Geofeed-এর code RFC ও প্রতিটি service-এর documentation-এ দেওয়া response format দিয়ে test করা হয়েছে (fake HTTP ও fake DNS দিয়ে)। আসল service-এর বিরুদ্ধে প্রথমবার চালানো হবে আপনার computer-এ।

---

## Phase 2: location ও network

| Source | কী দেয় | Key / file | সীমা ও শর্ত |
|---|---|---|---|
| **ip-api** | দেশ, অঞ্চল, শহর, ZIP, lat/lon, timezone, ISP, org, ASN, reverse DNS, mobile/proxy/hosting flag | লাগে না | 45 req/min (single), batch 100টি IP × 15 req/min; free tier শুধু HTTP, non-commercial |
| **IPinfo Lite** | দেশ, মহাদেশ, ASN, AS name ও domain | `IPINFO_TOKEN` (free) | Unlimited (IPinfo-র দাবি) |
| **MaxMind GeoLite2** | শহর, lat/lon **± accuracy radius**, timezone, registered country, ASN | `data/GeoLite2-City.mmdb`, `data/GeoLite2-ASN.mmdb` (free account) | Offline; database-এর build date report-এ দেখায় |
| **Team Cymru** | BGP-তে announce করা prefix, origin ASN, RIR, allocation date, AS name | লাগে না (DNS) | Fair use |
| **PeeringDB** | ASN-টা কেমন network: ISP / Content / Education, scope, peering policy | ঐচ্ছিক `PEERINGDB_API_KEY` | ASN জানা গেলে তবেই চলে |

- **Cache:** online উত্তর `data/cache.sqlite`-এ জমা থাকে (reverse DNS ১ ঘণ্টা, RIPEstat ৬ ঘণ্টা, ip-api, IPinfo, Team Cymru, Geofeed ও InternetDB ১ দিন, RDAP, RDAP bootstrap ও PeeringDB ৭ দিন; local list-এর ফল cache হয় না, সবসময় সর্বশেষ list থেকে আসে), তাই একই IP বারবার দেখলে free quota খরচ হয় না।
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
ipfinder update-lists                     # Tor, cloud, Private Relay, VPN list (+ GeoLite2)
ipfinder update-lists --status            # কোন list আছে, কত পুরোনো
ipfinder cache info                       # cache-এ কী আছে
ipfinder cache clear                      # cache মুছে ফেলা
ipfinder                                  # v1.0-এর মতো interactive prompt
python -m ipfinder 8.8.8.8                # repo folder থেকে, rich install থাকলে
```

**Exit codes:** `0` সফল, `1` অন্তত একটি input বৈধ IP নয় (বা `me` নিজের IP খুঁজে পায়নি, বা `update-lists`-এ কোনো list নামানো যায়নি), `2` usage ভুল (ভুল option, input file পড়া যায়নি, output file লেখা যায়নি), `3` internal error, `130` Ctrl+C।

Report যায় **stdout**-এ। Prompt, status ও error বার্তা যায় **stderr**-এ, তাই `ipfinder -f json > out.json` সবসময় বৈধ JSON দেয়। Input file UTF-8 (BOM সহ বা ছাড়া) বা UTF-16 হতে পারে, যেমন Windows PowerShell-এর তৈরি file।

**কোন folder থেকে চালাবেন:** `.env`, `data/` folder-এর database আর `data/cache.sqlite` **যে folder থেকে command চালাচ্ছেন সেখান থেকে** পড়া হয় (সাধারণত repo-র root)। অন্য জায়গা থেকে চালালে `IPFINDER_MAXMIND_CITY_DB`, `IPFINDER_MAXMIND_ASN_DB`, `IPFINDER_OUI_DB`, `IPFINDER_CACHE`, `IPFINDER_LISTS_DIR` দিয়ে path দিন।

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
│   ├── cli.py                  # argparse CLI (lookup, me, sources, cache, update-lists)
│   ├── core/
│   │   ├── validator.py        # input → validated address, helpful errors
│   │   ├── text.py             # version-independent IPv6 text, safe display of input
│   │   ├── special_ranges.py   # IANA special-purpose tables + longest-prefix classify
│   │   ├── models.py           # ProviderResult, IPReport
│   │   ├── config.py           # .env + environment, API keys, paths, profile
│   │   ├── session.py          # one run: HTTP client, DNS, cache, rate limiters
│   │   ├── cache.py            # memory + SQLite cache with per-provider TTL
│   │   ├── ratelimit.py        # sliding-window limiter + server-driven pauses
│   │   ├── http.py             # JSON requests, capped downloads; errors never contain the URL/token
│   │   ├── errors.py           # ProviderError (shared, no imports)
│   │   ├── dns.py              # TXT / PTR / A / AAAA lookups (dnspython)
│   │   └── orchestrator.py     # stage 0 offline → stage 1 sources → stage 2 (PeeringDB, Geofeed)
│   ├── providers/
│   │   ├── base.py             # Provider interface (profile, key, files, cache, limits)
│   │   ├── offline.py          # L1
│   │   ├── ipapi.py            # ip-api single + batch
│   │   ├── ipinfo_lite.py      # IPinfo Lite
│   │   ├── maxmind.py          # GeoLite2 City + ASN (.mmdb)
│   │   ├── cymru.py            # Team Cymru IP-to-ASN over DNS
│   │   ├── peeringdb.py        # PeeringDB network type
│   │   ├── rdap.py             # RDAP: IANA bootstrap, registration, abuse contact
│   │   ├── ripestat.py         # RIPEstat: BGP, RPKI, visibility, neighbours, abuse
│   │   ├── reverse_dns.py      # PTR + forward-confirmed reverse DNS
│   │   ├── geofeed.py          # operator-published location (RFC 8805 / 9632)
│   │   ├── list_base.py        # base for providers that answer from downloaded lists
│   │   ├── tor.py              # Tor exit relay check
│   │   ├── private_relay.py    # iCloud Private Relay egress check
│   │   ├── cloud_ranges.py     # AWS / Google / Azure / Oracle / Cloudflare / Fastly
│   │   ├── vpn_lists.py        # X4BNet VPN and datacenter networks (by prefix and ASN)
│   │   ├── internetdb.py       # Shodan InternetDB: ports, CPEs, possible CVEs
│   │   ├── common.py           # shared normalisation helpers
│   │   └── __init__.py         # registry + planned providers (Phase 5–7)
│   ├── lists/
│   │   ├── specs.py            # every downloadable list: URL, format, parser, freshness
│   │   ├── index.py            # longest-prefix lookup (300k prefixes load in ~1-1.5 s, lookups in microseconds)
│   │   ├── store.py            # data/lists/: safe replace-after-validate downloads + metadata
│   │   └── maxmind.py          # GeoLite2 download (same protocol as geoipupdate)
│   ├── analysis/
│   │   ├── addressing.py       # representations, IPv4 class, multicast, Python flags
│   │   ├── ipv6_insights.py    # embedded IPv4, EUI-64/ISATAP, structure, multicast
│   │   ├── oui.py              # IEEE OUI vendor lookup
│   │   ├── hostname.py         # hints from a reverse-DNS name
│   │   ├── offline.py          # combines L1 + online-lookup decision
│   │   └── summary.py          # map pin, local time, agreement between sources
│   └── output/
│       ├── terminal.py         # rich panels (no markup parsing, control characters escaped)
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

- Key ছাড়া চলে: ip-api, RDAP, RIPEstat (prefix-overview, routing-status, abuse-contact), Shodan InternetDB, GreyNoise Community (key ঐচ্ছিক)।
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
| 3 | RDAP, RIPEstat (BGP/RPKI), DNS/FCrDNS, Geofeed | ✅ (code ও test; আসল API-তে প্রথম চালানো বাকি) |
| 4 | Tor, Private Relay, cloud range, VPN/datacenter list, InternetDB; `update-lists` | ✅ (code ও test; AWS ও X4BNet list live দিয়ে যাচাই, বাকি source আপনার computer-এ প্রথম চালানো বাকি) |
| 5–10 | Threat intel, scoring, active mode, reports, dashboard | ⏳ |

`ipfinder sources` চালালে প্রতিটি data source-এর phase ও API-key অবস্থা দেখা যায়।

---

## দায়িত্বশীল ব্যবহার

- Phase 1 পুরোপুরি passive ও offline। কোনো packet কোথাও পাঠায় না।
- Active probing (Phase 7) default-এ বন্ধ থাকবে এবং শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত system-এ চালানো যাবে।
- বাংলাদেশে সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ প্রযোজ্য; বিস্তারিত [ADVANCED_PLAN.md §9](ADVANCED_PLAN.md#9-security-ethics-ও-আইন)।
