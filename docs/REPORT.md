# IP Finder v2: একটি multi-source IP intelligence tool

**Project report**

| | |
|---|---|
| Project | IP Finder v2 (`ip-finder`, version 2.0.0b1) |
| লেখক | dipro20debnath |
| Repository | https://github.com/dipro20debnath/IP-Finder |
| ভাষা ও platform | Python 3.10–3.14; Windows, macOS, Linux |
| তারিখ | অক্টোবর 2026 |

---

## সারসংক্ষেপ

একটা IP address থেকে আইনসঙ্গতভাবে যা জানা সম্ভব, তার বেশিরভাগ ছড়িয়ে আছে ভিন্ন ভিন্ন জায়গায়:
- address-এর নিজের গঠনে,
- geolocation database-এ,
- Regional Internet Registry-তে,
- BGP routing table-এ,
- DNS-এ,
- cloud provider-দের প্রকাশিত list-এ,
- threat intelligence service-এ।

এই তথ্যগুলো প্রায়ই একে অপরের সাথে মেলে না। আর কোন তথ্য কতটা নির্ভরযোগ্য, তা সাধারণ tool বলে না।

IP Finder v2 ২৭টা source একসাথে জিজ্ঞেস করে এবং তাদের ফল ১২টা স্তরে সাজায়। প্রতিটা তথ্যের সাথে দেখায় কোথা থেকে এল, কতটা নির্ভরযোগ্য, আর কী জানা যায় না। Source-গুলোর ফল মিলিয়ে চারটা উত্তর দেয়: connection type, location consensus, location confidence, আর reputation ও exposure score। প্রতিটা score স্বচ্ছ নিয়মে বানানো, তাই কেন এই উত্তর, তা লাইন ধরে দেখা যায়।

Tool-টার তিনটা ব্যবহারের পথ আছে: command line, HTML report আর localhost web dashboard। এতে আছে:
- `--offline` mode, যেখানে address-এর কোনো তথ্য computer-এর বাইরে যায় না।
- `--active` mode (ping, traceroute, TLS), যা শুধু স্পষ্ট অনুমতির পরে চলে।

631টা automated test Python 3.10 থেকে 3.14 পর্যন্ত internet ছাড়াই চলে। HTML report আর dashboard আসল browser-এ (Chromium) যাচাই করা।

---

## ১. ভূমিকা

### ১.১ সমস্যা

IP Finder-এর প্রথম version (v1.0) একটা web API (ip-api.com) থেকে দেশ আর শহর দেখাত। এতে চারটা সমস্যা ছিল:

1. **এক source, কোনো যাচাই নেই।** Geolocation database প্রায়ই ভুল বা পুরোনো। দুটো database একই address-কে কয়েকশো কিলোমিটার দূরে বসাতে পারে, অথচ user সেটা জানতে পারে না।
2. **"IP = মানুষ" ভুল ধারণা।** CGNAT, VPN, Tor, iCloud Private Relay, cloud server বা anycast service-এর পেছনে একটা address মানে একজন মানুষ বা একটা জায়গা নয়। Tool এগুলো চিনত না।
3. **Address-এর ভেতরের তথ্য উপেক্ষিত।** IPv6 address-এ লুকানো IPv4 (Teredo, 6to4), device-এর MAC address (EUI-64), বা special-purpose range (documentation, CGNAT) কোনো database ছাড়াই পড়া যায়।
4. **নিরাপত্তা ও নৈতিকতা।** কোনো তথ্য তৃতীয় পক্ষের কাছে যাবে কিনা, বা target-এ packet যাবে কিনা, user সেটা নিয়ন্ত্রণ করতে পারত না।

### ১.২ লক্ষ্য

- একটা public IP address থেকে আইনসঙ্গত ও প্রযুক্তিগতভাবে যা যা জানা সম্ভব, সব এক জায়গায় আনা।
- প্রতিটা তথ্যের **উৎস, নির্ভরযোগ্যতা ও সীমাবদ্ধতা** দেখানো।
- Source-দের মধ্যে অমিল লুকিয়ে না রেখে মিলিয়ে দেখা, আর স্বচ্ছ নিয়মে confidence দেওয়া।
- Default-এ শুধু passive কাজ করা। Active probe শুধু অনুমতি নিয়ে, আর privacy-র জন্য সম্পূর্ণ offline mode রাখা।
- কোনো API key ছাড়াই কাজ করা। Key দিলে আরও source যুক্ত হবে।

### ১.৩ যা এই project-এর লক্ষ্য নয়

কোনো ব্যক্তিকে শনাক্ত করা, বাড়ির ঠিকানা বের করা, বা অনুমতি ছাড়া কোনো system scan করা। প্রতিটা report-এ লেখা থাকে: *"IP geolocation is approximate. An IP address does not identify a person."*

---

## ২. পটভূমি

**IP address-এর গঠন।** IANA কিছু address range বিশেষ কাজে আলাদা করে রেখেছে (RFC 6890-এর registry)। যেমন private network (RFC 1918), CGNAT-এর shared space `100.64.0.0/10` (RFC 6598), documentation (RFC 5737, RFC 9637)। এগুলোর জন্য public geolocation-এর কোনো অর্থ নেই। IPv6 address-এর ভেতরে IPv4 থাকতে পারে:
- 6to4 (RFC 3056)
- NAT64 (RFC 6052)
- Teredo (RFC 4380): client-এর public IPv4 আর NAT port, bit উল্টে রাখা

SLAAC-এর পুরোনো নিয়মে interface ID বানানো হয় MAC থেকে (modified EUI-64, RFC 4291 Appendix A)। এতে device track করা যায়, তাই RFC 8981 random address চালু করেছে।

**Registry ও routing।** প্রতিটা address block কোনো Regional Internet Registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) থেকে কারো নামে বরাদ্দ। RDAP (RFC 9083) সেই তথ্য structured JSON-এ দেয়। কোন RIR-কে জিজ্ঞেস করতে হবে, তা IANA-র bootstrap file (RFC 9224) বলে।

BGP-তে কোন network (AS) কোন prefix announce করছে, সেটা দেখা যায়। RPKI (RFC 6811) যাচাই করে, সেই AS-এর announce করার অনুমতি আছে কিনা।

**Geolocation।** Database-গুলো (MaxMind GeoLite2, ip-api, IPinfo) নিজেদের পদ্ধতিতে অনুমান করে। MaxMind নিজের ফলের সাথে একটা accuracy radius দেয়। Network operator নিজেও নিজের address-এর location প্রকাশ করতে পারে (geofeed, RFC 8805)। সেটা খুঁজে পাওয়ার নিয়ম RFC 9632-এ।

**Anycast।** একই address পৃথিবীর অনেক জায়গা থেকে announce হয় (যেমন 8.8.8.8, 1.1.1.1)। তাই তার একটা location হয় না।

**Speed-of-light সীমা।** Fibre-এ আলো প্রতি millisecond-এ প্রায় 200 km যায়। তাই round-trip time থেকে দূরত্বের একটা নিশ্চিত ঊর্ধ্বসীমা পাওয়া যায়।

---

## ৩. প্রয়োজনীয়তা

**কার্যকরী (functional):**
- IPv4 ও IPv6 address নেওয়া: port, URL, zone ID, integer আর বাংলা সংখ্যা সহ। অস্পষ্ট input আন্দাজে না পড়ে ব্যাখ্যা দেওয়া।
- ১২টা স্তরে তথ্য:
  - L1: offline বিশ্লেষণ
  - L2–L3: location ও network
  - L4: registration
  - L5: BGP ও RPKI
  - L6: DNS
  - L7: anonymity ও hosting
  - L8: খোলা service
  - L9: threat reputation
  - L10: active probe
  - L11: সমন্বিত বিশ্লেষণ
  - L12: report
- Verdict: connection type, anycast, location consensus ও confidence, reputation ও exposure, প্রতিটার কারণ সহ।
- Output: terminal, JSON, CSV, map সহ HTML; একসাথে অনেক address (batch); browser dashboard।

**অ-কার্যকরী (non-functional):**
- একটা source fail করলে বাকিগুলো চলবে।
- Free API-র rate limit কখনো ভাঙবে না (যেমন ip-api: মিনিটে 45টা)।
- একই address বারবার দেখলে cache থেকে আসবে, quota খরচ হবে না।
- Network থেকে আসা কোনো text terminal, browser বা Excel-কে নিয়ন্ত্রণ করতে পারবে না।
- API key কখনো log, error বা report-এ আসবে না।
- Windows, macOS, Linux; Python 3.10–3.14।

---

## ৪. System design

![Architecture](architecture.svg)

বিস্তারিত: [ARCHITECTURE.md](ARCHITECTURE.md)। মূল সিদ্ধান্তগুলো:

**Staged orchestrator।** Source-গুলো চার ধাপে চলে:
- **Stage 0:** offline বিশ্লেষণ। এটা ঠিক করে online lookup আদৌ হবে কিনা, আর কোন address-এ (যেমন Teredo-র ভেতরের IPv4)।
- **Stage 1:** স্বাধীন source-গুলো একসাথে (async)।
- **Stage 2:** যাদের stage 1-এর তথ্য লাগে (PeeringDB-র ASN, Geofeed-এর RDAP link)।
- **Stage 3:** active probe, passive কাজ শেষ হওয়ার পরে।

**Provider contract।** প্রতিটা source একটা class। সেখানে ঘোষণা করা থাকে:
- কোন stage-এ আর কোন profile-এ চলে।
- কোন key লাগে।
- Local কিনা, active কিনা।
- Cache কতক্ষণ, rate limit কত, timeout কত।

কেন চলল না, সেই কারণ report-এ হুবহু দেখায়।

**Shared session।** একটা run-এ একটাই HTTP client, DNS resolver, SQLite cache, rate limiter আর parse করা list থাকে। Web dashboard পুরো server-এর জন্য একটা session রাখে, তাই browser-এর সব tab মিলিয়েও rate limit মানা হয়।

**Profile ও mode।**

| Profile বা mode | কী চলে, কেন |
|---|---|
| `quick` | শুধু L1 আর ip-api: দ্রুত, একটা তৃতীয় পক্ষ। |
| `standard` (default) | যেসব source-এ threat-intel key লাগে না। |
| `full` | Threat intelligence-ও। এতে address আরও ৭টা তৃতীয় পক্ষে যায়, তাই default-এ বন্ধ। |
| `--offline` | শুধু local file। |
| `--active` | Target-এ packet; অনুমতি সাপেক্ষে। |

---

## ৫. Algorithm

### ৫.১ Address classification (L1)

Python-এর `ipaddress` module-এর `is_global` IANA registry-র সাথে সব জায়গায় মেলে না, আর Python version ভেদে বদলায়। এই project-এ Python 3.10.20, 3.11.17, 3.12.3, 3.13.16 আর 3.14.6-এ যাচাই করে পাওয়া গেছে:
- `5f00::1` (SRv6 SID, RFC 9602) globally reachable নয়, কিন্তু Python বলে `True`।
- `2001:1::3` (RFC 9665) globally reachable, কিন্তু Python বলে `False`।
- `3fff::1` (documentation, RFC 9637) Python 3.12.3-এ `True`।

তাই IANA-র special-purpose registry থেকে নিজস্ব table বানানো হয়েছে (`core/special_ranges.py`, 2025-10-09-এর registry অনুযায়ী)। সেখানে longest-prefix match হয়, আর Python যেখানে ভিন্ন কথা বলে, report-এ সেটা জানানো হয়।

### ৫.২ IPv6-এর ভেতরের তথ্য

- **Teredo:** server IPv4 = bit 32–63। Client IPv4 = শেষ 32 bit XOR `0xFFFFFFFF`। Port = bit 80–95 XOR `0xFFFF`।
- **EUI-64:** interface ID-র মাঝে `ff:fe` থাকলে MAC বের হয়: প্রথম byte-এর U/L bit উল্টে, `ff:fe` বাদ দিয়ে। কাকতালীয়ভাবে মেলার সম্ভাবনা 1/65,536, তাই confidence high। IEEE-র OUI list থাকলে নির্মাতার নামও দেখায়।
- **অন্যান্য:** 6to4, NAT64, ISATAP, RFC 5453-এর reserved ID, multicast scope ও flags।

### ৫.৩ Location consensus

1. **দেশ:** weighted vote। Operator-এর geofeed আর Apple-এর Private Relay list নিজেরাই নিজেদের address-এর কথা বলে, তাই তাদের ভোট ৩। Database-গুলোর (MaxMind, ip-api, IPinfo) ভোট ১।
2. **শহর:** জেতা দেশের ভেতরে যে শহর সবচেয়ে বেশি source বলে।
3. **Spread:** যেকোনো দুই source-এর মধ্যে সবচেয়ে বেশি দূরত্ব, haversine সূত্রে (R = 6371 km):

   d = 2R · asin( √( sin²(Δφ/2) + cos φ₁ · cos φ₂ · sin²(Δλ/2) ) )

   MaxMind-এর accuracy radius এর চেয়ে বড় হলে সেটাই uncertainty ধরা হয়। যাচাই: ঢাকা থেকে চট্টগ্রাম = 214 km।

### ৫.৪ Location confidence (০–১০০)

100 থেকে শুরু করে নিয়ম অনুযায়ী point বাদ বা যোগ হয়:

| নিয়ম | Point |
|---|---|
| Spread > 500 km / > 100 km | −40 / −25 |
| মাত্র একটা source coordinate দিয়েছে | −10 |
| কোনো source coordinate দেয়নি | −20 |
| দেশ নিয়ে অমিল | −20 |
| Hosting বা data centre | −30 |
| Tor বা VPN | −50 |
| Private Relay | −20 |
| Mobile network | −20 |
| Anycast | −60 |
| RTT অসম্ভব | −30 |
| Geofeed-এর দেশ consensus-এর সাথে মেলে | +10 |

70 বা তার বেশি = High, 40–69 = Medium, 40-এর কম = Low। এটা probability নয়। প্রতিটা point কেন, report-এ দেখায়, তাই examiner বা user নিজে যাচাই করতে পারেন।

### ৫.৫ Connection type

একটা decision tree, যেখানে প্রথম যে নিয়ম মেলে সেটাই উত্তর:

1. Tor
2. Private Relay
3. Anycast
4. Hosting + VPN
5. Hosting
6. VPN বা proxy
7. Mobile
8. Residential
9. Education, Government, Business বা ISP

প্রতিটা উত্তরের সাথে প্রমাণ থাকে, আর লেখা থাকে সেটা প্রকাশিত list থেকে (তথ্য) নাকি flag বা hostname থেকে (অনুমান)। বিপরীত signal (যেমন একটা source বলে mobile, আরেকটা বলে data centre) লুকানো হয় না।

### ৫.৬ Reputation আর exposure

দুটো আলাদা প্রশ্ন, তাই কখনো যোগ করা হয় না।

**Reputation** (address থেকে খারাপ কিছু হয়েছে কিনা):

| Signal | Point |
|---|---|
| AbuseIPDB confidence × 0.4 | সর্বোচ্চ +40 |
| GreyNoise: malicious | +25 |
| VirusTotal: প্রতিটা malicious engine | +5, সর্বোচ্চ +25 |
| যেকোনো blocklist | +20 |
| Tor exit | +10 |
| GreyNoise RIOT (পরিচিত ভালো service) | −30 |

**Exposure** (কী খোলা আছে; Shodan InternetDB থেকে):

| Signal | Point |
|---|---|
| প্রতিটা খোলা port | +2 |
| প্রতিটা প্রায়ই-আক্রান্ত service (Telnet, SMB, RDP…) | +15 |
| প্রতিটা সম্ভাব্য CVE | +5 |

কোনো source না চললে score দেখানোই হয় না, কারণ "0" মানে "পরিষ্কার", "জানা নেই" নয়।

### ৫.৭ Speed-of-light check (L10)

সবচেয়ে কম round-trip time R ms হলে address-টা সর্বোচ্চ **R/2 × 200 km** দূরে। দাবি করা location তার চেয়ে দূরে (দুই পক্ষের অনিশ্চয়তা বাদ দিয়ে) হলে geolocation ভুল, নয়তো address-টা anycast।

Proxy-র ফাঁদ ধরতে আগে `192.0.2.1`-এ একটা handshake চেষ্টা করা হয়। এটা RFC 5737-এর documentation address, internet-এ কখনো route হয় না। কেউ উত্তর দিলে বোঝা যায়, পথে কেউ (corporate firewall, antivirus) সবার হয়ে উত্তর দিচ্ছে। তখন সেই ফল বিশ্বাস করা হয় না। এই ফাঁদটা আসলেই এই project-এর development environment-এ পাওয়া গেছে।

---

## ৬. বাস্তবায়ন

**প্রযুক্তি:**
- `rich`: terminal।
- `httpx`: async HTTP।
- `dnspython`: DNS।
- `maxminddb`: GeoLite2 file পড়া।
- ঐচ্ছিক: FastAPI ও uvicorn (dashboard)।
- Test: `pytest`; lint ও format: `ruff`।
- Windows-এ `tzdata`।

ইচ্ছা করে নিজে লেখা হয়েছে: `.env` parser, RDAP client, ছোট X.509 certificate reader আর rate limiter। এতে dependency কম থাকে আর আচরণ পুরোপুরি নিয়ন্ত্রণে থাকে।

**আকার** (খালি লাইন বাদে, comment ও docstring সহ):

| অংশ | লাইন | File |
|---|---|---|
| Application (`ipfinder/`) | 8,505 | 72 |
| তার মধ্যে providers | 2,379 | 27 |
| Tests | ~5,000 | 24 |
| নিজস্ব web frontend (HTML, JS, CSS) | 521 | 6 |

**ধাপে ধাপে উন্নয়ন** (প্রতিটা phase একটা commit, `ADVANCED_PLAN.md`-এর roadmap অনুযায়ী):

| Phase | কাজ |
|---|---|
| 0–1 | Setup, CI, fixture script; validator, IANA table, IPv6 বিশ্লেষণ, CLI |
| 2 | ip-api, IPinfo Lite, MaxMind, Team Cymru, PeeringDB; cache; rate limiter |
| 3 | RDAP, RIPEstat (BGP/RPKI), reverse DNS + FCrDNS, Geofeed |
| 4 | Tor, Private Relay, cloud range, VPN list, Shodan InternetDB; `update-lists` |
| 5 | AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox, URLhaus, Spamhaus; Feodo ও DROP |
| 6 | Analysis engine: consensus, connection type, anycast, score |
| 7 | Active mode: RTT, traceroute, TLS, speed-of-light check, অনুমতির gate |
| 8 | CSV, offline map সহ HTML report, batch, progress bar |
| 9 | Web dashboard (`ipfinder serve`) |
| 10 | এই report, architecture, demo, viva প্রস্তুতি; `--offline` mode |

**কয়েকটা প্রকৌশল সিদ্ধান্ত ও কারণ:**

| সিদ্ধান্ত | কারণ |
|---|---|
| Python-এর `is_global`-এর বদলে নিজস্ব IANA table | Python কয়েকটা address-এ registry-র সাথে মেলে না, আর version ভেদে বদলায় (৫.১) |
| `folium`-এর বদলে Leaflet ও Natural Earth file-এর ভেতরে | folium 0.20.0-এর HTML চারটা CDN থেকে script নামায়। OpenStreetMap-এর tile server Referer ছাড়া request ফেরত দেয়, আর disk থেকে খোলা page Referer পাঠাতে পারে না। |
| List download আলাদা command (`update-lists`) | Lookup কখনো বড় file নামায় না। নতুন file আগে পুরো parse করে যাচাই হয়, তারপর পুরোনোটার জায়গায় বসে |
| Spamhaus-এ আগে RFC 5782-এর test entry জিজ্ঞেস করা | Public resolver দিয়ে query গেলে Spamhaus উত্তর দেয় না। তখন "listed নয়" বলা মিথ্যা হতো |
| Reverse DNS-এ forward-confirmation (FCrDNS) | Reverse zone-এর মালিক যেকোনো নাম বসাতে পারে। নামটা আবার একই address-এ ফিরলে তবেই বিশ্বাসযোগ্য |
| Dashboard-এর token link-এর `#` অংশে | Browser `#`-এর পরের অংশ server-এ পাঠায় না, তাই token server log-এ থাকে না |

---

## ৭. Testing ও যাচাই

**Automated test:** 631টা, Python 3.10, 3.11, 3.12, 3.13 আর 3.14-এ (প্রতিটা push-এ GitHub Actions-এ)।

- Online source-গুলো test হয় fake HTTP আর fake DNS দিয়ে। Response-এর গঠন প্রতিটা service-এর নিজের documentation বা official code থেকে নেওয়া।
- MaxMind অংশ test হয় MaxMind-এর official test database দিয়ে।
- Test-এ কোনো internet বা API key লাগে না।

| Test file (কয়েকটা) | Test | কী যাচাই করে |
|---|---|---|
| `test_special_ranges.py` | 78 | IANA table, longest-prefix match |
| `test_validator.py` | 74 | Input-এর প্রতিটা রূপ ও ভুল |
| `test_registry_routing.py` | 49 | RDAP, RIPEstat, reverse DNS, Geofeed |
| `test_ipv6_insights.py` | 48 | Teredo, EUI-64, NAT64, multicast |
| `test_analysis_engine.py` | 47 | প্রতিটা score-এর নিয়ম (plan-এর উদাহরণ: 214 km, mobile → 55 Medium) |
| `test_cli.py` | 47 | Command, exit code, output |
| `test_active.py` | 34 | `--active` ছাড়া কখনো probe না চলা, local server-এ probe |
| `test_web.py` | 28 | Dashboard-এর token, Host/Origin যাচাই, active gate, stream |
| `test_demo.py` | 5 | Demo-র সব command বৈধ; offline demo শুরু থেকে শেষ, network ছাড়া |

**আসল পরিবেশে যাচাই করা হয়েছে:**
- Python-এর `is_global`-এর অমিল, পাঁচটা Python version-এ (৫.১)।
- AWS-এর live `ip-ranges.json` (17,570 prefix) আর X4BNet-এর VPN ও datacenter list download করে lookup।
- নিজস্ব X.509 reader: container-এর 128টা CA certificate-এ CPython-এর নিজের decoder-এর সাথে হুবহু মিলেছে।
- Leaflet file-এর hash npm registry-র published integrity-র সাথে মিলেছে।
- HTML report আসল Chromium-এ disk থেকে খুলে: map আঁকা হয়, শূন্য network request।
- Dashboard আসল Chromium-এ:
  - address লিখে lookup, map, download।
  - token ছাড়া token form।
  - কোনো CSP violation নেই।
  - Dashboard ছাড়া অন্য কোনো server-এ request নেই।
- Dashboard-এর dependency-র সবচেয়ে পুরোনো অনুমোদিত version (FastAPI 0.115.0, uvicorn 0.30.0) আর সর্বশেষ (FastAPI 0.143.0, uvicorn 0.54.0) দুটোতেই test pass।
- `--offline`: একটাও HTTP request বা DNS query যায় না (test-এ গণনা করা)।
- Transparent proxy ধরা: development environment-এর আসল egress gateway দিয়ে।

**এখনও আসল service-এর বিরুদ্ধে চালানো বাকি (সৎ অবস্থা):** development environment থেকে বাইরের বেশিরভাগ service-এ পৌঁছানো যেত না। তাই নিচেরগুলো এখন পর্যন্ত documentation-এর format দিয়ে test করা, আসল service দিয়ে নয়:
- ip-api, IPinfo, Team Cymru, RDAP, RIPEstat, reverse DNS, Geofeed, InternetDB।
- Threat-intel API-গুলো।
- Tor, Apple, Google, Azure, Oracle, Cloudflare ও Fastly-র list।
- Ping ও traceroute-এর আসল output।

`scripts/capture_fixtures.py` আসল response রেকর্ড করার জন্য তৈরি, আর `scripts/demo.py --check` বলে দেয় কী প্রস্তুত। Plan-এর Phase 0-এর এই অংশটা (fixture রেকর্ড) internet-যুক্ত computer-এ করতে হবে।

---

## ৮. ফলাফল

নিচের সব output এই repository-তে আসলেই চালানো। Location-এর অংশ MaxMind-এর official **test** database থেকে, আসল GeoLite2 থেকে নয়।

| Input | IP Finder যা বলে |
|---|---|
| `81.2.69.142` (test DB) | London, GB; MaxMind radius 10 km; confidence 90/100 High (একটাই source, মিলিয়ে দেখার কিছু নেই: −10) |
| `8.8.8.8` (`--offline`) | Anycast service (Google Public DNS), প্রকাশিত list থেকে |
| `2001:0:4136:e378:8000:63bf:f7f7:f7f7` | Teredo: client 8.8.8.8, port 40000; server 65.54.227.120; online lookup ভেতরের 8.8.8.8-এর জন্য |
| `fe80::21a:2bff:fe3c:4d5e%eth0` | EUI-64: MAC 00:1a:2b:3c:4d:5e, privacy সতর্কতা |
| `100.64.1.1` | Shared Address Space (CGNAT), RFC 6598; online lookup প্রযোজ্য নয় |
| `010.1.1.1` | Leading zero অস্পষ্ট; inet_aton পড়ে 8.1.1.1 (CVE-2021-29921) |
| `ipfinder --active 8.8.8.8`, ভুল উত্তর | "Not confirmed. Nothing was sent." |

HTML report আর dashboard-এর ছবি: [html-report-example.png](html-report-example.png), [dashboard-example.png](dashboard-example.png)। পুরো demo: [DEMO.md](DEMO.md)।

---

## ৯. সীমাবদ্ধতা

- **Geolocation আনুমানিক।** সব source একমত হলেও সেটা address-এর network-এর অবস্থান, মানুষের নয়। VPN, Tor, Private Relay, CGNAT আর mobile network-এ সেটা আরও দুর্বল।
- **List আর database পুরোনো হতে পারে।** VPN list community-র বানানো। List-এ থাকা মানে network-টা পরিচিত, কোনো নির্দিষ্ট connection-এর প্রমাণ নয়। Tor-এর list-এ IPv6 নেই।
- **Threat listing মানে সন্দেহ, প্রমাণ নয়।** ভাগ করা address (CGNAT, cloud, VPN) অন্যদের ইতিহাস বয়ে বেড়ায়।
- **Free API-র শর্ত।** ip-api-র free tier শুধু HTTP দেয় (encrypted নয়) আর non-commercial। VirusTotal আর InternetDB-ও non-commercial।
- **Score-এর ওজন** plan-এ নির্ধারিত নিয়ম। বড় ডেটাসেটে মিলিয়ে calibrate করা হয়নি।
- আসল service-এর বিরুদ্ধে প্রথম চালানো বাকি (৭ নম্বর অংশ)।

---

## ১০. নৈতিকতা ও আইন

- Default-এ সব কাজ passive। Target কিছু টের পায় না।
- Active probe-এর শর্ত:
  - `--active` দিতে হয়, আর হুবহু `I AM AUTHORIZED` লিখতে হয়।
  - এক run-এ সর্বোচ্চ ২০টা address, শুধু public।
  - Port scan নেই।
- **বাংলাদেশ:** সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ (Ordinance No. 25 of 2025) 21 May 2025-এ কার্যকর হয়েছে, আর Cyber Security Act 2023 বাতিল করেছে। অনুমতি ছাড়া কোনো computer system-এ প্রবেশ বা হস্তক্ষেপ অপরাধ। জমা দেওয়ার আগে Gazette-এ সর্বশেষ অবস্থা দেখে নিতে হবে।
- **Privacy:**
  - `--offline` mode-এ কিছুই বাইরে যায় না।
  - `full` profile-এ address আরও ৭টা তৃতীয় পক্ষে যায়, তাই সেটা default-এ বন্ধ।
  - Cache local থাকে, `.gitignore`-এ আছে।
  - API key শুধু `.env`-এ থাকে, কখনো error বা report-এ আসে না।

---

## ১১. ভবিষ্যৎ কাজ

1. Internet-যুক্ত computer-এ প্রতিটা source-এর আসল response রেকর্ড করে test-এ যোগ করা (Phase 0-এর বাকি অংশ)।
2. পরিচিত location-এর address-এর একটা ছোট ডেটাসেট দিয়ে confidence score-এর ওজন যাচাই করা।
3. Hostname দিলে নিজে resolve করে সব address দেখা (এখন tool শুধু IP নেয়)।
4. Multi-vantage RTT, অর্থাৎ কয়েকটা জায়গা থেকে মেপে triangulation। এখন একটা vantage থেকে শুধু ঊর্ধ্বসীমা পাওয়া যায়।
5. বাংলা interface (এখন report English-এ, documentation বাংলায়)।

---

## ১২. উপসংহার

IP Finder v2 একটা address-এর তথ্য ২৭টা source থেকে এনে ১২টা স্তরে সাজায়। শুধু তথ্য দেখানোই এর মূল অবদান নয়। এটা দেখায় তথ্যগুলো কতটা বিশ্বাসযোগ্য, কোথায় source-রা একমত নয়, আর কী জানা সম্ভব নয়।

Tool-টা default-এ passive আর key ছাড়াই চলে। পুরো offline mode আছে, আর active probe শুধু স্পষ্ট অনুমতিতে চলে। ৬৩১টা test আর আসল browser-এ যাচাই project-টাকে নির্ভরযোগ্য করেছে। আসল service-এর বিরুদ্ধে প্রথম চালানোর কাজটা সৎভাবে বাকি হিসেবে চিহ্নিত।

---

## তথ্যসূত্র

**RFC ও registry**
- IANA IPv4 / IPv6 Special-Purpose Address Registries (RFC 6890): https://www.iana.org/assignments/iana-ipv4-special-registry/ , https://www.iana.org/assignments/iana-ipv6-special-registry/
- RFC 791 (IPv4), RFC 1918 (private), RFC 3056 (6to4), RFC 3180 (GLOP), RFC 4291 (IPv6 addressing, EUI-64), RFC 4380 ও RFC 5991 (Teredo), RFC 5737 ও RFC 9637 (documentation), RFC 6052 (NAT64), RFC 6598 (shared address space), RFC 8981 (temporary IPv6 addresses)
- RFC 9083 (RDAP), RFC 9224 (RDAP bootstrap), RFC 6811 (RPKI origin validation), RFC 8805 ও RFC 9632 (geofeed), RFC 5782 (DNSBL testing)
- CVE-2021-29921 (Python `ipaddress`, leading zeros): https://nvd.nist.gov/vuln/detail/CVE-2021-29921

**Data source**
- ip-api: https://ip-api.com/docs · IPinfo Lite: https://ipinfo.io/lite · MaxMind GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- RIPEstat: https://stat.ripe.net/ · Team Cymru IP to ASN: https://www.team-cymru.com/ip-asn-mapping · PeeringDB: https://docs.peeringdb.com/
- Shodan InternetDB: https://internetdb.shodan.io/ · AbuseIPDB: https://docs.abuseipdb.com/ · GreyNoise: https://docs.greynoise.io/ · VirusTotal: https://docs.virustotal.com/ · AlienVault OTX: https://otx.alienvault.com/api · abuse.ch: https://abuse.ch/ · Spamhaus: https://www.spamhaus.org/
- Tor exit list: https://check.torproject.org/torbulkexitlist · Apple Private Relay: https://mask-api.icloud.com/egress-ip-ranges.csv · AWS: https://ip-ranges.amazonaws.com/ip-ranges.json · X4BNet lists_vpn: https://github.com/X4BNet/lists_vpn

**Software ও map**
- Leaflet 1.9.4: https://leafletjs.com/ · Natural Earth: https://www.naturalearthdata.com/ · FastAPI: https://fastapi.tiangolo.com/ · Rich: https://rich.readthedocs.io/ · HTTPX: https://www.python-httpx.org/
- OpenStreetMap tile usage policy: https://operations.osmfoundation.org/policies/tiles/

**আইন**
- Cyber Security Ordinance 2025 (Bangladesh): https://digitalpolicyalert.org/event/38587-cyber-security-ordinance-2025-ordinance-no-25-of-2025-enters-into-force

সম্পূর্ণ plan ও source যাচাইয়ের তারিখ: [ADVANCED_PLAN.md](../ADVANCED_PLAN.md)।
