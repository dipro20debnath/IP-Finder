# IP Finder v2: demo script (viva ও presentation)

প্রায় **১০ মিনিটের** একটা live demo। প্রতিটা step-এ লেখা আছে কী চালাবেন, কী বলবেন আর screen-এ কোথায় দেখাবেন। চালানোর কাজটা `scripts/demo.py` করে দেয়: প্রতিটা step-এর command দেখায়, Enter চাপলে চালায়।

Demo-র দুটো পথ আছে:

| পথ | কখন | Command |
|---|---|---|
| **Online** | আপনার laptop-এ internet আছে | `python scripts/demo.py` |
| **Offline** | Wi-Fi নেই, ধীর, বা নির্ভরযোগ্য নয় | `python scripts/demo.py --offline` |

Offline পথে কোনো কিছু network-এ যায় না (নিচে "কেন offline-ও চলে" দেখুন)। এর location data আসে MaxMind-এর official **test** database থেকে (যেমন 81.2.69.142 = London), আসল GeoLite2 থেকে নয়। Demo-র শুরুতে এটা বলে দিন।

---

## আগের দিন: প্রস্তুতি

1. Repo folder-এ: `python -m pip install -e ".[dev]"` (dashboard আর test-এর জন্য যা লাগে সব এতে আছে)।
2. `.env`-এ যে key আছে বসান: `IPINFO_TOKEN`, MaxMind-এর `MAXMIND_ACCOUNT_ID` ও `MAXMIND_LICENSE_KEY`, আর threat intelligence-এর key-গুলো (ঐচ্ছিক; key না থাকলে সেই source "skipped" দেখায়)।
3. `ipfinder update-lists`: Tor, cloud, Private Relay, VPN list আর (MaxMind key থাকলে) GeoLite2 নামায়।
4. যাচাই: `python scripts/demo.py --check` আর `python scripts/demo.py --check --offline`। কিছু না থাকলে `FAIL` বা `note` দেখায়, সাথে কী করতে হবে।
5. পুরো একবার রিহার্সাল: `python scripts/demo.py`। Online ফলগুলো `data/cache.sqlite`-এ জমা থাকে, তাই viva-র দিন একই address দ্রুত আসে আর ip-api-র quota খরচ হয় না।
6. Backup যাচাই: `python scripts/demo.py --offline --yes --no-browser`। পুরো offline demo না থেমে চলে, শেষে `Demo finished. All steps ran.` দেখানোর কথা।
7. Terminal-এর font বড় করুন (Ctrl + `+`), browser খোলা রাখুন। Windows-এ পুরোনো console-এর বদলে Windows Terminal ভালো।

`demo.py` সবসময় নিজের Python দিয়ে `python -m ipfinder ...` চালায়, তাই virtual environment activate না করলেও চলে। তবে সেটা repo folder থেকে চালাতে হবে, কারণ `.env` আর `data/` সেখান থেকেই পড়া হয়।

---

## চালানোর সময়

```bash
python scripts/demo.py             # online
python scripts/demo.py --offline   # offline
python scripts/demo.py --from 8    # step 8 থেকে (যেমন সময় কম থাকলে)
python scripts/demo.py --list      # শুধু step-গুলোর তালিকা
```

প্রতিটা step-এ: Enter চাপলে চলে, `s` + Enter দিলে বাদ যায়, Ctrl+C দিলে থামে।

---

## Step-by-step

নিচের output-গুলো এই repo-তে **আসলেই চালানো** offline পথের output (সংক্ষেপিত)। Online পথের ফল দিন-তারিখ আর আপনার key-এর উপর নির্ভর করে, তাই সেখানে শুধু লেখা আছে কী খুঁজবেন।

### Step 1: এক address, অনেক স্তর (১.৫ মিনিট)

- Online: `ipfinder 8.8.8.8`
- Offline: `ipfinder --offline 81.2.69.142`

**বলুন:** "v1.0 শুধু ip-api থেকে শহর দেখাত। v2 একটা address-এর জন্য ২৭টা source জিজ্ঞেস করে: address-এর গঠন, location, network, registry, BGP, DNS, anonymity, threat intelligence। প্রতিটা তথ্যের সাথে থাকে কোথা থেকে এল, কতটা নির্ভরযোগ্য, আর কী জানা যায় না।"

**দেখান:**
- উপরের **Verdict** অংশ। Score কোনো probability নয়, স্বচ্ছ নিয়ম: প্রতিটা point কেন যোগ বা বিয়োগ হলো, তা `why` লাইনে লেখা।
- নিচের **Sources** অংশ, যেখানে প্রতিটা source `ok`, `skipped` বা `error`। একটা source fail করলে বাকিগুলো থামে না।

```text
│ Verdict                                                                      │
│   Connection type        Unknown                                             │
│   Location (consensus)   London, GB  (MaxMind radius 10 km)                  │
│   Location confidence    90/100 HIGH                                         │
│     why                  only one source gave coordinates, nothing to        │
│                          cross-check (-10)                                   │
│ Sources                                                                      │
│   ip-api (L2/L3/L7)     skipped: offline mode: this source would send the    │
│                         address over the network                             │
│   maxmind (L2/L3)       ok (1 ms)                                            │
```

### Step 2: Anycast, এক address অনেক জায়গায় (১ মিনিট)

- Online: `ipfinder 1.1.1.1`
- Offline: `ipfinder --offline 8.8.8.8`

**বলুন:** "8.8.8.8 একসাথে পৃথিবীর অনেক জায়গা থেকে announce হয়। আপনি সবচেয়ে কাছেরটায় পৌঁছান। তাই '8.8.8.8 কোথায়?' প্রশ্নের একটা উত্তর হয় না। Tool সেটা চেনে, location শুধু দেশ পর্যন্ত রাখে আর confidence থেকে 60 কাটে।"

```text
│   Connection type   Anycast service (Google Public DNS)  (from published     │
│                     lists)                                                   │
│     evidence        8.8.8.0/24 is Google Public DNS, a documented anycast    │
│                     service                                                  │
```

### Step 3: Teredo, IPv6-এর ভেতরে লুকানো IPv4 আর port (১ মিনিট)

- দুই পথেই: `ipfinder 2001:0:4136:e378:8000:63bf:f7f7:f7f7` (offline-এ `--offline` সহ)

**বলুন:** "Teredo address-এর ভেতরে client-এর আসল public IPv4 আর NAT port থাকে, bit উল্টে রাখা (RFC 4380)। এখানে কোনো database লাগে না, শুধু হিসাব। Tool তারপর online lookup চালায় ভেতরের IPv4-এর জন্য, IPv6-টার জন্য নয়।"

```text
│   Type                   Teredo  [2001::/32, RFC 4380]                       │
│   Online lookup target   8.8.8.8  (Using the IPv4 address embedded in this   │
│                          Teredo address (teredo_client, RFC 4380, RFC        │
│                          5991))                                              │
│ Embedded IPv4 (teredo_client)                                                │
│   IPv4                    8.8.8.8                                            │
│   Role                    client's public (NAT) IPv4                         │
│   Client port             40000                                              │
│ Embedded IPv4 (teredo_server)                                                │
│   IPv4                 65.54.227.120                                         │
│   Role                 Teredo server                                         │
```

### Step 4: EUI-64, IPv6 address-এ device-এর MAC (১ মিনিট)

- দুই পথেই: `ipfinder fe80::21a:2bff:fe3c:4d5e%eth0`

**বলুন:** "পুরোনো নিয়মে (SLAAC EUI-64) IPv6 address-এর শেষ 64 bit device-এর MAC থেকে বানানো হয়। তাই একই device-কে network বদলালেও চেনা যায়। এই কারণেই আধুনিক OS random (privacy) address ব্যবহার করে। `ff:fe` pattern কাকতালীয়ভাবে মেলার সম্ভাবনা 65,536-এ 1, তাই confidence high।"

```text
│ Interface identifier                                                         │
│   Type          eui64                                                        │
│   MAC address   00:1a:2b:3c:4d:5e                                            │
│   OUI           00:1a:2b                                                     │
│   Privacy       This MAC can identify and track the same device across       │
│                 networks                                                     │
│   Confidence    high (a random ID matches this pattern by chance 1 in        │
│                 65,536)                                                      │
```

### Step 5: CGNAT, একটা public IP মানে একজন মানুষ নয় (৪৫ সেকেন্ড)

- দুই পথেই: `ipfinder 100.64.1.1`

**বলুন:** "ISP অনেক গ্রাহককে একটা public IP-এর পেছনে রাখে। ভেতরে `100.64.0.0/10` (RFC 6598)। এই address internet থেকে দেখা যায় না, তাই tool online lookup-ই করে না। কাউকে 'এই IP থেকে এসেছে' বলে দোষ দেওয়ার আগে এটা মনে রাখা দরকার।"

```text
│   Type                   Shared Address Space (CGNAT)  [100.64.0.0/10, RFC   │
│                          6598]                                               │
│   Globally reachable     no                                                  │
│   Online lookup target   not applicable: Shared Address Space (CGNAT) (RFC   │
│                          6598) is not globally reachable, so public          │
│                          geolocation and registry data do not apply          │
```

### Step 6: সাবধানে input পড়া (৪৫ সেকেন্ড)

- দুই পথেই: `ipfinder lookup 010.1.1.1 0x7f000001 google.com` (exit code 1 এখানে স্বাভাবিক)

**বলুন:** "`010.1.1.1`-কে কিছু software octal হিসেবে পড়ে `8.1.1.1` বানায়। এই ধরনের পার্থক্য থেকে security bug হয়েছে (CVE-2021-29921)। Tool অনুমান না করে ব্যাখ্যা দেয়।"

```text
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

### Step 7: Threat intelligence (১.৫ মিনিট, শুধু online)

- `ipfinder --profile full 8.8.8.8`

**বলুন:** "এই source-গুলো চলে শুধু `full` profile-এ, কারণ তখন address-টা ৭টা তৃতীয় পক্ষের কাছে যায় আর তাদের free quota ছোট (VirusTotal দিনে 500টা)। Key না থাকলে source-টা 'skipped: no API key' দেখায়, crash করে না। Reputation (address থেকে খারাপ কিছু হয়েছে কিনা) আর exposure (কোন service খোলা আছে) আলাদা প্রশ্ন, তাই score-ও আলাদা।"

**দেখান:** Verdict-এর Reputation আর Exposure লাইন, প্রতিটার `why`। নিচে প্রতিটা source-এর নিজের উত্তর।

### Step 8: Report, map সহ HTML আর CSV (১.৫ মিনিট)

- Online: `ipfinder lookup 8.8.8.8 1.1.1.1 -f html -o demo-output/report.html` (তারপর একই address দিয়ে `-f csv`)
- Offline: `ipfinder lookup --offline 81.2.69.142 89.160.20.112 -f html -o demo-output/report.html`

`demo.py` HTML file-টা browser-এ খুলে দেয়।

**বলুন:** "পুরো report একটাই file, internet ছাড়াও খোলে। Map library আর দেশের সীমানা file-এর ভেতরেই আছে, তাই report খুললে কারো কাছে কোনো request যায় না। CSV Excel-এ খোলে, আর Excel যেন কোনো text-কে formula হিসেবে না চালায় সেই সুরক্ষা আছে।"

দেখতে কেমন: [html-report-example.png](html-report-example.png)

### Step 9: Web dashboard (১.৫ মিনিট)

- Online: `ipfinder serve --open`
- Offline: `ipfinder serve --offline --open`

Browser নিজেই খোলে। একটা address লিখুন (offline-এ `81.2.69.142`), "Look up" চাপুন। Demo থামাতে terminal-এ Enter চাপুন।

**বলুন:** "একই engine, browser থেকে। ফল একটা একটা করে আসে, প্রতিটার map থাকে, আর download button আছে। এটা আপনার API key দিয়ে চলে, তাই শুধু এই computer থেকে খোলা যায়, প্রতিবার নতুন token লাগে, আর অন্য website এটা ব্যবহার করতে পারে না।"

দেখতে কেমন: [dashboard-example.png](dashboard-example.png)

### Step 10: দায়িত্বশীল ব্যবহার, active probe-এ অনুমতি লাগে (৪৫ সেকেন্ড)

- Online: `ipfinder --active 8.8.8.8`
- Offline: `ipfinder --active 192.168.1.1` (private address, তাই অনুমতি দিলেও probe চলে না)

প্রশ্নের উত্তরে ইচ্ছা করে ভুল কিছু লিখুন। নিচের output এই repo-তে আসল terminal-এ (pseudo-terminal দিয়ে) চালিয়ে নেওয়া:

```text
[!] Active mode sends packets directly to the target (TCP handshakes on ports 443/80, ping, traceroute, a TLS handshake).
    Only scan systems you own or have written permission to test.
    Type 'I AM AUTHORIZED' to continue: yes please
[!] Not confirmed. Nothing was sent.
```

**বলুন:** "এতক্ষণের সবকিছু passive ছিল, target কিছু টের পায়নি। Active probe target-এ সরাসরি packet পাঠায়, তাই হুবহু phrase না লিখলে কিছুই যায় না। এক run-এ সর্বোচ্চ ২০টা address, শুধু public, আর port scan নেই। বাংলাদেশে সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫ অনুযায়ী অনুমতি ছাড়া কোনো system-এ হস্তক্ষেপ অপরাধ।"

### Step 11: মান যাচাই, test suite (৩০ সেকেন্ড)

- `python -m pytest -q`

**বলুন:** "সব test internet ছাড়া চলে: online source-গুলো fake HTTP আর fake DNS দিয়ে test হয়, MaxMind অংশ MaxMind-এর official test database দিয়ে। GitHub-এ প্রতিটা push-এ Python 3.10 থেকে 3.14 পর্যন্ত চলে।"

এই repo-তে শেষবার: **631 passed in ~13 s** (এর মধ্যে প্রায় ৭ সেকেন্ড লাগে পুরো offline demo চালিয়ে দেখতে)।

---

## কেন offline পথও চলে

`--offline` দিলে শুধু এই computer-এর source চলে: address-এর নিজের বিশ্লেষণ, GeoLite2 file, আর `update-lists` দিয়ে আগে নামানো list (Tor, cloud, VPN, Private Relay, Feodo, Spamhaus DROP)। বাকি সব source "offline mode" বলে skip হয়।

Test-এ যাচাই করা হয়েছে যে তখন একটাও HTTP request বা DNS query যায় না। পুরো offline demo একটা অচল proxy দিয়ে চালিয়েও দেখা হয়েছে: কোনো network চেষ্টা হলে "cannot reach" দেখাত, কিন্তু দেখায়নি। এটা শুধু demo-র সুবিধা নয়, privacy-রও: যে address দেখছেন তা কেউ জানতে পারে না।

---

## কিছু ভুল হলে

| সমস্যা | কী করবেন, কী বলবেন |
|---|---|
| Wi-Fi নেই বা খুব ধীর | Ctrl+C দিয়ে থামিয়ে `python scripts/demo.py --offline --from N`। বলুন: "tool offline-ও কাজ করে, এটাই এর privacy mode।" |
| কোনো source `error` দেখাচ্ছে | এটা design-এর অংশ: একটা source fail করলে বাকিগুলো চলে, আর কারণ লেখা থাকে। |
| ip-api-র limit (মিনিটে 45টা) | আগের রিহার্সালের ফল cache থেকে আসে। Tool নিজে কখনো limit পার হয় না। |
| Offline-এ `maxmind ... error: address not found` | স্বাভাবিক: MaxMind-এর test database-এ 8.8.8.8 নেই। |
| Browser খুলছে না | `demo-output/report.html` হাতে খুলুন। Dashboard-এর link terminal-এ লেখা থাকে। |
| Dashboard "token" চায় | Terminal-এর পুরো link (`#token=` সহ) আবার খুলুন। |
| Windows-এ বাংলা বা box অক্ষর ভাঙা | Windows Terminal ব্যবহার করুন। |

---

## ৫ মিনিটের ছোট version

Step 1, 3, 8, 9, 10:

```bash
python scripts/demo.py --from 1 --to 3   # step 2 "s" দিয়ে বাদ দিন
python scripts/demo.py --from 8 --to 10
```
