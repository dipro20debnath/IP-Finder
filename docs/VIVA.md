# Viva প্রস্তুতি: প্রশ্ন ও উত্তর

মৌলিক ধারণার ১২টা প্রশ্ন (RDAP, ASN, BGP ও RPKI, anycast, CGNAT, FCrDNS, RTT, EUI-64, Geofeed, Private Relay, reputation বনাম exposure, কেন একাধিক source) [ADVANCED_PLAN.md §10](../ADVANCED_PLAN.md#10-advanced-viva-প্রশ্ন)-এ আছে। এখানে আছে **এই project-এর নিজস্ব** প্রশ্ন: কেন এভাবে বানানো, কীভাবে যাচাই করা, আর কী জানা যায় না।

প্রতিটা উত্তরের শেষে "কোথায়" দেওয়া আছে। Examiner code দেখতে চাইলে সেই file খুলুন।

---

## ক. ধারণা

**১. IP address থেকে কি কারো বাড়ি বা পরিচয় বের করা যায়?**
না। Geolocation বলে address-এর network কোথায়, মানুষ কোথায় নয়। CGNAT, VPN, Tor, mobile network-এ সেটা আরও দূরের। কোন customer কখন address-টা ব্যবহার করেছিল, তা শুধু ISP জানে, আর সেটা আইনি প্রক্রিয়ায় পাওয়া যায়। Tool এই কারণেই abuse contact দেখায়, আর প্রতিটা report-এ লেখে "An IP address does not identify a person"।

**২. Teredo address থেকে IPv4 আর port কীভাবে বের করেন?**
Teredo-র (RFC 4380) গঠন: প্রথম 32 bit prefix `2001::/32`, পরের 32 bit Teredo server-এর IPv4, তারপর 16 bit flag। এরপর 16 bit port আর শেষ 32 bit client-এর IPv4, দুটোই bit উল্টে রাখা (XOR `0xFFFF` আর `0xFFFFFFFF`)। `2001:0:4136:e378:8000:63bf:f7f7:f7f7`-এ:
- `4136:e378` = 65.54.227.120 (server)
- `63bf` XOR `ffff` = 40000 (port)
- `f7f7f7f7` XOR `ffffffff` = 8.8.8.8 (client)

কোথায়: `analysis/ipv6_insights.py`।

**৩. EUI-64 থেকে MAC কীভাবে পান, আর কতটা নিশ্চিত?**
Interface ID-র মাঝখানে `ff:fe` থাকলে সেটা MAC থেকে বানানো (RFC 4291 Appendix A)। `ff:fe` বাদ দিয়ে প্রথম byte-এর U/L bit (`0x02`) উল্টালে MAC পাওয়া যায়। একটা random ID-তে কাকতালীয়ভাবে `ff:fe` থাকার সম্ভাবনা 65,536-এ 1, তাই confidence "high", নিশ্চিত নয়। আধুনিক OS random address (RFC 8981) ব্যবহার করে, তখন MAC পাওয়া যায় না।

**৪. Python-এর `ipaddress.is_global` থাকতে নিজের table কেন?**
এটা কয়েকটা address-এ IANA registry-র সাথে মেলে না। পাঁচটা Python version-এ যাচাই করে পাওয়া গেছে:
- `5f00::1` (SRv6, RFC 9602) globally reachable নয়, অথচ Python বলে `True`।
- `2001:1::3` (RFC 9665) globally reachable, অথচ Python বলে `False`।
- `3fff::1` (documentation) Python 3.12.3-এ `True`, বাকিগুলোতে `False`।

একই input-এ version ভেদে ভিন্ন ফল একটা tool-এর জন্য গ্রহণযোগ্য নয়। কোথায়: `core/special_ranges.py`, README-র Phase 1 table।

**৫. RPKI "invalid" মানেই কি hijack?**
না। `invalid_asn` মানে কোনো ROA এই AS-কে অনুমতি দেয় না: hijack হতে পারে, আবার ভুল configuration-ও হতে পারে। `unknown` মানে কোনো ROA নেই, অর্থাৎ সুরক্ষিত নয়, কিন্তু ভুলও নয়। Tool প্রতিটা status-এর মানে লিখে দেয়। কোথায়: `providers/ripestat.py`।

**৬. Spamhaus PBL-এ থাকা মানে কি address খারাপ?**
না। PBL (`127.0.0.10/11`) মানে home বা dynamic line, যেখান থেকে সরাসরি mail যাওয়ার কথা নয়। এটা policy, abuse-এর চিহ্ন নয়। তাই reputation score-এ PBL গোনা হয় না। আরেকটা ফাঁদ: `127.255.255.254` মানে query public resolver দিয়ে গেছে আর Spamhaus উত্তর দিতে অস্বীকার করেছে। এটা listing নয়। কোথায়: `providers/spamhaus.py`।

---

## খ. Design

**৭. Orchestrator কেন stage-এ ভাগ করা?**
- Stage 0 (offline) আগে ঠিক করে online lookup আদৌ হবে কিনা, আর কোন address-এ (Teredo-র ভেতরের IPv4)।
- Stage 1-এর source-গুলো স্বাধীন, তাই একসাথে চলে।
- Stage 2-এর লাগে stage 1-এর তথ্য: PeeringDB-র ASN, Geofeed-এর RDAP link।
- Active probe সবার শেষে, যাতে অন্য traffic round-trip time নষ্ট না করে।

কোথায়: `core/orchestrator.py`।

**৮. একটা source fail করলে কী হয়?**
প্রতিটা provider আলাদাভাবে চলে, timeout সহ। Exception হলে সেই source-এর ফল হয় `error`, সাথে কারণ। বাকি source আর পুরো report চলতে থাকে। Code-এ bug থাকলেও report ভাঙে না, শুধু "unexpected ..." দেখায়। কোথায়: `core/orchestrator.py`-এর `_run`।

**৯. Cache কীভাবে কাজ করে?**
SQLite-এ `(provider, address)` key-তে রাখা হয়, প্রতিটা source-এর আলাদা TTL:
- reverse DNS: ১ ঘণ্টা
- RIPEstat: ৬ ঘণ্টা
- ip-api, IPinfo: ১ দিন
- RDAP, PeeringDB: ৭ দিন

Error শুধু ওই run-এর memory-তে থাকে, file-এ লেখা হয় না, তাই পরের run আবার চেষ্টা করে। অর্ধেক-সফল ফলও (যেমন RIPEstat-এর একটা অংশ fail) cache হয় না। কোথায়: `core/cache.py`।

**১০. ip-api-র 45/min limit কখনো ভাঙে না, কীভাবে নিশ্চিত?**
Sliding-window limiter (আধা সেকেন্ড margin সহ): শেষ 60.5 সেকেন্ডে 45টা request হলে পরেরটা অপেক্ষা করে। ip-api-র নিজের header (`X-Rl` বাকি সংখ্যা, `X-Ttl` কত সেকেন্ড পরে) আর HTTP 429 পেলে server যতক্ষণ বলে ততক্ষণ থামে। Limit-এর জন্য অপেক্ষার সময় provider-এর timeout-এ গোনা হয় না। Web dashboard সব tab-এর জন্য একই limiter ভাগ করে। কোথায়: `core/ratelimit.py`, `tests/test_ratelimit_cache.py`।

**১১. Profile তিনটা কেন?**
Privacy আর quota-র জন্য:
- `quick`: শুধু ip-api।
- `standard`: যেসব source-এ threat-intel key লাগে না।
- `full`: আরও ৭টা threat-intel service, যেখানে address তৃতীয় পক্ষে যায় আর free quota ছোট (VirusTotal দিনে 500টা)।

তাই `full` default নয়।

**১২. `--offline` ঠিক কী নিশ্চয়তা দেয়?**
শুধু `local` চিহ্নিত provider চলে: L1 বিশ্লেষণ, GeoLite2 file, আর `update-lists` দিয়ে আগে নামানো list। Test-এ fake network দিয়ে গোনা হয়েছে: একটাও HTTP request বা DNS query হয় না। পুরো offline demo একটা অচল proxy দিয়েও চালানো হয়েছে। কোথায়: `providers/base.py` (`local`), `tests/test_offline_mode.py`, `tests/test_demo.py`।

**১৩. Location confidence probability নয় কেন? Calibrate করেননি কেন?**
Calibrate করতে লাগে অনেক address-এর আসল জানা location, যা আমার কাছে ছিল না। তাই এটা plan-এর স্বচ্ছ নিয়ম: প্রতিটা point কেন, report-এ লেখা। এতে examiner বা user নিজে যাচাই বা দ্বিমত করতে পারেন। Calibration ভবিষ্যৎ কাজ। কোথায়: `analysis/scoring.py`।

**১৪. Geofeed আর Private Relay-কে ৩ ভোট কেন?**
এগুলো network-এর মালিক নিজে নিজের address সম্পর্কে প্রকাশ করে। Database-গুলো (MaxMind, ip-api, IPinfo) বাইরে থেকে অনুমান করে, তাই তাদের ১ ভোট। Geofeed-এর entry তখনই নেওয়া হয়, যখন সেটা geofeed-এর link দেওয়া registered network-এর ভেতরে পড়ে (RFC 9632)। নাহলে যে কেউ অন্যের address-এর location লিখে দিতে পারত। কোথায়: `analysis/geo.py`, `providers/geofeed.py`।

**১৫. একটা উদাহরণ দিয়ে confidence হিসাব দেখান।**
বাংলাদেশি mobile address, দুই source-এর মধ্যে 214 km পার্থক্য (ঢাকা থেকে চট্টগ্রাম):
- spread > 100 km: −25
- mobile network: −20

100 − 25 − 20 = **55, Medium**। এটা হুবহু test-এ আছে: `tests/test_analysis_engine.py`।

**১৬. Reputation আর exposure যোগ করেন না কেন? আর score "0" না দেখিয়ে কখনো লুকান কেন?**
একটা address পরিষ্কার হয়েও অনেক port খোলা রাখতে পারে, আবার উল্টোটাও হয়। যোগ করলে দুটো অর্থই হারিয়ে যায়। আর কোনো source না চললে score দেখানো হয় না, কারণ "0" মানে "কিছু পাওয়া যায়নি", "দেখা হয়নি" নয়।

**১৭. Speed-of-light check কেন শুধু ঊর্ধ্বসীমা?**
আলো fibre-এ প্রায় 200 km/ms যায়, তাই R ms round trip মানে সর্বোচ্চ R/2 × 200 km দূরে। কিন্তু পথ সোজা নয়, আর router delay যোগ করে, তাই আসল দূরত্ব প্রায়ই অনেক কম। ফলে এটা দিয়ে location বের করা যায় না। শুধু "এই location অসম্ভব" বলা যায়, তখন confidence থেকে 30 কাটা হয়। কোথায়: `analysis/rtt.py`।

**১৮. `192.0.2.1`-এ handshake কেন?**
এটা documentation-এর address (RFC 5737), internet-এ কখনো route হয় না। কেউ উত্তর দিলে বোঝা যায়, পথে একটা proxy বা firewall সবার হয়ে উত্তর দিচ্ছে। তখন TCP-এর সময় আর certificate target-এর নয়, তাই tool সেগুলো বাদ দেয়। এই সমস্যা সত্যিই development environment-এ পাওয়া গিয়েছিল: অস্তিত্বহীন `203.0.113.77`-ও 0.5 ms-এ "উত্তর" দিচ্ছিল। কোথায়: `active/probes.py`।

**১৯. Anycast কীভাবে চেনেন?**
তিনটা উৎস থেকে নিশ্চিত হয়:
- পরিচিত anycast DNS (Google, Cloudflare, Quad9, OpenDNS-এর address)।
- Cloudflare-এর range।
- AWS Global Accelerator (AWS নিজেই এগুলোকে "static anycast IP" বলে)।

Fastly-র range-কে "সম্ভবত" বলা হয়। Anycast হলে location শুধু দেশ পর্যন্ত, confidence −60। কোথায়: `analysis/anycast.py`।

---

## গ. নিরাপত্তা

**২০. Network-এর text terminal-এ দেখানো বিপজ্জনক কেন?**
Registry remark, hostname বা API বার্তায় ESC-এর মতো control character থাকতে পারে, যা terminal-এর রঙ, title বা লেখা বদলে দিতে পারে (escape-sequence injection)। `display_safe()` এগুলোকে `\x1b`-এর মতো লেখা হিসেবে দেখায়, কিন্তু বাংলা অক্ষর ঠিক রাখে। কোথায়: `core/text.py`।

**২১. CSV injection কী?**
কোনো cell `=`, `+`, `-` বা `@` দিয়ে শুরু হলে Excel সেটাকে formula হিসেবে চালায়, যেমন `=HYPERLINK(...)`। AS name-এর মতো text-এর আগে `'` বসানো হয়। কিন্তু আসল সংখ্যা, যেমন ঋণাত্মক longitude, সংখ্যাই থাকে। কোথায়: `output/csv_out.py`।

**২২. HTML report-এ XSS কীভাবে আটকান?**
চার স্তরে:
1. সব text HTML-escape করা হয়।
2. Map-এর label `textContent` দিয়ে বসে, HTML হিসেবে কখনো নয়।
3. Embedded JSON-এ `</` থাকলে `<\/` হয়ে যায়, যাতে data নিজের `<script>` বন্ধ করতে না পারে।
4. Content-Security-Policy শুধু দুটো script চালাতে দেয়, তাদের SHA-256 hash দিয়ে।

Test-এ `</script><img onerror=...>` নামের AS দিয়ে যাচাই করা হয়েছে। কোথায়: `output/html_report.py`, `tests/test_reports.py`।

**২৩. Dashboard তো localhost-এ, তাহলে নিরাপত্তা নিয়ে এত চিন্তা কেন?**
আপনার browser-এ খোলা যেকোনো website `127.0.0.1`-এ request পাঠাতে পারে। আর dashboard আপনার API key দিয়ে lookup চালায় (অনুমতি থাকলে active probe-ও)। তাই চারটা ব্যবস্থা:
1. **Token:** প্রতিবার চালু হলে নতুন, 192 bit।
2. **Host header যাচাই:** DNS rebinding আটকায়, অর্থাৎ কোনো site নিজের domain-কে `127.0.0.1`-এ point করলেও কাজ হয় না।
3. **Origin আর Sec-Fetch-Site যাচাই।**
4. **CORS নেই।** Authorization header থাকায় অন্য site-এর request-এ browser আগে preflight পাঠায়, আর server সেটা অনুমোদন করে না।

কোথায়: `web/app.py` (`Gate`)।

**২৪. Token URL-এর `#`-এর পরে কেন?**
URL-এর `#`-এর পরের অংশ browser কখনো server-এ পাঠায় না। তাই token server log বা proxy-তে থাকে না। Page সেটা পড়ে address bar থেকে মুছে দেয়, তারপর প্রতিটা request-এ header-এ পাঠায়।

**২৫. API key কীভাবে গোপন থাকে?**
Key শুধু `.env`-এ থাকে, আর `.env` `.gitignore`-এ। IPinfo-র token URL-এ যায়, তাই কোনো error বার্তায় URL লেখা হয় না। Fixture রেকর্ড করার script URL redact করে আর request header save করে না। কোথায়: `core/http.py`, `scripts/capture_fixtures.py`।

**২৬. Download করা list নষ্ট বা ভুয়া হলে?**
নতুন file আগে পুরো parse করে যাচাই হয়, তারপর পুরোনোটার জায়গায় বসে। তাই error page বা আধা-নামা file ভালো list নষ্ট করতে পারে না। MaxMind-এর download-এ checksum মেলানো হয়। Leaflet-এর file-এর hash npm registry-র published integrity-র সাথে মিলিয়ে নেওয়া হয়েছিল। কোথায়: `lists/store.py`, `lists/maxmind.py`।

**২৭. Port scan রাখেননি কেন?**
Plan অনুযায়ী port scan শুধু লিখিত অনুমতিতে চলতে পারে, আর বাংলাদেশে অনুমতি ছাড়া system-এ হস্তক্ষেপ অপরাধ (সাইবার সুরক্ষা অধ্যাদেশ, ২০২৫)। খোলা port-এর তথ্য Shodan InternetDB থেকে passively পাওয়া যায়, target কিছু টের পায় না।

---

## ঘ. Testing

**২৮. Internet ছাড়া online source কীভাবে test করলেন?**
`httpx`-এর MockTransport দিয়ে একটা fake internet (`FakeAPI`) আর একটা fake DNS resolver। প্রতিটা response-এর গঠন service-এর নিজের documentation বা official code থেকে নেওয়া। Test-এ কোনো real request গেলে সেটা "network is disabled" error দেয়। কোথায়: `tests/conftest.py`।

**২৯. আসল API দিয়ে test করেছেন?**
সৎ উত্তর: development environment থেকে বেশিরভাগ বাইরের service-এ পৌঁছানো যেত না। যেগুলো আসলে যাচাই হয়েছে:
- AWS-এর live list (17,570 prefix) আর X4BNet-এর list।
- MaxMind-এর official test database।
- Leaflet-এর hash।
- 128টা আসল CA certificate (নিজস্ব X.509 reader বনাম CPython)।

বাকি service আমার computer-এ প্রথমবার চলবে। `scripts/capture_fixtures.py` আসল response রেকর্ড করে, আর `scripts/demo.py --check` প্রস্তুতি দেখায়। এটা report-এর §৭-এ লেখা আছে।

**৩০. Browser-এ কীভাবে যাচাই করলেন?**
Playwright দিয়ে আসল Chromium:
- `scripts/check_html_report.py` report disk থেকে খোলে। দেখে প্রতিটা map আঁকা হয়েছে কিনা, error বা CSP violation আছে কিনা, network request গেছে কিনা।
- `scripts/check_dashboard.py` server চালু করে, address লিখে lookup করে, HTML download করে, আর token ছাড়া page খুলে দেখে।

মজার ঘটনা: Playwright-এর নিজের `wait_for_function`-ও dashboard-এর CSP-তে আটকে গিয়েছিল, কারণ সেটা `eval` ব্যবহার করে।

**৩১. CI-তে কেন Python 3.10 থেকে 3.14?**
3.10 এখনও সমর্থিত সবচেয়ে পুরোনো version, 3.14 সর্বশেষ। আর আসলেই version ভেদে পার্থক্য পাওয়া গেছে: `is_global`, আর `::ffff:8.8.8.8` লেখার ধরন (CPython 3.12.3 লেখে `::ffff:808:808`)।

---

## ঙ. সীমাবদ্ধতা ও নৈতিকতা

**৩২. VPN চেনা কতটা নির্ভরযোগ্য?**
সীমিত। VPN list community-র বানানো (X4BNet)। List-এ থাকা মানে network-টা VPN বা datacenter হিসেবে পরিচিত, কোনো নির্দিষ্ট connection VPN দিয়ে এসেছে তার প্রমাণ নয়। List-এ নেই এমন VPN ধরা পড়ে না। Tool তাই "listed VPN network" বলে, "এটা VPN" নয়।

**৩৩. কোনো address blocklist-এ থাকলে কি সে অপরাধী?**
না। Listing মানে কেউ এই address থেকে কিছু দেখেছে বা report করেছে। CGNAT, cloud, VPN-এর মতো ভাগ করা address অন্যদের ইতিহাস বয়ে বেড়ায়। VirusTotal-এ ১–২টা engine flag করা খুব সাধারণ। Tor exit-এর জন্য মাত্র +10, কারণ এটা ঝুঁকির সংকেত, অপরাধ নয়।

**৩৪. এই tool কি বিক্রি করা যাবে?**
এখনকার রূপে না। ip-api-র free tier, VirusTotal-এর public API আর Shodan InternetDB শুধু non-commercial কাজে free। Academic project-এর জন্য ঠিক আছে।

**৩৫. ip-api HTTP হওয়ায় সমস্যা কী?**
Free tier-এ HTTPS নেই। তাই পথের যে কেউ (Wi-Fi, ISP) দেখতে পারে আপনি কোন address খুঁজছেন। Sensitive কাজে `--offline` বা HTTPS source (IPinfo) ব্যবহার করা উচিত। Report-এও এটা বলা আছে।

---

## চ. দ্রুত প্রশ্ন

| প্রশ্ন | এক লাইনের উত্তর |
|---|---|
| 8.8.8.8 কোথায়? | একটা জায়গায় নয়: anycast, অনেক জায়গা থেকে announce হয় |
| Tool ভুল location দিলে? | Spread আর confidence দেখায়, সব source পাশাপাশি রাখে; `--active` দিলে speed-of-light check অসম্ভব location ধরে |
| MaxMind-এর accuracy radius কী? | MaxMind-এর নিজের দাবি: আসল অবস্থান এই বৃত্তের ভেতরে থাকার কথা; map-এ বৃত্ত হিসেবে আঁকা |
| Privacy address-এ MAC পাবেন? | না, সেগুলো random; শুধু `ff:fe` pattern-এ সম্ভব |
| কোনো key ছাড়া কী চলে? | L1, ip-api, MaxMind (file থাকলে), Team Cymru, RDAP, RIPEstat, reverse DNS, Geofeed, list, InternetDB |
| কত test? | 631টা, internet ছাড়া, Python 3.10–3.14 |
| Internet না থাকলে demo? | `python scripts/demo.py --offline`: কিছুই বাইরে যায় না |
| পরের কাজ? | আসল response রেকর্ড, score calibration, hostname resolve, multi-vantage RTT |
