# data/

Downloaded datasets live here. Everything in this folder except this README is git-ignored.

| File | Used for | How to get it |
|---|---|---|
| `oui.csv` | Vendor name behind an EUI-64 IPv6 address (L1) | `curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv` (or download it in a browser) |

Later phases add more files here: the MaxMind GeoLite2 database, Tor exit list, cloud IP ranges and the lookup cache.
