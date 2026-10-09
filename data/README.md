# data/

Downloaded datasets and the lookup cache live here. Everything in this folder except
this README is git-ignored. Paths are relative to the folder you run `ipfinder` from;
override them in `.env` (see `.env.example`).

| File | Used for | How to get it |
|---|---|---|
| `GeoLite2-City.mmdb` | City, coordinates, accuracy radius, time zone (MaxMind provider) | Free MaxMind account, then download "GeoLite2 City" in **MaxMind DB (.mmdb)** format from your account page, or use MaxMind's `geoipupdate` tool |
| `GeoLite2-ASN.mmdb` | ASN and network owner (MaxMind provider) | Same as above, edition "GeoLite2 ASN" |
| `oui.csv` | Vendor name behind an EUI-64 IPv6 address (L1) | `curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv` (or download it in a browser) |
| `cache.sqlite` | Cached online lookups (created automatically) | `ipfinder cache info`, `ipfinder cache clear`; `--no-cache` skips it |

MaxMind updates GeoLite2 regularly; an old database gives old answers. The report shows
each database's build date.

Later phases add more files here: the Tor exit list, cloud IP ranges and more.
