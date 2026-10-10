# Assets for HTML reports and the web dashboard

The HTML report embeds these files, so it is a single self-contained file: it works
offline, opened straight from disk, and viewing it sends nobody the locations it
shows. The web dashboard (`ipfinder serve`) serves the same files itself.

| File | What | Source | Licence |
|---|---|---|---|
| `leaflet.js`, `leaflet.css` | Leaflet 1.9.4 map library | npm `leaflet-1.9.4.tgz` (integrity sha512-nxS1ynzJ…FA74PA==, as published on registry.npmjs.org); SRI sha256-20nQCchB… (js) and sha256-p4NxAoJB… (css), identical to Leaflet's official files | BSD 2-Clause, see `LICENSE-leaflet.txt` |
| `world-110m.json` | Country outlines and 243 populated places | Natural Earth 1:110m admin 0 countries and populated places, compacted with `scripts/build_world_map.py` (names only, coordinates rounded to 0.01°) | Public domain (naturalearthdata.com) |
| `ipfinder-map.js`, `report.css` | IP Finder's own map drawing and report styles, shared by the HTML report and the web dashboard | This project | Same as IP Finder |

Country borders are Natural Earth's de facto boundaries; they are background
orientation only, not a statement about any border.
