# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository overview

This is the static site + backend source for **mylr.sh**, a security research site. It has two parts:

1. **`index.html`** — the standalone landing page for mylr.sh, deployed as-is (GitHub Pages via `CNAME`).
2. **`intel/`** — source for **DEIMOS / "The Daily Brief"**, a threat-intelligence aggregation platform. This directory is deployed separately to a server (EC2/nginx), not served directly from this repo. `robots.txt` disallows `/intel/` from being indexed on mylr.sh itself.

There is no build step, package manager, or test suite. This is hand-written HTML/CSS/vanilla JS on the frontend and a single-file Python script on the backend.

## Running the aggregator

```bash
cd intel
python3 aggregate_feeds_enhanced.py
# or from elsewhere:
python3 intel/aggregate_feeds_enhanced.py --project-dir /path/to/intel
```

Requires `feeds.json` to exist in the project directory (the script exits with an error otherwise). Output is written to `intel/output/`:
- `feed_data.json` — full article set + metadata (threat level, geo stats, feed stats) consumed by the dashboard and map frontends
- `archive/<YYYY-MM>.json` + `archive/index.json` — monthly rolling archive, deduplicated by article ID
- `summary.txt` — human-readable digest

Python dependencies (installed via `pip install --break-system-packages ...` in `install-daily-brief.sh`, no `requirements.txt` in this repo):
`feedparser`, `requests`, `geopy`, `python-dateutil`, `pycountry`, `beautifulsoup4`, `lxml`, `OTXv2`, `vt-py`. All of the API/geocoding integrations (`OTXv2`, `vt`, `geopy`) degrade gracefully — they're wrapped in `try/except ImportError` and the corresponding features (enrichment, geocoding) just no-op when the packages or API keys aren't present.

There is no automated test suite for the Python or JS code. Validate changes to `aggregate_feeds_enhanced.py` by running it and inspecting `output/feed_data.json` and `output/summary.txt`; validate frontend changes by opening `intel/the-daily-brief.html` / `intel/map.html` in a browser against a generated `feed_data.json`.

## Local secrets and generated files (not in this repo)

These files are referenced by the code but gitignored — they must be created locally/on-server and are never committed:
- `intel/api_keys.json` — optional API keys for OTX/VirusTotal/abuse.ch enrichment and the `ANTHROPIC_API_KEY` for the AI brief. All integrations run fine without it.
- `intel/output/`, `intel/data/` — generated at runtime (feed output, geocode/API caches).

## Architecture: the feed pipeline

Everything flows through `intel/aggregate_feeds_enhanced.py`, run on a schedule (cron, every 30 min in the reference deployment). It is one script, structured as several cooperating classes rather than a package — keep changes in this single-file style:

- **`FeedAggregator`** — the orchestrator. Reads `feeds.json` (feed definitions) and `platform_config.json` (thresholds/toggles), dispatches each enabled feed to one of three fetchers by `type`:
  - `rss` → `fetch_rss_feed` (feedparser)
  - `json_static` → `fetch_json_static` (e.g. CISA KEV — single GET, no auth)
  - `json_api` → `fetch_json_api` (GET or POST, optional `auth_key_ref` resolved against `api_keys.json`)
  
  JSON feeds are declarative: `field_mapping` in `feeds.json` uses `{field}` template interpolation (see `_interpolate_template`) and `response_path` (dot-separated) to navigate the response, so **adding a new JSON feed is just a `feeds.json` entry**, not new Python code — including structured IOC extraction, which is driven by an optional `structured_iocs` block on the feed entry (`cve_fields`, `hash_fields`, `url_fields`, `host_fields` for plain field→bucket mappings; `typed_ioc` for a value/type field pair like ThreatFox's `ioc`/`ioc_type`; `nested_hash_lists` for hashes nested in a sub-list like ThreatFox's `malware_samples`) consumed generically by `_extract_structured_iocs`. Both `fetch_json_static` and `fetch_json_api` catch broad `Exception` around entry parsing (matching `fetch_rss_feed`) so one malformed feed/entry can't take down the whole run; `main()` also has a top-level try/except so an unexpected failure exits cleanly instead of leaving a Python traceback with no clear signal.

- **`ThreatEnrichment`** — extracts IOCs (IPs/domains/hashes/CVEs/ATT&CK IDs) from article text via regex, then optionally enriches IPs/domains/hashes through AlienVault OTX and VirusTotal, disk-cached under `data/api_cache/`. Cache TTL, retry count, and per-request timeout come from `platform_config.json`'s `enrichment` section (`cache_duration_hours`, `max_retries`, `timeout_seconds`) rather than being hardcoded.

- **`GeocodingService`** — maps article text to a country/coordinates, first via a word-boundary match against `countries.json` (fast, offline), falling back to Nominatim geocoding only for high-confidence matches. In-process results are `lru_cache`d; geocoder-fallback results are also disk-cached under `data/geocode_cache/` (30-day TTL, toggled by `platform_config.json`'s `geocoding.cache_enabled`) so repeat cron runs don't re-hit Nominatim for the same location, and live Nominatim calls are throttled to respect its 1 req/sec usage policy. `extract_location_generic` filters out common false-positive words (months, generic security terms) before attempting a geocode.

- **Threat level** — the platform's headline threat indicator. `ThreatLevelCalculator.calculate()` derives a level purely from the aggregated articles using weighted factors (critical article count, active-exploit keyword hits, APT/malware article volume) against thresholds in `platform_config.json`'s `threat_level` section. Note the inverted severity scale: internal `ThreatLevelCalculator.THREAT_LEVELS` numbers 1 (most severe) → 5 (normal) — this used to be modeled on real-world DEFCON, but all DEFCON naming/branding (including a live scrape of a third-party "current DEFCON level" site) has been removed; it's purely an internally-calculated score now. Output/config keys are `threat_level`/`threat_level_details` (metadata) and `platform_config.json`'s `threat_level` section — **the frontend (`feed-dashboard.js`, `threat-map.js`) reads these with a fallback to the old `defcon_level`/`defcon_details` keys**, so that archive months saved before the rename (which live on the production server, not in this repo) still render correctly. Don't remove that fallback without a plan for migrating/backfilling those old archive files.

- Output pipeline: aggregate → filter by `max_age_hours` → deduplicate by article `id` (md5 of link+title, or feed-specific `id_field`) → sort by `(priority, published)` → compute threat level + geo stats → `save_output` writes `feed_data.json`, appends into the current month's archive (`save_archive`, dedup by id, also regenerates `archive/index.json`), and writes `summary.txt`.

## Architecture: the frontend

Vanilla JS, no framework, no bundler — `<script>` tags loading files directly.

- **`intel/the-daily-brief.html` + `feed-dashboard.js`** — the main dashboard. Fetches `output/feed_data.json` and renders it.
- **`intel/map.html` + `threat-map.js`** — the interactive Leaflet.js map (marker clustering + heatmap), reads the same `feed_data.json` (tries several relative paths, falls back to sample data if none load — see `ThreatMap.init`).
- **`intel/dashboard-enhancements.css` / `intel/threat-map.css`** — corresponding styles.

**Security convention — follow this for any frontend change**: all dynamic/external content is rendered via `textContent` or the `DOM.create()` safe-builder helper in `feed-dashboard.js`, never `innerHTML`. `Sanitize.searchQuery()` strips search input to a safe character set before use. When adding UI that renders feed/article data (which comes from third-party RSS/JSON sources), use the existing `DOM` helper rather than string-concatenated HTML.

## Deployment scripts (`intel/*.sh`)

These are ops tooling for the live server, not part of app logic:
- `install-daily-brief.sh` — full first-time installer for WSL/Linux (nginx, venv, cron, directory layout under `~/_x0mylr/intel/feeds`).
- `quick-deploy.sh` — one-command deploy from this flat repo layout to `~/daily-brief` / `/var/www/daily-brief` on a fresh box; installs from `install-daily-brief.sh` if present, wires up cron (`*/30 * * * *`) and nginx.
- `deploy-ec2.sh <domain> <email>` — Amazon Linux 2023-specific EC2 bring-up (installs to `/home/ec2-user/daily-brief`, provisions Let's Encrypt via certbot).
- `redeploy.sh` — run *on* the EC2 box after pushing to GitHub: `git pull`s this repo and syncs the web files (HTML/CSS/JS) and, if changed, the Python backend into the live install/web-root directories. Note the rename it performs: `the-daily-brief.html` → `index.html` in the deployed web root.

If you change a file under `intel/`, keep in mind it reaches production only via one of these scripts (or an EC2 `git pull` + `redeploy.sh`), not by pushing to this repo alone.
