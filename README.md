# DFIR Platform

Design notes, prototypes, and research for an open DFIR platform aimed at small teams who want analyst-grade tooling without paid subscriptions.

> **Status:** Most code here is prototype work. The shipped, deployed implementation now lives in the portfolio repo at [github.com/Pranith-Jain/Pranith-Jain.github.io](https://github.com/Pranith-Jain/Pranith-Jain.github.io) under `api/src/*` and `src/pages/dfir/*`. This repo is kept as the design trail.

**Live tools:** [pranithjain.qzz.io/dfir](https://pranithjain.qzz.io/dfir)

---

## What was prototyped here

| Folder | What it is | State |
|---|---|---|
| `worker/` | Standalone Cloudflare Worker IOC checker (15 providers). The original proof-of-concept for "do this on the edge with no backend." | **Superseded** by the portfolio integration |
| `api/` | Python FastAPI prototype: phishing analyzer, IOC providers, exposure scanner, file analyzer, wiki, intel feeds | Reference only |
| `cli/` | DFIR CLI scratch | Reference only |
| `web/` | Next.js prototype web frontend | Reference only |
| `docs/` | Design specs and planning notes | Live design trail |
| `DFIR-PLATFORM-PLAN.md` | Original platform plan: services, APIs, roadmap | Live design trail |

## The architecture that actually shipped

Everything in `worker/` and `api/` was rewritten and consolidated into the portfolio repo, where it now runs as a single Cloudflare Worker that serves both the React SPA and the `/api/v1/*` API.

| Concern | Where it lives in the deployed stack |
|---|---|
| 22 IOC providers (VT, AbuseIPDB, Shodan, OTX, URLScan, Hybrid Analysis, the abuse.ch trio, Feodo, Spamhaus, Tor, OpenPhish, DoH, Bitwire, Blocklist.de, Binary Defense, Ipsum, Phishing Army, CIRCL Hashlookup, TweetFeed, CINS Army) | portfolio:`api/src/providers/*` |
| IOC checker route with parallel SSE streaming + weighted scoring | portfolio:`api/src/routes/ioc.ts` + `api/src/lib/scoring.ts` |
| Domain / file / phishing / exposure routes | portfolio:`api/src/routes/{domain,file,phishing,exposure}.ts` |
| Subdomain takeover with 15 service fingerprints | portfolio:`api/src/routes/takeover.ts` |
| STIX 2.1 viewer (interactive graph) | portfolio:`src/pages/dfir/StixViewer.tsx` + `src/lib/dfir/stix-graph.ts` |
| Cyber threat map (geolocated choropleth across 7 IOC sources) | portfolio:`api/src/routes/threat-map.ts` + `src/pages/dfir/ThreatMap.tsx` |
| Dark web watch (15 feeds, persistent watchlist, regex search) | portfolio:`src/pages/dfir/DarkWeb.tsx` |
| MITRE ATT&CK matrix with technique drawer | portfolio:`src/pages/dfir/MitreMatrix.tsx` |
| Daily / weekly intel briefings (cron) | portfolio:`api/src/lib/briefing-builder.ts` + `api/src/routes/briefings.ts` |
| RSS proxy with SSRF allow-list (50+ hosts) | portfolio:`api/src/routes/feeds.ts` |
| KV caching (briefings) + Cache API caching (provider results, blocklists) | portfolio:`api/src/lib/cache.ts` + `api/src/lib/ratelimit.ts` |

## How to read this repo

Start with `DFIR-PLATFORM-PLAN.md` — that's the original design doc. Then:

- `worker/src/` — minimal-deps TypeScript implementation of an IOC checker on the edge. Useful as a self-contained reference if you want to build the same tool without bundling an entire React app.
- `api/` — Python implementation of a richer back-end (phishing analyzer, exposure scanner, etc.). Includes some logic that's not in the deployed Worker version (e.g. the `whois` library does TCP whois on port 43, which Workers can't do).
- `docs/superpowers/plans/` — staged implementation plans.

## Why two repos

| Concern | Resolution |
|---|---|
| Portfolio (the public site) deploys frequently and needs to push to a custom domain | Lives in `Pranith-Jain.github.io`, deployed via `wrangler deploy` |
| Long-form design specs and prototype code | Live here, decoupled from the deploy cadence |
| Prototype work that experiments with stacks (Python FastAPI, Next.js) without committing to them in production | Live here |

## Contributing

PRs against the deployed implementation should go to the portfolio repo. Issues / design discussion belong here.

## License

Source files are MIT unless the file headers say otherwise.
