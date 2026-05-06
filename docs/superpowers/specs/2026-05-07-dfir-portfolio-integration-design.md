# DFIR Toolkit + Portfolio Integration — Design

**Date:** 2026-05-07
**Owner:** Pranith Jain
**Status:** Draft for review

## 1. Goal

Merge the DFIR Platform (currently `dfir/` with Next.js frontend + FastAPI backend) and the personal portfolio (currently `Pranith-Jain.github.io`, Next.js on Cloudflare Workers) into a single Next.js application served from `pranithjain.qzz.io`.

The toolkit lives at `/dfir` and all 5 tools (IOC checker, phishing analyzer, domain lookup, exposure scanner, file analyzer) work live against real threat-intel APIs. New functionality (dashboard, shareable results, theme, MITRE ATT&CK tagging, PDF export) and infrastructure improvements (SSE streaming, KV caching) are added on top of the original plan.

## 2. Architecture

### 2.1 Topology

One repo, one Cloudflare Worker. The existing `dfir/web` Next.js 16 app becomes the unified portfolio + DFIR site.

- **Repo strategy:** the existing `dfir` repo is renamed and adopted as the new portfolio repo. Portfolio content from `Pranith-Jain.github.io` is migrated into `app/(portfolio)/...`. The old portfolio repo is archived after cutover.
- **Build adapter:** `@opennextjs/cloudflare` — official Next.js 16 App Router path on Cloudflare Workers.
- **Domain:** `pranithjain.qzz.io` resolves to the new Worker. DNS unchanged.
- **The existing `api/` Python (FastAPI) directory is deleted** after logic is ported to TypeScript route handlers. No dual stack.

### 2.2 Cloudflare bindings (`wrangler.toml`)

| Binding | Type | Purpose | Notes |
|---|---|---|---|
| `KV_CACHE` | KV namespace | Threat-intel response cache | TTL 1h–24h by indicator type |
| `KV_SHARES` | KV namespace | Shared-result snapshots + recent-lookups history | TTL 30d (recent), 90d (shares) |
| `R2_FILES` | R2 bucket | File analyzer uploads | 10MB limit, hash-only mode default |
| `RL_API` | Rate limit | `/api/v1/*` abuse protection | 30 req/min/IP |

### 2.3 Secrets (`wrangler secret put`)

`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `HYBRID_ANALYSIS_API_KEY`, `PULSEDIVE_API_KEY`. Never committed.

## 3. Routes & sitemap

### 3.1 Portfolio routes (`app/(portfolio)/...`)

```
/                       portfolio home (migrated from Pranith-Jain.github.io)
/about                  about page
/projects               projects index
/projects/[slug]        project case-study (one of these is the DFIR write-up)
/contact                contact page
```

### 3.2 DFIR routes (`app/dfir/...`)

```
/dfir                   landing — tool grid + recent activity + intro
/dfir/ioc-check         IOC checker UI
/dfir/phishing          phishing email analyzer UI
/dfir/domain            domain lookup UI
/dfir/exposure          exposure scanner UI
/dfir/file              file analyzer UI
/dfir/wiki              knowledge base index (5 categories)
/dfir/wiki/[slug]       wiki article (statically generated for SEO)
/dfir/dashboard         recent lookups (anonymous, cookie-keyed)
/dfir/r/[id]            shared result page (read-only)
```

### 3.3 API routes (`app/api/v1/...`)

```
GET  /api/v1/ioc/check?indicator=…    SSE stream, per-provider results
POST /api/v1/phishing/analyze
GET  /api/v1/domain/lookup?domain=…
GET  /api/v1/exposure/scan?domain=…   SSE stream
POST /api/v1/file/analyze              hash-mode + optional upload
GET  /api/v1/wiki/articles
GET  /api/v1/wiki/[slug]
POST /api/v1/share                     returns short id
GET  /api/v1/share/[id]
GET  /api/v1/recent                    last 20 lookups for cookie uid
GET  /api/v1/export/pdf?share_id=…     PDF download
```

## 4. Backend

### 4.1 Layout

```
lib/
  providers/
    virustotal.ts
    abuseipdb.ts
    shodan.ts
    greynoise.ts
    otx.ts
    urlscan.ts
    hybridanalysis.ts
    pulsedive.ts
  scoring.ts        composite-score algorithm (port of providers.py:calculate_score)
  cache.ts          KV cache wrapper, per-type TTL, stale-while-revalidate
  mitre.ts          provider-tag → ATT&CK technique map
  share.ts          encode/decode share-link payloads
  indicator.ts      type detection + defang/refang helpers
content/
  wiki/*.mdx        wiki articles (migrated from wiki_data.py)
```

### 4.2 Provider adapter contract

Every adapter exports the same shape so the IOC route can fan out and combine results:

```ts
export async function query(
  indicator: { type: 'ipv4'|'ipv6'|'domain'|'url'|'hash'|'email'; value: string },
  env: Env
): Promise<ProviderResult>;

type ProviderResult = {
  source: 'virustotal' | 'abuseipdb' | 'shodan' | 'greynoise' | 'otx'
        | 'urlscan' | 'hybridanalysis' | 'pulsedive';
  status: 'ok' | 'error' | 'unsupported';
  score: number;            // 0-100, normalized
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  raw_summary: object;      // flat fields for the UI
  tags: string[];           // feeds MITRE mapping
  fetched_at: string;       // ISO timestamp
  cached: boolean;
};
```

Each adapter handles its own auth header, error mapping, normalization, and timeout (5s default).

### 4.3 Composite scoring (`lib/scoring.ts`)

Weighted average per indicator type — for an IP, AbuseIPDB and GreyNoise weigh more than hash-focused sources; for a hash, VT and Hybrid Analysis dominate. Port the existing `calculate_score` logic from `api/providers.py`. Add a confidence band derived from the count of providers that responded `ok` vs `error`.

### 4.4 Caching (`lib/cache.ts`)

- **Key:** `sha256(provider:indicator_value)`
- **TTL:** hashes 24h, domains 6h, IPs 1h, URLs 1h
- **Hit:** return cached result immediately, set `cached: true`
- **Miss:** query provider, write to KV, return
- **Stale-while-revalidate (SSE only):** emit cached result instantly, kick off refresh in background, emit a second event if the refreshed result differs

### 4.5 SSE streaming (IOC + Exposure)

The route handler returns a `ReadableStream` with `Content-Type: text/event-stream`. Frontend uses `EventSource` to render provider cards in three states (`pending` → `result` / `error`). Fast (cached) providers appear within ~200ms; slow ones don't block the others.

### 4.6 Anti-abuse

- Cloudflare rate-limit binding: 30 req/min/IP on `/api/v1/*`
- Per-provider circuit breaker: two consecutive 401/403 responses within 5 min mark the provider unhealthy in KV for 15 min; further requests short-circuit
- Input hardening: payloads >10kB rejected, email bodies truncated to 64kB, file uploads capped at 10MB

### 4.7 Workers caveats (deliberately accepted)

- **30s CPU limit per request** — fine for a fan-out of 8 provider calls (each ~1–3s)
- **Exposure scanner** does not run nmap; it stays a wrapper around Shodan/Censys/passive-DNS, identical to current Python behavior
- **File analyzer** is hash-only by default. Optional drag-drop upload writes to R2, server computes SHA-256, queries by hash. No actual sandbox detonation — third-party only.

## 5. New features

### 5.1 Recent lookups dashboard (`/dfir/dashboard`)

- Anonymous, cookie-keyed (random 16-byte id stored in `dfir_uid` cookie)
- KV stores last 20 lookups per uid, TTL 30 days
- UI lists indicator, verdict chip, score, age, "re-run" button
- No login. Clearing cookies clears history.

### 5.2 Shareable result links (`/dfir/r/[id]`)

- "Share" button on any result page → POST `/api/v1/share` with the result snapshot → returns short id (e.g. `r/Xk2P9q`)
- KV stores the snapshot, TTL 90 days
- Read-only page, no recompute, "Re-run live" CTA links back to the tool with prefilled input
- Open Graph image generated via `next/og` in a Workers route so links unfurl on Twitter/LinkedIn

### 5.3 Dark/light theme

- Tailwind v4 with CSS variables, `<html data-theme="…">` toggle
- System preference default, manual override stored in `localStorage`
- Toggle in DFIR layout header

### 5.4 MITRE ATT&CK tagging (`lib/mitre.ts`)

- Static map: provider tag → ATT&CK technique id (e.g. URLScan `phishing` → `T1566.002`, VirusTotal `cryptominer` → `T1496`)
- Result UI renders ATT&CK chips with links to mitre.org technique pages
- Map-based only — no inference beyond what the map covers, to avoid false attribution

### 5.5 PDF export

- "Export PDF" button on result and share pages → `/api/v1/export/pdf?share_id=…`
- Implementation: `@react-pdf/renderer` server-side in the Worker (no external service, no extra cost)
- PDF contents: header, indicator, composite verdict, per-provider rows, MITRE chips, timestamp
- Pixel-perfect Cloudflare Browser Rendering integration is **out of scope** (paid feature; revisit later)

## 6. Improvements

- **Streaming via SSE** (§4.5)
- **KV caching with per-type TTL** (§4.4)
- **Stale-while-revalidate** for SSE flows (§4.4)
- **Optimistic UI** — defanged echo + indicator type detection runs client-side instantly while providers load
- **Skeleton loaders + error boundaries** on every tool page
- **Bulk IOC mode** — paste up to 50 indicators on `/dfir/ioc-check`; internal queue runs concurrency=5; results stream in as each finishes. Triggered automatically when input contains multiple lines.

## 7. Out of scope

Listed explicitly to keep scope tight:

- User accounts, login, OAuth — anonymous + cookie is enough for a portfolio piece
- Credit / billing system — drop "Phase 3 Enterprise" from the original `DFIR-PLATFORM-PLAN.md`
- Real port scanning, sandbox detonation, malware execution — third-party APIs only
- Mobile app
- CLI tool (`dfir-cli`)
- Self-hosted variant
- Cloudflare Browser Rendering integration for PDFs

## 8. Migration phases

| # | Phase | Scope | Acceptance |
|---|---|---|---|
| 0 | Foundation | `@opennextjs/cloudflare` setup, `wrangler.toml`, KV/R2 bindings, secret placeholders, dev/prod envs | `wrangler dev` serves the existing one-page Next.js app on a `*.workers.dev` URL |
| 1 | Portfolio migration | Pull `/`, `/about`, `/projects`, `/contact` content from `Pranith-Jain.github.io` into `app/(portfolio)/...`. Set up portfolio layout. | New Worker URL renders portfolio with visual + content parity to current site (manual diff sign-off on each route) |
| 2 | Provider adapters + IOC tool | Port `providers.py` → `lib/providers/*.ts`, scoring, caching, IOC route handler with SSE, IOC checker UI | `/dfir/ioc-check` works live with VirusTotal + AbuseIPDB + GreyNoise at minimum; cache hit returns < 200ms |
| 3 | Remaining adapters + tools | Shodan, OTX, URLScan, Hybrid Analysis, Pulsedive. Build phishing, domain, exposure, file analyzer UIs + routes | All 5 tool pages return live data from ≥ 2 providers each on cold cache; ≥ 1 of those providers must be currently in good health |
| 4 | Wiki | Migrate `wiki_data.py` content → `content/wiki/*.mdx`. Build index + article pages with `generateStaticParams` | `/dfir/wiki` lists 5 categories, articles render and are crawlable |
| 5 | New features (B) | Dashboard, share links, theme toggle, MITRE chips, PDF export | Each feature has at least one happy-path test |
| 6 | Polish & cutover | Rate limiting, circuit breakers, OG images, SEO metadata, error boundaries, delete `api/` Python code, archive old portfolio repo, point `pranithjain.qzz.io` at new Worker | Lighthouse ≥ 90 on `/` and `/dfir`; all tool pages return data with p95 < 3s |

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Provider free-tier quota exhaustion | KV cache + circuit breaker + rate limit on `/api/v1/*` |
| API key leak via misconfigured env | Secrets via `wrangler secret put` only; `.dev.vars` gitignored; pre-commit hook scans for known key prefixes |
| Cloudflare Worker 30s CPU limit | Per-provider 5s timeout; SSE streams partial results so a stuck provider doesn't kill the request |
| File upload abuse | 10MB cap, content-type validation, hash-only default mode |
| Shared result links leaking sensitive data | Snapshots are explicit user action; expire after 90 days; no PII in shares |
| Migration breaks live portfolio at `pranithjain.qzz.io` | Cut over via Cloudflare gradual deployment (10% → 100%); keep old Worker deployable as rollback for 7 days |

## 10. Success criteria

- `pranithjain.qzz.io/` serves the migrated portfolio with parity to today
- `pranithjain.qzz.io/dfir/<tool>` serves all 5 tools with live results
- Wiki indexed by Google within 4 weeks of cutover
- p95 tool response time < 3s with cache warm
- Zero secrets in git history
- Old `Pranith-Jain.github.io` repo archived; old `api/` directory deleted from this repo
