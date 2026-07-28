# DFIR Platform

Interactive incident-response and threat-investigation toolkit. ~110 single-purpose tools (IOC enrichment, CVE lookup, EXIF / EVTX / PE / EML parsing, MITRE & ATLAS matrices, STIX builder, threat-actor knowledge base, rule converters, IAM / RBAC analyzers, and many more) wired to a Cloudflare Worker API.

**Live:** [pranithjain.qzz.io/dfir](https://pranithjain.qzz.io/dfir)

This repository is the `/dfir` slice extracted from the [pranithjain.qzz.io](https://pranithjain.qzz.io) monorepo. Everything that is not `/dfir/*` (portfolio, blog, threat-intel pages) has been stripped. The earlier Python / Next.js prototypes are preserved under [`archive/`](/Pranith-Jain/DFIR-PLATFORM/blob/main/archive) for historical reference.

## Stack

- React 18 + Vite (client bundle aliased to `preact/compat` for parse-time wins)
- TypeScript, Tailwind CSS
- Cloudflare Workers (API) — `worker/index.ts` + `api/src/*`
- Vitest for unit tests

## Layout

```
src/             React + Vite SPA (routes /dfir/*)
  pages/dfir/      ~110 tool pages, lazy-loaded
  components/      AppShell, dfir/, intel/, shared chrome
  data/dfir/       ATT&CK / ATLAS / wiki / actor data
  lib/, hooks/, services/
api/             Cloudflare Worker route handlers
worker/          Worker entry
migrations/      D1 schema
archive/         Earlier Python / Next.js prototypes (kept for history)
```

## Develop

```bash
npm install
npm run dev          # Vite on :5173, proxies /api -> :8787
npm run dev:api      # Wrangler on :8787
npm run test         # Vitest
npm run build        # client bundle
```

## Deploy

`npm run deploy` builds the client and ships it to Cloudflare via Wrangler. `wrangler.jsonc` carries the production binding config.

## License

MIT — see [LICENSE](/Pranith-Jain/DFIR-PLATFORM/blob/main/LICENSE).
