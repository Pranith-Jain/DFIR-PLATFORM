# DFIR Platform

> **Status:** Design archive. The shipped implementation now lives in the monorepo at [github.com/Pranith-Jain/Pranith-Jain.github.io](https://github.com/Pranith-Jain/Pranith-Jain.github.io) — this repo contains the original prototypes, design notes, and planning documents.

**Live:** [pranithjain.qzz.io/dfir](https://pranithjain.qzz.io/dfir) — 65+ tools, free, no signup.

---

## Evolution

This repo started as separate prototypes across multiple languages before consolidating into a single Cloudflare Worker deployment:

| Phase | What | Where it went |
|-------|------|---------------|
| 1 | Standalone Cloudflare Worker IOC checker (15 providers) | Rewritten into `api/src/providers/*` (now 24 providers) |
| 2 | Python FastAPI prototype (phishing analyzer, exposure scanner, file analyzer, threat intel feeds) | Reference only — logic ported to TypeScript/Hono |
| 3 | Next.js web frontend prototype | Replaced by React 18 + Vite + Tailwind in the monorepo |
| 4 | CLI tools | Reference only — functionality superseded by the web UI |

## What shipped

The monorepo now contains **three surfaces in one deploy:**

### DFIR Toolkit — 65+ tools
IOC/Hash Checker (24 sources, streaming), Malware Scanner, Phishing Analyzer, Domain/IP Reputation (19 DNSBLs via DoH), URL/Email Reputation, CVE Lookup (NVD/EPSS/KEV), STIX Viewer, Diamond Model, MITRE ATT&CK, YARA/Sigma Playground, and 55+ more.

### Threat Intel Platform — 20+ surfaces
Ransomware leak-site tracking, CVE/KCV feed, cross-source IOC correlation (18 feeds), Telegram/Reddit/Bluesky firehoses, auto-generated daily briefings, typosquat domain monitoring, actor timelines, and a 90+ source aggregation.

### Email Security Suite
BEC spoofability scoring with per-gap remediation records, email reputation with 19 DNSBL blacklist checks, phishing email header analysis, and DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT inspection.

### Key stats
- 24 IOC providers, 19 DNSBL sources
- 181 unit tests, 21 test files
- 0 API keys required (works with public sources only)
- 158 static assets, 760 KB total, 18ms worker startup
- WCAG 2.2 AA compliant, 100/100 Lighthouse

## Design documents still relevant here

- [DFIR-PLATFORM-PLAN.md](./DFIR-PLATFORM-PLAN.md) — original platform plan and architecture decisions
- [docs/](./docs) — detailed design specs for individual services
- [web/](./web) — Next.js frontend prototype (reference only)
- [api/](./api) — Python FastAPI prototype (reference only)

## Quick links

- **Live:** [pranithjain.qzz.io/dfir](https://pranithjain.qzz.io/dfir)
- **Threat Intel:** [pranithjain.qzz.io/threatintel](https://pranithjain.qzz.io/threatintel)
- **Source:** [github.com/Pranith-Jain/Pranith-Jain.github.io](https://github.com/Pranith-Jain/Pranith-Jain.github.io)
