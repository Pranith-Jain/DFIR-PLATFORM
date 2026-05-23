# DFIR Worker — IOC Reputation API

Cloudflare Worker that checks IP, domain, URL, and file-hash reputation across **15 providers** — 7 commercial (API-key) and 8 free / no-key.

## Quick start

```bash
cd dfir/worker
npm install
npx wrangler login           # one-time
npm run dev                  # local dev at http://127.0.0.1:8787
npm run deploy               # deploy to *.workers.dev
```

## Endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` or `/health` | Liveness |
| `GET` | `/api/providers/status` | Which providers are configured |
| `GET` | `/api/v1/ioc/check?indicator=<v>` | Check IOC (auto-detect type) |
| `POST` | `/api/v1/ioc/check` | Body: `{"indicator": "..."}` |

Auto-detected types: `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`. Defanged inputs (e.g. `8[.]8[.]8[.]8`, `hxxp://...`) are normalized.

### Example

```bash
curl 'https://<your>.workers.dev/api/v1/ioc/check?indicator=8.8.8.8'
```

```json
{
  "success": true,
  "indicator": "8.8.8.8",
  "type": "ipv4",
  "defanged": "8[.]8[.]8[.]8",
  "score": 0,
  "verdict": "clean",
  "tags": [],
  "sources": [ /* per-provider results */ ],
  "providers_queried": ["FeodoTracker", "Spamhaus", "TorExit", "URLScan"],
  "providers_skipped": ["VirusTotal", "AbuseIPDB", "..."]
}
```

## Providers

### Free / no-key (always on)

| Provider | IP | Domain | URL | Hash | Notes |
|---|:-:|:-:|:-:|:-:|---|
| Feodo Tracker | ✓ | | | | Botnet C2 IP blocklist |
| Spamhaus DROP/EDROP | ✓ | | | | Hijacked / malicious /CIDR ranges |
| Tor Exit list | ✓ | | | | Public Tor exit relays (informational) |
| Cloudflare DoH | | ✓ | | | DNS resolution, SPF/DMARC, NXDOMAIN |
| OpenPhish | | ✓ | ✓ | | Public phishing URL feed |
| URLScan.io | ✓ | ✓ | ✓ | | Search works without key (rate-limited) |

### Commercial (API key required)

| Provider | IP | Domain | URL | Hash | Free tier |
|---|:-:|:-:|:-:|:-:|---|
| VirusTotal | ✓ | ✓ | ✓ | ✓ | 4/min, 500/day |
| AbuseIPDB | ✓ | | | | 1,000/day |
| Shodan | ✓ | ✓ | | | Limited |
| GreyNoise | ✓ | | | | Community tier |
| OTX (AlienVault) | ✓ | ✓ | ✓ | ✓ | Free, generous |
| URLScan.io | ✓ | ✓ | ✓ | | 100/mo public |
| Pulsedive | ✓ | ✓ | ✓ | | 30/min |

### abuse.ch (one shared free Auth-Key)

Sign up at https://auth.abuse.ch and store **one** key as `ABUSECH_AUTH_KEY` to enable:

- ThreatFox — IP / domain / URL / hash IOC database
- URLhaus — active malware URLs
- MalwareBazaar — malware sample database (hashes)

## Configuring secrets

```bash
npx wrangler secret put VIRUSTOTAL_API_KEY
npx wrangler secret put ABUSEIPDB_API_KEY
npx wrangler secret put SHODAN_API_KEY
npx wrangler secret put GREYNOISE_API_KEY
npx wrangler secret put OTX_API_KEY
npx wrangler secret put URLSCAN_API_KEY
npx wrangler secret put PULSEDIVE_API_KEY
npx wrangler secret put ABUSECH_AUTH_KEY
```

For local dev, put them in `.dev.vars` instead (gitignored):

```
VIRUSTOTAL_API_KEY=...
ABUSECH_AUTH_KEY=...
```

## Optional: KV-backed cache

Public blocklists (Tor, Spamhaus, Feodo, OpenPhish) are cached for 1 hour. By default the request-scoped Cache API is used — works out of the box but caches per data center. For a globally shared cache, bind a KV namespace:

```bash
npx wrangler kv:namespace create DFIR_CACHE
# uncomment the [[kv_namespaces]] block in wrangler.toml and paste the id
```

## Scoring

Each provider returns:
- `score` — 0–100 maliciousness
- `weight` — confidence (0–1) used for the weighted aggregate
- `verdict` — `malicious | suspicious | clean | unknown`

The aggregate verdict is `malicious` if the weighted average is ≥ 70 OR any high-confidence (`weight ≥ 0.8`) provider flags it; `suspicious` ≥ 30; otherwise `clean`.
