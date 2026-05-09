import { detectType, defang, refang } from "./ioc/detect";
import { aggregate } from "./ioc/score";
import type { Env, Provider, ProviderResult } from "./providers/types";

import { virustotal } from "./providers/virustotal";
import { abuseipdb } from "./providers/abuseipdb";
import { shodan } from "./providers/shodan";
import { greynoise } from "./providers/greynoise";
import { otx } from "./providers/otx";
import { urlscan } from "./providers/urlscan";
import { pulsedive } from "./providers/pulsedive";
import { threatfox } from "./providers/threatfox";
import { urlhaus } from "./providers/urlhaus";
import { malwarebazaar } from "./providers/malwarebazaar";
import { feodo } from "./providers/feodo";
import { spamhaus } from "./providers/spamhaus";
import { tor } from "./providers/tor";
import { doh } from "./providers/doh";
import { phishtank } from "./providers/phishtank";

const ALL_PROVIDERS: Provider[] = [
  virustotal, abuseipdb, shodan, greynoise, otx, urlscan, pulsedive,
  threatfox, urlhaus, malwarebazaar, feodo, spamhaus, tor, doh, phishtank,
];

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

    const url = new URL(req.url);

    try {
      if (url.pathname === "/" || url.pathname === "/health") {
        return json({ ok: true, service: "dfir-worker", version: "0.1.0" });
      }
      if (url.pathname === "/api/providers/status") {
        return json({
          providers: ALL_PROVIDERS.map((p) => ({
            name: p.name,
            available: p.isAvailable(env),
          })),
        });
      }
      if (url.pathname === "/api/v1/ioc/check") {
        return await handleCheck(req, env, ctx);
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "internal", message: (e as Error).message }, 500);
    }
  },
};

async function handleCheck(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  let indicator: string | null = null;
  if (req.method === "GET") {
    indicator = new URL(req.url).searchParams.get("indicator");
  } else if (req.method === "POST") {
    try {
      const body = (await req.json()) as { indicator?: string };
      indicator = body.indicator ?? null;
    } catch {
      return json({ error: "invalid_json" }, 400);
    }
  } else {
    return json({ error: "method_not_allowed" }, 405);
  }

  if (!indicator) return json({ error: "missing_indicator" }, 400);

  const refanged = refang(indicator);
  const type = detectType(refanged);
  if (type === "unknown") {
    return json({ error: "unknown_ioc_type", indicator: refanged }, 400);
  }

  const candidates = ALL_PROVIDERS.filter((p) => p.supports(type) && p.isAvailable(env));

  const settled = await Promise.allSettled(
    candidates.map((p) => withTimeout(p.check(refanged, type, env, ctx), 8000, p.name)),
  );

  const results: ProviderResult[] = settled.map((s, i) => {
    const name = candidates[i].name;
    if (s.status === "fulfilled") return s.value;
    return { provider: name, verdict: "unknown", score: 0, weight: 0, tags: [], details: {}, error: s.reason?.message ?? "rejected" };
  });

  const agg = aggregate(results);

  return json({
    success: true,
    indicator: refanged,
    type,
    defanged: defang(refanged),
    score: agg.score,
    verdict: agg.verdict,
    tags: agg.tags,
    sources: results,
    providers_queried: candidates.map((p) => p.name),
    providers_skipped: ALL_PROVIDERS.filter((p) => p.supports(type) && !p.isAvailable(env)).map((p) => p.name),
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS_HEADERS },
  });
}

async function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return await Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`${label} timeout`)), ms)),
  ]);
}
