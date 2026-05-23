import type { Provider, ProviderResult } from "./types";
import type { IOCType } from "../ioc/detect";
import { emptyResult } from "./types";

const BASE = "https://otx.alienvault.com/api/v1/indicators";

function pathFor(type: IOCType, indicator: string): string | null {
  switch (type) {
    case "ipv4": return `${BASE}/IPv4/${encodeURIComponent(indicator)}/general`;
    case "ipv6": return `${BASE}/IPv6/${encodeURIComponent(indicator)}/general`;
    case "domain": return `${BASE}/domain/${encodeURIComponent(indicator)}/general`;
    case "url": return `${BASE}/url/${encodeURIComponent(indicator)}/general`;
    case "md5":
    case "sha1":
    case "sha256":
      return `${BASE}/file/${encodeURIComponent(indicator)}/general`;
    default: return null;
  }
}

export const otx: Provider = {
  name: "OTX",

  isAvailable: (env) => !!env.OTX_API_KEY,

  supports: (type) => pathFor(type, "x") !== null,

  async check(indicator, type, env): Promise<ProviderResult> {
    if (!env.OTX_API_KEY) return emptyResult("OTX", { error: "no_api_key" });
    const url = pathFor(type, indicator);
    if (!url) return emptyResult("OTX", { error: "unsupported_type" });

    let resp: Response;
    try {
      resp = await fetch(url, { headers: { "X-OTX-API-KEY": env.OTX_API_KEY, accept: "application/json" } });
    } catch (e) {
      return emptyResult("OTX", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("OTX", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    const pulses: any[] = data?.pulse_info?.pulses ?? [];
    const pulseCount = pulses.length;
    const reputation: number = data.reputation ?? 0;

    const score = Math.min(100, pulseCount * 15 + Math.max(0, -reputation));
    const verdict = score >= 70 ? "malicious" : score >= 30 ? "suspicious" : "clean";

    const tagSet = new Set<string>();
    for (const p of pulses.slice(0, 5)) {
      for (const t of (p.tags ?? []).slice(0, 3)) tagSet.add(`otx:${String(t).toLowerCase()}`);
    }
    if (pulseCount > 0) tagSet.add("otx-pulse");

    return {
      provider: "OTX",
      verdict,
      score,
      weight: 0.7,
      tags: [...tagSet].slice(0, 10),
      details: {
        pulse_count: pulseCount,
        reputation,
        country: data.country_code,
        asn: data.asn,
        recent_pulse_names: pulses.slice(0, 3).map((p) => p.name),
      },
    };
  },
};
