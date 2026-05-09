import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

const BASE = "https://pulsedive.com/api";

export const pulsedive: Provider = {
  name: "Pulsedive",

  isAvailable: (env) => !!env.PULSEDIVE_API_KEY,

  supports: (type) => type === "ipv4" || type === "ipv6" || type === "domain" || type === "url",

  async check(indicator, _type, env): Promise<ProviderResult> {
    if (!env.PULSEDIVE_API_KEY) return emptyResult("Pulsedive", { error: "no_api_key" });

    const url = `${BASE}/info.php?indicator=${encodeURIComponent(indicator)}&pretty=0&key=${env.PULSEDIVE_API_KEY}`;
    let resp: Response;
    try {
      resp = await fetch(url);
    } catch (e) {
      return emptyResult("Pulsedive", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("Pulsedive", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    if (data?.error) {
      // "Indicator not found" -> treat as clean/unknown
      return { provider: "Pulsedive", verdict: "unknown", score: 0, weight: 0.3, tags: [], details: { error: data.error } };
    }

    const risk: string = (data.risk ?? "none").toLowerCase();
    const tags: string[] = Array.isArray(data.attributes?.protocol) ? [] : [];
    if (Array.isArray(data.threats)) {
      for (const t of data.threats.slice(0, 5)) tags.push(`pd:${String(t.name).toLowerCase()}`);
    }
    if (risk !== "none" && risk !== "unknown") tags.push(`pd-risk:${risk}`);

    const riskScore: Record<string, number> = {
      none: 0, unknown: 0, low: 25, medium: 55, high: 80, critical: 95, retired: 0,
    };
    const score = riskScore[risk] ?? 0;
    const verdict = score >= 70 ? "malicious" : score >= 25 ? "suspicious" : "clean";

    return {
      provider: "Pulsedive",
      verdict,
      score,
      weight: 0.7,
      tags,
      details: {
        risk,
        type: data.type,
        stamp_seen: data.stamp_seen,
        threats: (data.threats ?? []).slice(0, 3).map((t: any) => t.name),
      },
    };
  },
};
