import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

/**
 * abuse.ch ThreatFox — IOC database covering IP / domain / URL / hash.
 * Free, but as of 2024 abuse.ch unified API requires an Auth-Key (free at https://auth.abuse.ch).
 * If ABUSECH_AUTH_KEY is unset, this provider is skipped.
 */
export const threatfox: Provider = {
  name: "ThreatFox",

  isAvailable: (env) => !!env.ABUSECH_AUTH_KEY,

  supports: (type) =>
    type === "ipv4" || type === "ipv6" || type === "domain" ||
    type === "url" || type === "md5" || type === "sha1" || type === "sha256",

  async check(indicator, _type, env): Promise<ProviderResult> {
    if (!env.ABUSECH_AUTH_KEY) return emptyResult("ThreatFox", { error: "no_auth_key" });

    let resp: Response;
    try {
      resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
        method: "POST",
        headers: { "Auth-Key": env.ABUSECH_AUTH_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "search_ioc", search_term: indicator }),
      });
    } catch (e) {
      return emptyResult("ThreatFox", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("ThreatFox", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    if (data.query_status === "no_result" || data.query_status === "ok" && !data.data?.length) {
      return { provider: "ThreatFox", verdict: "clean", score: 0, weight: 0.5, tags: [], details: {} };
    }
    if (data.query_status !== "ok") {
      return emptyResult("ThreatFox", { error: data.query_status });
    }

    const items: any[] = data.data ?? [];
    const malwareSet = new Set<string>();
    let maxConfidence = 0;
    for (const it of items.slice(0, 10)) {
      if (it.malware) malwareSet.add(String(it.malware));
      maxConfidence = Math.max(maxConfidence, Number(it.confidence_level) || 0);
    }

    const tags: string[] = [];
    for (const m of [...malwareSet].slice(0, 5)) tags.push(`malware:${m.toLowerCase()}`);
    tags.push("threatfox-hit");

    return {
      provider: "ThreatFox",
      verdict: "malicious",
      score: Math.max(70, maxConfidence),
      weight: 0.85,
      tags,
      details: {
        match_count: items.length,
        malware: [...malwareSet].slice(0, 5),
        confidence_level: maxConfidence,
        first_seen: items[0]?.first_seen,
        last_seen: items[0]?.last_seen,
      },
    };
  },
};
