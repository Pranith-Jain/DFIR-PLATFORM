import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

/**
 * abuse.ch URLhaus — active malware distribution URLs.
 * Free with Auth-Key (https://auth.abuse.ch).
 */
export const urlhaus: Provider = {
  name: "URLhaus",

  isAvailable: (env) => !!env.ABUSECH_AUTH_KEY,

  supports: (type) => type === "url" || type === "domain" || type === "ipv4",

  async check(indicator, type, env): Promise<ProviderResult> {
    if (!env.ABUSECH_AUTH_KEY) return emptyResult("URLhaus", { error: "no_auth_key" });

    const body = type === "url"
      ? { url: indicator }
      : type === "domain"
        ? { host: indicator }
        : { host: indicator };

    let resp: Response;
    try {
      resp = await fetch(`https://urlhaus-api.abuse.ch/v1/${type === "url" ? "url" : "host"}/`, {
        method: "POST",
        headers: { "Auth-Key": env.ABUSECH_AUTH_KEY, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (e) {
      return emptyResult("URLhaus", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("URLhaus", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    if (data.query_status === "no_results") {
      return { provider: "URLhaus", verdict: "clean", score: 0, weight: 0.6, tags: [], details: {} };
    }
    if (data.query_status !== "ok") {
      return emptyResult("URLhaus", { error: data.query_status });
    }

    const isOnline = data.url_status === "online" || data.firstseen != null;
    const tags: string[] = ["urlhaus-hit"];
    if (Array.isArray(data.tags)) {
      for (const t of data.tags.slice(0, 5)) tags.push(`urlhaus:${String(t).toLowerCase()}`);
    }
    if (data.threat) tags.push(`threat:${String(data.threat).toLowerCase()}`);

    return {
      provider: "URLhaus",
      verdict: "malicious",
      score: isOnline ? 95 : 80,
      weight: 0.9,
      tags,
      details: {
        threat: data.threat,
        url_status: data.url_status,
        firstseen: data.firstseen,
        lastseen: data.lastseen,
        host: data.host,
        url_count: data.url_count,
      },
    };
  },
};
