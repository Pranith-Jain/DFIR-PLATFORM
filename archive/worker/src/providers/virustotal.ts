import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

const BASE = "https://www.virustotal.com/api/v3";

export const virustotal: Provider = {
  name: "VirusTotal",

  isAvailable: (env) => !!env.VIRUSTOTAL_API_KEY,

  supports: (type) =>
    type === "ipv4" || type === "ipv6" || type === "domain" || type === "url" ||
    type === "md5" || type === "sha1" || type === "sha256",

  async check(indicator, type, env): Promise<ProviderResult> {
    if (!env.VIRUSTOTAL_API_KEY) return emptyResult("VirusTotal", { error: "no_api_key" });

    let path: string;
    if (type === "ipv4" || type === "ipv6") {
      path = `/ip_addresses/${encodeURIComponent(indicator)}`;
    } else if (type === "domain") {
      path = `/domains/${encodeURIComponent(indicator)}`;
    } else if (type === "url") {
      const id = await urlIdBase64(indicator);
      path = `/urls/${id}`;
    } else {
      path = `/files/${encodeURIComponent(indicator)}`;
    }

    let resp: Response;
    try {
      resp = await fetch(`${BASE}${path}`, {
        headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, accept: "application/json" },
      });
    } catch (e) {
      return emptyResult("VirusTotal", { error: `network: ${(e as Error).message}` });
    }

    if (resp.status === 404) {
      return { provider: "VirusTotal", verdict: "clean", score: 0, weight: 0.4, tags: ["vt-unknown"], details: { status: 404 } };
    }
    if (!resp.ok) {
      return emptyResult("VirusTotal", { error: `http_${resp.status}` });
    }

    const json = (await resp.json()) as any;
    const attrs = json?.data?.attributes ?? {};
    const stats = attrs.last_analysis_stats ?? {};
    const malicious: number = stats.malicious ?? 0;
    const suspicious: number = stats.suspicious ?? 0;
    const harmless: number = stats.harmless ?? 0;
    const undetected: number = stats.undetected ?? 0;
    const total = malicious + suspicious + harmless + undetected;

    const score = total > 0 ? Math.min(100, Math.round(((malicious + suspicious * 0.5) / total) * 100 * 5)) : 0;
    const verdict = malicious >= 3 ? "malicious" : malicious + suspicious > 0 ? "suspicious" : total > 0 ? "clean" : "unknown";
    const tags: string[] = [];
    if (malicious > 0) tags.push("vt-malicious");
    if (suspicious > 0) tags.push("vt-suspicious");
    if (Array.isArray(attrs.tags)) tags.push(...attrs.tags.map((t: string) => `vt:${t}`).slice(0, 5));

    return {
      provider: "VirusTotal",
      verdict,
      score,
      weight: 0.9,
      tags,
      details: {
        malicious, suspicious, harmless, undetected, total,
        reputation: attrs.reputation,
        country: attrs.country,
        meaningful_name: attrs.meaningful_name,
      },
    };
  },
};

async function urlIdBase64(url: string): Promise<string> {
  // VirusTotal requires the URL ID to be the base64-url-encoded URL without padding.
  const data = new TextEncoder().encode(url);
  let bin = "";
  for (const b of data) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

