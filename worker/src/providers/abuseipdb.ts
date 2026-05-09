import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

export const abuseipdb: Provider = {
  name: "AbuseIPDB",

  isAvailable: (env) => !!env.ABUSEIPDB_API_KEY,

  supports: (type) => type === "ipv4" || type === "ipv6",

  async check(indicator, _type, env): Promise<ProviderResult> {
    if (!env.ABUSEIPDB_API_KEY) return emptyResult("AbuseIPDB", { error: "no_api_key" });

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose=`;
    let resp: Response;
    try {
      resp = await fetch(url, {
        headers: { Key: env.ABUSEIPDB_API_KEY, Accept: "application/json" },
      });
    } catch (e) {
      return emptyResult("AbuseIPDB", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("AbuseIPDB", { error: `http_${resp.status}` });

    const data = ((await resp.json()) as any).data ?? {};
    const score: number = data.abuseConfidenceScore ?? 0;
    const reports: number = data.totalReports ?? 0;

    const verdict =
      score >= 70 ? "malicious" :
      score >= 25 ? "suspicious" :
      reports > 0 ? "suspicious" : "clean";

    const tags: string[] = [];
    if (score >= 70) tags.push("high-abuse-confidence");
    if (data.isWhitelisted) tags.push("abuseipdb-whitelisted");
    if (data.usageType) tags.push(`usage:${String(data.usageType).toLowerCase().replace(/\s+/g, "-")}`);

    return {
      provider: "AbuseIPDB",
      verdict,
      score,
      weight: 0.85,
      tags,
      details: {
        abuseConfidenceScore: score,
        totalReports: reports,
        countryCode: data.countryCode,
        isp: data.isp,
        domain: data.domain,
        usageType: data.usageType,
        isWhitelisted: data.isWhitelisted,
      },
    };
  },
};
