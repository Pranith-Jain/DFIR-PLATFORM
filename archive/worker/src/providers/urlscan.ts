import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";
import { urlToHostname } from "../ioc/detect";

const BASE = "https://urlscan.io/api/v1";

export const urlscan: Provider = {
  name: "URLScan",

  // urlscan.io search works without an API key but is rate-limited.
  // We treat the key as optional but still use it when present.
  isAvailable: () => true,

  supports: (type) => type === "url" || type === "domain" || type === "ipv4",

  async check(indicator, type, env): Promise<ProviderResult> {
    let q: string;
    if (type === "url") {
      const host = urlToHostname(indicator);
      if (!host) return emptyResult("URLScan", { error: "bad_url" });
      q = `page.url:"${indicator}"`;
    } else if (type === "domain") {
      q = `page.domain:${indicator}`;
    } else {
      q = `page.ip:${indicator}`;
    }

    const url = `${BASE}/search/?q=${encodeURIComponent(q)}&size=5`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (env.URLSCAN_API_KEY) headers["API-Key"] = env.URLSCAN_API_KEY;

    let resp: Response;
    try {
      resp = await fetch(url, { headers });
    } catch (e) {
      return emptyResult("URLScan", { error: `network: ${(e as Error).message}` });
    }
    if (!resp.ok) return emptyResult("URLScan", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    const results: any[] = Array.isArray(data.results) ? data.results : [];
    const total: number = data.total ?? results.length;

    let malicious = 0;
    for (const r of results) {
      if (r?.verdicts?.overall?.malicious || r?.verdicts?.urlscan?.malicious) malicious++;
    }

    const score = malicious > 0 ? Math.min(100, 60 + malicious * 10) : total === 0 ? 0 : 5;
    const verdict = malicious > 0 ? "malicious" : total === 0 ? "unknown" : "clean";

    return {
      provider: "URLScan",
      verdict,
      score,
      weight: env.URLSCAN_API_KEY ? 0.7 : 0.4,
      tags: malicious ? ["urlscan-malicious"] : [],
      details: {
        total_results: total,
        malicious_results: malicious,
        latest_scan: results[0]?.task?.time,
        latest_url: results[0]?.task?.url,
        screenshot: results[0]?.screenshot,
      },
    };
  },
};
