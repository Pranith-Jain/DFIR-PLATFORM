import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

export const shodan: Provider = {
  name: "Shodan",

  isAvailable: (env) => !!env.SHODAN_API_KEY,

  supports: (type) => type === "ipv4" || type === "ipv6" || type === "domain",

  async check(indicator, type, env): Promise<ProviderResult> {
    const key = env.SHODAN_API_KEY;
    if (!key) return emptyResult("Shodan", { error: "no_api_key" });

    const url = type === "domain"
      ? `https://api.shodan.io/dns/domain/${encodeURIComponent(indicator)}?key=${key}`
      : `https://api.shodan.io/shodan/host/${encodeURIComponent(indicator)}?key=${key}`;

    let resp: Response;
    try {
      resp = await fetch(url);
    } catch (e) {
      return emptyResult("Shodan", { error: `network: ${(e as Error).message}` });
    }
    if (resp.status === 404) {
      return { provider: "Shodan", verdict: "clean", score: 0, weight: 0.3, tags: ["shodan-no-data"], details: {} };
    }
    if (!resp.ok) return emptyResult("Shodan", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    const vulns: string[] = Array.isArray(data.vulns) ? data.vulns : [];
    const ports: number[] = Array.isArray(data.ports) ? data.ports : [];
    const tags: string[] = [];
    if (vulns.length) tags.push("known-vulnerabilities");
    if (ports.length > 5) tags.push("many-open-ports");

    let score = 0;
    if (vulns.length) score = Math.min(80, 40 + vulns.length * 5);
    else if (ports.length > 5) score = 25;

    return {
      provider: "Shodan",
      verdict: score >= 70 ? "malicious" : score >= 25 ? "suspicious" : "clean",
      score,
      weight: 0.5,
      tags,
      details: {
        ip: data.ip_str,
        country: data.country_name,
        city: data.city,
        isp: data.isp,
        os: data.os,
        ports: ports.slice(0, 20),
        vulns: vulns.slice(0, 10),
        domains: Array.isArray(data.domains) ? data.domains.slice(0, 10) : [],
      },
    };
  },
};
