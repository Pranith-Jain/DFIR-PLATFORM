import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

export const greynoise: Provider = {
  name: "GreyNoise",

  isAvailable: (env) => !!env.GREYNOISE_API_KEY,

  supports: (type) => type === "ipv4",

  async check(indicator, _type, env): Promise<ProviderResult> {
    if (!env.GREYNOISE_API_KEY) return emptyResult("GreyNoise", { error: "no_api_key" });

    const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(indicator)}`;
    let resp: Response;
    try {
      resp = await fetch(url, { headers: { key: env.GREYNOISE_API_KEY, accept: "application/json" } });
    } catch (e) {
      return emptyResult("GreyNoise", { error: `network: ${(e as Error).message}` });
    }
    if (resp.status === 404) {
      return { provider: "GreyNoise", verdict: "clean", score: 0, weight: 0.3, tags: ["greynoise-no-data"], details: {} };
    }
    if (!resp.ok) return emptyResult("GreyNoise", { error: `http_${resp.status}` });

    const data = (await resp.json()) as any;
    const classification: string = data.classification ?? "unknown";
    const noise: boolean = !!data.noise;
    const riot: boolean = !!data.riot;

    let score = 0;
    let verdict: ProviderResult["verdict"] = "unknown";
    const tags: string[] = [];

    if (classification === "malicious") { score = 90; verdict = "malicious"; tags.push("greynoise-malicious"); }
    else if (classification === "benign" || riot) { score = 0; verdict = "clean"; tags.push("greynoise-benign"); }
    else if (noise) { score = 50; verdict = "suspicious"; tags.push("greynoise-noise"); }

    return {
      provider: "GreyNoise",
      verdict,
      score,
      weight: 0.7,
      tags,
      details: { classification, noise, riot, name: data.name, link: data.link },
    };
  },
};
