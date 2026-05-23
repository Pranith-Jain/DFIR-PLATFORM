import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";
import { getCachedText } from "../lib/cache";

const URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";

/**
 * abuse.ch Feodo Tracker — botnet C2 IP blocklist.
 * Truly free, no auth required (public download).
 */
export const feodo: Provider = {
  name: "FeodoTracker",

  isAvailable: () => true,

  supports: (type) => type === "ipv4",

  async check(indicator, _type, env, ctx): Promise<ProviderResult> {
    const text = await getCachedText(URL, env, ctx);
    if (!text) return emptyResult("FeodoTracker", { error: "fetch_failed" });

    const set = parseList(text);
    const hit = set.has(indicator);

    return {
      provider: "FeodoTracker",
      verdict: hit ? "malicious" : "clean",
      score: hit ? 90 : 0,
      weight: hit ? 0.9 : 0.4,
      tags: hit ? ["feodo-c2"] : [],
      details: { listed: hit, list_size: set.size },
    };
  },
};

function parseList(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    out.add(t.split(/\s+/)[0]);
  }
  return out;
}
