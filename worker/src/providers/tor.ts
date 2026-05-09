import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";
import { getCachedText } from "../lib/cache";

const URL = "https://check.torproject.org/exit-addresses";

/**
 * Tor Project — current Tor exit relay IPs.
 * Free, no auth. Hits are informational (not malicious by themselves).
 */
export const tor: Provider = {
  name: "TorExit",

  isAvailable: () => true,

  supports: (type) => type === "ipv4",

  async check(indicator, _type, env, ctx): Promise<ProviderResult> {
    const text = await getCachedText(URL, env, ctx);
    if (!text) return emptyResult("TorExit", { error: "fetch_failed" });

    const exits = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      if (line.startsWith("ExitAddress")) {
        const ip = line.split(/\s+/)[1];
        if (ip) exits.add(ip);
      }
    }

    const hit = exits.has(indicator);
    return {
      provider: "TorExit",
      verdict: hit ? "suspicious" : "clean",
      score: hit ? 35 : 0,
      weight: 0.5,
      tags: hit ? ["tor-exit"] : [],
      details: { listed: hit, exit_count: exits.size },
    };
  },
};
