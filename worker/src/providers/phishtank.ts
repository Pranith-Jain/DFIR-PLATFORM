import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";
import { getCachedText } from "../lib/cache";

/**
 * OpenPhish public feed (PhishTank gating their API now).
 * Free, no auth — refreshed every 12 hours.
 */
const FEED = "https://openphish.com/feed.txt";

export const phishtank: Provider = {
  name: "OpenPhish",

  isAvailable: () => true,

  supports: (type) => type === "url" || type === "domain",

  async check(indicator, type, env, ctx): Promise<ProviderResult> {
    const text = await getCachedText(FEED, env, ctx);
    if (!text) return emptyResult("OpenPhish", { error: "fetch_failed" });

    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

    const hit =
      type === "url"
        ? lines.includes(indicator)
        : lines.some((u) => domainMatches(u, indicator));

    return {
      provider: "OpenPhish",
      verdict: hit ? "malicious" : "clean",
      score: hit ? 90 : 0,
      weight: hit ? 0.85 : 0.45,
      tags: hit ? ["openphish-listed", "phishing"] : [],
      details: { listed: hit, feed_size: lines.length },
    };
  },
};

function domainMatches(url: string, domain: string): boolean {
  try {
    const host = new URL(url).hostname;
    return host === domain || host.endsWith(`.${domain}`);
  } catch {
    return false;
  }
}
