import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";
import { getCachedText } from "../lib/cache";

const DROP = "https://www.spamhaus.org/drop/drop.txt";
const EDROP = "https://www.spamhaus.org/drop/edrop.txt";

/**
 * Spamhaus DROP / EDROP — public lists of hijacked or completely malicious /CIDR ranges.
 * Truly free, no auth.
 */
export const spamhaus: Provider = {
  name: "Spamhaus",

  isAvailable: () => true,

  supports: (type) => type === "ipv4",

  async check(indicator, _type, env, ctx): Promise<ProviderResult> {
    const [drop, edrop] = await Promise.all([
      getCachedText(DROP, env, ctx),
      getCachedText(EDROP, env, ctx),
    ]);
    if (!drop && !edrop) return emptyResult("Spamhaus", { error: "fetch_failed" });

    const ranges = [...parseRanges(drop ?? ""), ...parseRanges(edrop ?? "")];
    const ip = ipv4ToInt(indicator);
    if (ip === null) return emptyResult("Spamhaus", { error: "bad_ip" });

    const hit = ranges.some(([start, end]) => ip >= start && ip <= end);

    return {
      provider: "Spamhaus",
      verdict: hit ? "malicious" : "clean",
      score: hit ? 85 : 0,
      weight: hit ? 0.85 : 0.4,
      tags: hit ? ["spamhaus-drop"] : [],
      details: { listed: hit, ranges_checked: ranges.length },
    };
  },
};

function parseRanges(text: string): [number, number][] {
  const out: [number, number][] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith(";") || t.startsWith("#")) continue;
    const cidr = t.split(/[;\s]/)[0];
    const r = cidrRange(cidr);
    if (r) out.push(r);
  }
  return out;
}

function cidrRange(cidr: string): [number, number] | null {
  const [ip, bitsStr] = cidr.split("/");
  const bits = parseInt(bitsStr, 10);
  const start = ipv4ToInt(ip);
  if (start === null || isNaN(bits) || bits < 0 || bits > 32) return null;
  const size = 2 ** (32 - bits);
  return [start, start + size - 1];
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const x = parseInt(p, 10);
    if (isNaN(x) || x < 0 || x > 255) return null;
    n = n * 256 + x;
  }
  return n;
}
