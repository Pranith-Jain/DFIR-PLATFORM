import type { Provider, ProviderResult } from "./types";
import { emptyResult } from "./types";

/**
 * Cloudflare DNS over HTTPS resolution check.
 * Free, no auth. Flags NXDOMAIN, very recent registrations (via SOA), and missing A/AAAA.
 */
export const doh: Provider = {
  name: "CloudflareDoH",

  isAvailable: () => true,

  supports: (type) => type === "domain",

  async check(indicator, _type): Promise<ProviderResult> {
    const [a, mx, ns, txt] = await Promise.all([
      query(indicator, "A"),
      query(indicator, "MX"),
      query(indicator, "NS"),
      query(indicator, "TXT"),
    ]);

    if (a == null) return emptyResult("CloudflareDoH", { error: "fetch_failed" });

    const status = a.Status; // 0=NOERROR, 3=NXDOMAIN
    const tags: string[] = [];
    let score = 0;
    let verdict: ProviderResult["verdict"] = "clean";

    if (status === 3) {
      tags.push("nxdomain");
      score = 60;
      verdict = "suspicious";
    }
    if (!a.Answer && status === 0) {
      tags.push("no-a-record");
      score = Math.max(score, 25);
    }
    if (!mx?.Answer) tags.push("no-mx");
    if (!ns?.Answer) tags.push("no-ns");

    const spf = (txt?.Answer ?? []).some((r: any) => /v=spf1/i.test(r.data ?? ""));
    const dmarc = !!(await query(`_dmarc.${indicator}`, "TXT"))?.Answer?.length;
    if (!spf) tags.push("no-spf");
    if (!dmarc) tags.push("no-dmarc");

    return {
      provider: "CloudflareDoH",
      verdict,
      score,
      weight: 0.5,
      tags,
      details: {
        status,
        has_a: !!a.Answer,
        has_mx: !!mx?.Answer,
        has_ns: !!ns?.Answer,
        spf,
        dmarc,
      },
    };
  },
};

async function query(name: string, type: string): Promise<any | null> {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
    );
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}
