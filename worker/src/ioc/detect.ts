export type IOCType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "unknown";

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_RE = /^(?:[a-f0-9:]+:+)+[a-f0-9]+$/i;
const DOMAIN_RE = /^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
const MD5_RE = /^[a-f0-9]{32}$/i;
const SHA1_RE = /^[a-f0-9]{40}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;

export function detectType(raw: string): IOCType {
  const v = refang(raw).trim();
  if (!v) return "unknown";
  if (/^https?:\/\//i.test(v)) return "url";
  if (IPV4_RE.test(v)) return "ipv4";
  if (IPV6_RE.test(v) && v.includes(":")) return "ipv6";
  if (MD5_RE.test(v)) return "md5";
  if (SHA1_RE.test(v)) return "sha1";
  if (SHA256_RE.test(v)) return "sha256";
  if (DOMAIN_RE.test(v)) return "domain";
  return "unknown";
}

export function refang(s: string): string {
  return s
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/hxxps?:\/\//gi, (m) => m.replace(/x/g, "t"))
    .replace(/\[at\]/gi, "@")
    .trim();
}

export function defang(s: string): string {
  const t = detectType(s);
  if (t === "url") return s.replace(/\./g, "[.]").replace(/^https?/i, (m) => m.replace(/t/gi, "x"));
  if (t === "ipv4" || t === "ipv6" || t === "domain") return s.replace(/\./g, "[.]");
  return s;
}

export function urlToHostname(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}
