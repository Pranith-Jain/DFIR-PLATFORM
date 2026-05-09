import type { IOCType } from "../ioc/detect";

export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface Env {
  VIRUSTOTAL_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  SHODAN_API_KEY?: string;
  GREYNOISE_API_KEY?: string;
  OTX_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  PULSEDIVE_API_KEY?: string;
  ABUSECH_AUTH_KEY?: string;
  DFIR_CACHE?: KVNamespace;
}

export interface ProviderResult {
  provider: string;
  verdict: Verdict;
  score: number;             // 0-100, normalized maliciousness
  weight: number;            // confidence weight 0-1
  tags: string[];
  details: Record<string, unknown>;
  error?: string;
}

export interface Provider {
  name: string;
  /** True if the provider is configured for use (e.g. has its API key). */
  isAvailable(env: Env): boolean;
  /** True if the provider can answer for this IOC type. */
  supports(type: IOCType): boolean;
  check(indicator: string, type: IOCType, env: Env, ctx: ExecutionContext): Promise<ProviderResult>;
}

export function emptyResult(name: string, partial?: Partial<ProviderResult>): ProviderResult {
  return {
    provider: name,
    verdict: "unknown",
    score: 0,
    weight: 0,
    tags: [],
    details: {},
    ...partial,
  };
}
