import type { ProviderResult, Verdict } from "../providers/types";

export interface AggregateScore {
  score: number;
  verdict: Verdict;
  tags: string[];
}

export function aggregate(results: ProviderResult[]): AggregateScore {
  const usable = results.filter((r) => !r.error && r.weight > 0);

  if (usable.length === 0) {
    return { score: 0, verdict: "unknown", tags: [] };
  }

  let weightedSum = 0;
  let weightTotal = 0;
  const tagSet = new Set<string>();

  for (const r of usable) {
    weightedSum += r.score * r.weight;
    weightTotal += r.weight;
    for (const t of r.tags) tagSet.add(t);
  }

  const score = Math.round(weightedSum / weightTotal);
  let verdict: Verdict = "clean";
  if (score >= 70) verdict = "malicious";
  else if (score >= 30) verdict = "suspicious";
  else if (score === 0 && !usable.some((r) => r.verdict === "clean")) verdict = "unknown";

  // Promote verdict if any high-confidence provider says malicious
  if (usable.some((r) => r.verdict === "malicious" && r.weight >= 0.8)) {
    verdict = "malicious";
  }

  return { score, verdict, tags: [...tagSet].sort() };
}
