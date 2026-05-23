/**
 * Cache helper for fetching public blocklists.
 * Uses KV when DFIR_CACHE is bound; otherwise falls back to the request-scoped Cache API.
 */

interface CachedText {
  text: string;
  fetchedAt: number;
}

const KV_TTL_SECONDS = 3600; // 1 hour

export async function getCachedText(
  url: string,
  env: { DFIR_CACHE?: KVNamespace },
  ctx: ExecutionContext,
): Promise<string | null> {
  // KV path
  if (env.DFIR_CACHE) {
    const hit = await env.DFIR_CACHE.get(url);
    if (hit) return hit;
    const fresh = await fetchText(url);
    if (fresh !== null) {
      ctx.waitUntil(env.DFIR_CACHE.put(url, fresh, { expirationTtl: KV_TTL_SECONDS }));
    }
    return fresh;
  }

  // Cache API fallback
  const cache = caches.default;
  const cacheKey = new Request(url, { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) {
    return await cached.text();
  }
  const fresh = await fetchText(url);
  if (fresh !== null) {
    const resp = new Response(fresh, {
      headers: { "Cache-Control": `public, max-age=${KV_TTL_SECONDS}` },
    });
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
  }
  return fresh;
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const r = await fetch(url, { cf: { cacheTtl: KV_TTL_SECONDS, cacheEverything: true } });
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null;
  }
}

export type { CachedText };
