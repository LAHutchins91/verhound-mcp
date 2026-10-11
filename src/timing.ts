import { AsyncLocalStorage } from "node:async_hooks";

export interface CallStats {
  cacheHits: number;
  upstreamFetches: number;
  upstreamMs: number;
}

const storage = new AsyncLocalStorage<CallStats>();

export function noteCacheHit(): void {
  const stats = storage.getStore();
  if (stats) stats.cacheHits += 1;
}

export function noteUpstream(ms: number): void {
  const stats = storage.getStore();
  if (!stats) return;
  stats.upstreamFetches += 1;
  stats.upstreamMs += Math.max(0, Math.round(ms));
}

export async function withCallStats<T>(fn: () => Promise<T>): Promise<{ value: T; stats: CallStats }> {
  const stats: CallStats = { cacheHits: 0, upstreamFetches: 0, upstreamMs: 0 };
  const value = await storage.run(stats, fn);
  return { value, stats };
}

/** One line per tool call. Counts and durations only: no package names, manifests, or account ids. */
export function logToolTiming(tool: string, durationMs: number, ok: boolean, stats: CallStats, items: number): void {
  console.log(JSON.stringify({
    event: "tool_timing",
    tool,
    duration_ms: Math.max(0, Math.round(durationMs)),
    ok,
    items,
    cache_hits: stats.cacheHits,
    upstream_fetches: stats.upstreamFetches,
    upstream_ms: stats.upstreamMs
  }));
}

export function logCronTiming(checked: number, alerts: number, durationMs: number, remaining: number, failed: number): void {
  console.log(JSON.stringify({
    event: "cron_timing",
    checked,
    alerts,
    remaining,
    failed,
    duration_ms: Math.max(0, Math.round(durationMs))
  }));
}
