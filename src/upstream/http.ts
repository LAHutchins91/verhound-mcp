import { Agent, fetch as undiciFetch } from "undici";
import { nowDate, nowMs } from "../clock.js";
import { NPM_ALERT_AT, NPM_HARD_STOP, OTHER_SOURCE_ALERT_AT, USER_AGENT, utcMonth } from "../config.js";
import { getStore, type CacheRow } from "../store.js";
import { noteCacheHit, noteUpstream } from "../timing.js";

export type SourceName = "osv" | "depsdev" | "npm" | "pypi" | "eol" | "github" | "rubygems" | "packagist";

const ALLOWED_HOSTS = new Set([
  "api.osv.dev",
  "api.deps.dev",
  "registry.npmjs.org",
  "api.npmjs.org",
  "pypi.org",
  "endoflife.date",
  "api.github.com",
  "rubygems.org",
  "repo.packagist.org"
]);

const LABELS: Record<SourceName, string> = {
  osv: "OSV.dev",
  depsdev: "deps.dev",
  npm: "the npm registry",
  pypi: "PyPI",
  eol: "endoflife.date",
  github: "the GitHub API",
  rubygems: "RubyGems",
  packagist: "Packagist"
};

export class UpstreamError extends Error {
  readonly source: SourceName;
  readonly status?: number;
  constructor(message: string, source: SourceName, status?: number) {
    super(message);
    this.name = "UpstreamError";
    this.source = source;
    this.status = status;
  }
}

export function missMessage(source: SourceName): string {
  if (source === "depsdev") return "deps.dev did not respond; no version information is shown instead of a guess.";
  if (source === "osv") return "OSV.dev did not respond; no advisory list is shown instead of a guess.";
  if (source === "npm") return "The npm registry did not respond; registry details are not shown instead of a guess.";
  if (source === "pypi") return "PyPI did not respond; registry details are not shown instead of a guess.";
  if (source === "github") return "The GitHub API did not respond; that source is omitted instead of a guess.";
  if (source === "rubygems") return "RubyGems did not respond; registry details are not shown instead of a guess.";
  if (source === "packagist") return "Packagist did not respond; registry details are not shown instead of a guess.";
  return "endoflife.date did not respond; no end-of-life date is shown instead of a guess.";
}

export interface CachedJson {
  json: unknown;
  status: number;
  cacheAgeSeconds: number;
  stale: boolean;
  negative: boolean;
  note?: string;
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;
let fetchOverride: FetchLike | null = null;
const circuits = new Map<SourceName, number>();
const alerted = new Set<string>();
/** Identical requests that are already on the way share one upstream call. */
const inflight = new Map<string, Promise<CachedJson>>();
const h2 = new Agent({ allowH2: true, connect: { timeout: 8_000 } });

class Semaphore {
  private active = 0;
  private queue: (() => void)[] = [];
  constructor(private readonly max: number) {}
  async use<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) await new Promise<void>((resolve) => this.queue.push(resolve));
    this.active += 1;
    try {
      return await fn();
    } finally {
      this.active -= 1;
      this.queue.shift()?.();
    }
  }
}

const gates: Record<SourceName, Semaphore> = {
  osv: new Semaphore(8),
  depsdev: new Semaphore(8),
  npm: new Semaphore(6),
  pypi: new Semaphore(4),
  eol: new Semaphore(2),
  github: new Semaphore(4),
  rubygems: new Semaphore(4),
  packagist: new Semaphore(4)
};

export function setFetchForTests(fn: FetchLike | null): void {
  fetchOverride = fn;
}

export function resetUpstreamForTests(): void {
  fetchOverride = null;
  circuits.clear();
  alerted.clear();
  inflight.clear();
}

/** Health keeps the original five keys. Other sources have circuits but are not added here. */
export function upstreamHealth(): { osv: "ok" | "degraded"; depsdev: "ok" | "degraded"; npm: "ok" | "degraded"; pypi: "ok" | "degraded"; eol: "ok" | "degraded" } {
  const now = nowMs();
  const status = (source: SourceName): "ok" | "degraded" => (circuits.get(source) ?? 0) > now ? "degraded" : "ok";
  return { osv: status("osv"), depsdev: status("depsdev"), npm: status("npm"), pypi: status("pypi"), eol: status("eol") };
}

export async function dispatchFetch(url: string, init: RequestInit): Promise<Response> {
  return doFetch(url, init);
}

function retryDelay(): number {
  if (process.env.VITEST) return 0;
  return 50 + Math.floor(Math.random() * 150);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ageSeconds(fetchedAt: string): number {
  const then = Date.parse(fetchedAt);
  if (!Number.isFinite(then)) return 0;
  return Math.max(0, Math.floor((nowMs() - then) / 1000));
}

function isNegative(body: unknown): boolean {
  return Boolean(body && typeof body === "object" && (body as { _negative?: boolean })._negative);
}

function retryAfterMs(value: string | null): number {
  if (!value) return 30_000;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.min(Math.max(seconds, 1), 3_600) * 1000;
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.min(Math.max(date - nowMs(), 1_000), 3_600_000);
  return 30_000;
}

/** GitHub answers a spent rate limit with 403 and x-ratelimit-remaining: 0. Treat it like 429. */
function isRateLimited(response: Response): boolean {
  if (response.status === 429) return true;
  return response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0";
}

function rateLimitMs(response: Response): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) return retryAfterMs(retryAfter);
  const reset = Number(response.headers.get("x-ratelimit-reset"));
  if (Number.isFinite(reset) && reset > 0) return Math.min(Math.max(reset * 1000 - nowMs(), 1_000), 3_600_000);
  return 30_000;
}

function cacheKey(source: SourceName, method: string, url: string, body: unknown): string {
  const parsed = new URL(url);
  const material = body === undefined ? "" : JSON.stringify(body);
  return `${source}:${method}:${parsed.origin}${parsed.pathname}${parsed.search}:${material}`;
}

async function doFetch(url: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("User-Agent", USER_AGENT);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  const next: RequestInit = { ...init, headers, signal: AbortSignal.timeout(8_000) };
  if (fetchOverride) return fetchOverride(url, next);
  if (new URL(url).hostname === "api.osv.dev") {
    return undiciFetch(url, { ...next, dispatcher: h2 } as never) as unknown as Promise<Response>;
  }
  return fetch(url, next);
}

async function fetchAllowed(url: string, init: RequestInit, source: SourceName, redirects = 0): Promise<Response> {
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new UpstreamError("Refused a request to an unexpected host.", source);
  }
  const response = await doFetch(url, { ...init, redirect: "manual" });
  // 304 Not Modified is a revalidation answer, not a redirect.
  if (response.status >= 300 && response.status < 400 && response.status !== 304) {
    const location = response.headers.get("location");
    if (!location || redirects >= 3) throw new UpstreamError(missMessage(source), source, response.status);
    const next = new URL(location, url);
    if (next.hostname !== parsed.hostname) throw new UpstreamError("Refused a redirect off the upstream host.", source);
    const method = response.status === 303 ? "GET" : (init.method ?? "GET");
    return fetchAllowed(next.toString(), { ...init, method, body: method === "GET" ? undefined : init.body }, source, redirects + 1);
  }
  return response;
}

async function send(url: string, init: RequestInit, source: SourceName): Promise<Response> {
  try {
    const response = await fetchAllowed(url, init, source);
    if (response.status < 500) return response;
  } catch (error) {
    if (error instanceof UpstreamError && error.status && error.status < 500) throw error;
  }
  await sleep(retryDelay());
  return fetchAllowed(url, init, source);
}

function fromCache(row: CacheRow, stale: boolean, note?: string): CachedJson {
  return {
    json: isNegative(row.body) ? null : row.body,
    status: isNegative(row.body) ? 404 : 200,
    cacheAgeSeconds: ageSeconds(row.fetched_at),
    stale,
    negative: isNegative(row.body),
    note
  };
}

async function guardNpm(): Promise<void> {
  const current = await getStore().getUpstreamCount("npm", utcMonth());
  if (current >= NPM_HARD_STOP) {
    throw new UpstreamError("The npm request budget for this month is exhausted. No npm data is shown instead of a guess.", "npm");
  }
}

async function recordRequest(source: SourceName, countNpm: boolean): Promise<void> {
  const month = utcMonth();
  const next = await getStore().addUpstreamCount(source, month, 1);
  const alertAt = countNpm || source === "npm" ? NPM_ALERT_AT : OTHER_SOURCE_ALERT_AT;
  if (next >= alertAt) {
    const flag = `${source}:${month}`;
    if (!alerted.has(flag)) {
      alerted.add(flag);
      console.warn(JSON.stringify({ event: "upstream_budget_alert", source, month, requests: next }));
    }
  }
}

export type CachedJsonOptions = Parameters<typeof cachedJsonOnce>[0];

export function cachedJson(options: CachedJsonOptions): Promise<CachedJson> {
  const key = cacheKey(options.source, options.method ?? "GET", options.url, options.body);
  const running = inflight.get(key);
  if (running) return running;
  const started = cachedJsonOnce(options).finally(() => inflight.delete(key));
  inflight.set(key, started);
  return started;
}

async function cachedJsonOnce(options: {
  source: SourceName;
  method?: "GET" | "POST";
  url: string;
  body?: unknown;
  ttlSeconds: number;
  accept?: string;
  extraHeaders?: Record<string, string>;
  countNpm?: boolean;
}): Promise<CachedJson> {
  const method = options.method ?? "GET";
  const key = cacheKey(options.source, method, options.url, options.body);
  const store = getStore();
  let cached: CacheRow | null = null;
  try {
    cached = await store.getCache(key);
  } catch {
    cached = null;
  }
  const now = nowDate().toISOString();
  if (cached && cached.expires_at > now) {
    noteCacheHit();
    return fromCache(cached, false);
  }

  const openUntil = circuits.get(options.source) ?? 0;
  if (openUntil > nowMs()) {
    if (cached) {
      noteCacheHit();
      return fromCache(cached, true, `Served from cache because ${LABELS[options.source]} is rate limiting.`);
    }
    throw new UpstreamError(`${LABELS[options.source]} is rate limiting. No data is shown instead of a guess.`, options.source, 429);
  }

  return gates[options.source].use(async () => {
    if (options.countNpm || options.source === "npm") await guardNpm();
    const headers = new Headers();
    if (options.accept) headers.set("Accept", options.accept);
    if (options.extraHeaders) {
      for (const [name, value] of Object.entries(options.extraHeaders)) headers.set(name, value);
    }
    if (cached?.etag) headers.set("If-None-Match", cached.etag);
    if (cached?.last_modified) headers.set("If-Modified-Since", cached.last_modified);
    if (options.body !== undefined) headers.set("Content-Type", "application/json");

    let response: Response;
    const fetchStarted = nowMs();
    try {
      response = await send(options.url, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body)
      }, options.source);
      noteUpstream(nowMs() - fetchStarted);
    } catch (error) {
      noteUpstream(nowMs() - fetchStarted);
      if (cached) {
        noteCacheHit();
        return fromCache(cached, true, missMessage(options.source));
      }
      if (error instanceof UpstreamError) throw error;
      throw new UpstreamError(missMessage(options.source), options.source);
    }

    if (response.status === 304 && cached) {
      const refreshed: CacheRow = {
        ...cached,
        expires_at: new Date(nowMs() + options.ttlSeconds * 1000).toISOString()
      };
      await store.putCache(refreshed).catch(() => undefined);
      // A 304 is still a request to the upstream, so it counts toward the monthly budget.
      await recordRequest(options.source, Boolean(options.countNpm || options.source === "npm"));
      return fromCache(refreshed, false);
    }

    if (isRateLimited(response)) {
      circuits.set(options.source, nowMs() + rateLimitMs(response));
      if (options.countNpm || options.source === "npm") await recordRequest(options.source, true);
      if (cached) {
        noteCacheHit();
        return fromCache(cached, true, `Served from cache because ${LABELS[options.source]} is rate limiting.`);
      }
      throw new UpstreamError(`${LABELS[options.source]} is rate limiting. No data is shown instead of a guess.`, options.source, 429);
    }

    if (response.status === 404) {
      const negative: CacheRow = {
        key,
        source: options.source,
        body: { _negative: true, status: 404 },
        etag: response.headers.get("etag"),
        last_modified: response.headers.get("last-modified"),
        fetched_at: nowDate().toISOString(),
        expires_at: new Date(nowMs() + 10 * 60 * 1000).toISOString()
      };
      await store.putCache(negative).catch(() => undefined);
      if (options.countNpm || options.source === "npm") await recordRequest(options.source, true);
      else await recordRequest(options.source, false);
      return { json: null, status: 404, cacheAgeSeconds: 0, stale: false, negative: true };
    }

    if (response.status >= 400) {
      if (cached) return fromCache(cached, true, missMessage(options.source));
      throw new UpstreamError(missMessage(options.source), options.source, response.status);
    }

    let json: unknown;
    try {
      json = await response.json();
    } catch {
      if (cached) return fromCache(cached, true, `The response from ${LABELS[options.source]} could not be read; nothing was filled in instead of a guess.`);
      throw new UpstreamError(`The response from ${LABELS[options.source]} could not be read; nothing was filled in instead of a guess.`, options.source);
    }

    const row: CacheRow = {
      key,
      source: options.source,
      body: json,
      etag: response.headers.get("etag"),
      last_modified: response.headers.get("last-modified"),
      fetched_at: nowDate().toISOString(),
      expires_at: new Date(nowMs() + options.ttlSeconds * 1000).toISOString()
    };
    await store.putCache(row).catch(() => undefined);
    if (options.countNpm || options.source === "npm") await recordRequest(options.source, true);
    else await recordRequest(options.source, false);
    return { json, status: response.status, cacheAgeSeconds: 0, stale: false, negative: false };
  });
}
