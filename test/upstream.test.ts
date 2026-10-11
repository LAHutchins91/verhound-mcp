import { afterEach, describe, expect, it } from "vitest";
import { setClockForTests } from "../src/clock.js";
import { NPM_HARD_STOP, utcMonth } from "../src/config.js";
import { memoryStoreForTests, resetStoreForTests } from "../src/store.js";
import { cachedJson, resetUpstreamForTests, setFetchForTests, upstreamHealth } from "../src/upstream/http.js";

afterEach(() => {
  setClockForTests(null);
  resetStoreForTests();
  resetUpstreamForTests();
});

const T0 = 1_800_000_000_000;

describe("upstream rate limits and budgets", () => {
  it("opens a circuit for the Retry-After window on 429, then recovers", async () => {
    setClockForTests(T0);
    let calls = 0;
    setFetchForTests(async () => {
      calls += 1;
      return calls === 1
        ? new Response("slow down", { status: 429, headers: { "retry-after": "120" } })
        : new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    });
    const url = "https://endoflife.date/api/v1/products/nodejs";
    await expect(cachedJson({ source: "eol", url, ttlSeconds: 60 })).rejects.toThrow(/rate limiting/);
    expect(upstreamHealth().eol).toBe("degraded");
    setClockForTests(T0 + 60_000);
    await expect(cachedJson({ source: "eol", url, ttlSeconds: 60 })).rejects.toThrow(/rate limiting/);
    expect(calls).toBe(1);
    setClockForTests(T0 + 121_000);
    const ok = await cachedJson({ source: "eol", url, ttlSeconds: 60 });
    expect(ok.json).toEqual({ ok: true });
    expect(calls).toBe(2);
    expect(upstreamHealth().eol).toBe("ok");
  });

  it("serves stale cache while the circuit is open", async () => {
    setClockForTests(T0);
    const store = memoryStoreForTests();
    const url = "https://pypi.org/pypi/requests/json";
    setFetchForTests(async () => new Response(JSON.stringify({ v: 1 }), { status: 200, headers: { "content-type": "application/json" } }));
    await cachedJson({ source: "pypi", url, ttlSeconds: 60 });
    setClockForTests(T0 + 120_000);
    setFetchForTests(async () => new Response("no", { status: 429, headers: { "retry-after": "30" } }));
    const stale = await cachedJson({ source: "pypi", url, ttlSeconds: 60 });
    expect(stale.stale).toBe(true);
    expect(stale.json).toEqual({ v: 1 });
    expect(store.cache.size).toBe(1);
  });

  it("revalidates with If-None-Match, refreshes on 304, and counts the 304 toward the npm budget", async () => {
    setClockForTests(T0);
    const store = memoryStoreForTests();
    const url = "https://registry.npmjs.org/express";
    const seen: (string | null)[] = [];
    setFetchForTests(async (_u, init) => {
      const inm = new Headers(init?.headers).get("if-none-match");
      seen.push(inm);
      if (inm === "\"v1\"") return new Response(null, { status: 304 });
      return new Response(JSON.stringify({ name: "express" }), { status: 200, headers: { "content-type": "application/json", etag: "\"v1\"" } });
    });
    await cachedJson({ source: "npm", url, ttlSeconds: 60, countNpm: true });
    expect(await store.getUpstreamCount("npm", utcMonth())).toBe(1);
    setClockForTests(T0 + 61_000);
    const revalidated = await cachedJson({ source: "npm", url, ttlSeconds: 60, countNpm: true });
    expect(seen).toEqual([null, "\"v1\""]);
    expect(revalidated.json).toEqual({ name: "express" });
    expect(revalidated.stale).toBe(false);
    expect(await store.getUpstreamCount("npm", utcMonth())).toBe(2);
    const row = await store.getCache([...store.cache.keys()][0]);
    expect(Date.parse(row!.expires_at)).toBe(T0 + 61_000 + 60_000);
    setClockForTests(T0 + 90_000);
    await cachedJson({ source: "npm", url, ttlSeconds: 60, countNpm: true });
    expect(seen).toHaveLength(2);
  });

  it("stops npm requests at the monthly hard stop", async () => {
    setClockForTests(T0);
    const store = memoryStoreForTests();
    await store.addUpstreamCount("npm", utcMonth(), NPM_HARD_STOP);
    let calls = 0;
    setFetchForTests(async () => {
      calls += 1;
      return new Response("{}", { status: 200 });
    });
    await expect(cachedJson({ source: "npm", url: "https://registry.npmjs.org/react", ttlSeconds: 60, countNpm: true })).rejects.toThrow(/budget/);
    await expect(cachedJson({ source: "depsdev", url: "https://api.deps.dev/v3/systems/NPM/packages/react", ttlSeconds: 60, countNpm: true })).rejects.toThrow(/budget/);
    expect(calls).toBe(0);
  });
});
