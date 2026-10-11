import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { setClockForTests } from "../src/clock.js";
import { etDay, trialEndedMessage } from "../src/config.js";
import { checkPackages } from "../src/operations.js";
import { memoryStoreForTests, resetStoreForTests } from "../src/store.js";
import { resetUpstreamForTests, setFetchForTests } from "../src/upstream/http.js";
import { beginCall } from "../src/usage.js";
import { installFakeUpstream } from "./fake-upstream.js";

afterEach(() => {
  setClockForTests(null);
  resetStoreForTests();
  resetUpstreamForTests();
});

describe("plan caps", () => {
  it("stops an expired trial", async () => {
    setClockForTests(1_700_000_000_000);
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("11111111-1111-4111-8111-111111111111");
    setClockForTests(1_700_000_000_000 + 8 * 24 * 60 * 60 * 1000);
    const access = await accessFor(account.id);
    expect(access.expired).toBe(true);
    expect(await beginCall(access, "call")).toBe(trialEndedMessage());
  });

  it("does not let parallel calls pass the daily cap", async () => {
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("22222222-2222-4222-8222-222222222222");
    const access = await accessFor(account.id);
    store.usage.set(`${account.id}|${etDay()}`, { calls: 99, packages: 0, plan_upgrade_calls: 0 });
    const results = await Promise.all([beginCall(access, "call"), beginCall(access, "call")]);
    expect(results.filter((result) => result === null)).toHaveLength(1);
    expect(store.usage.get(`${account.id}|${etDay()}`)?.calls).toBe(100);
  });

  it("checks a package from fixtures", async () => {
    installFakeUpstream();
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("33333333-3333-4333-8333-333333333333");
    const access = await accessFor(account.id);
    const result = await checkPackages(access, [{ ecosystem: "npm", name: "express", version: "4.17.1" }]);
    const text = JSON.stringify(result.structuredContent);
    expect(text).toContain("GHSA-test-test-test");
    expect(text).toContain("4.18.0");
    expect(text.toLowerCase()).not.toMatch(/\bsafe\b/);
  });
});

describe("upstream guard", () => {
  it("refuses unexpected hosts and off-host redirects", async () => {
    const { cachedJson } = await import("../src/upstream/http.js");
    setFetchForTests(async () => new Response("no", { status: 200 }));
    await expect(cachedJson({ source: "npm", url: "https://evil.example/pkg", ttlSeconds: 60 })).rejects.toThrow(/unexpected host/i);
    installFakeUpstream();
    await expect(cachedJson({ source: "npm", url: "https://registry.npmjs.org/redirect-me", ttlSeconds: 60 })).rejects.toThrow(/redirect/i);
  });
});
