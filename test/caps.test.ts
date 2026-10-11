import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { setClockForTests } from "../src/clock.js";
import { etDay, LIMITS, proOnlyMessage, verifyEmailMessage } from "../src/config.js";
import { auditManifest, checkPackages, listAlerts, planUpgrade, runtimeEolTool, unwatchManifest, verifyPackageExists, watchManifest } from "../src/operations.js";
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
  it("moves an ended trial to the free plan instead of locking it", async () => {
    setClockForTests(1_700_000_000_000);
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("11111111-1111-4111-8111-111111111111", "ended@example.com");
    setClockForTests(1_700_000_000_000 + 8 * 24 * 60 * 60 * 1000);
    const access = await accessFor(account.id);
    expect(access.expired).toBe(true);
    expect(access.plan).toBe("free");
    expect(await beginCall(access, "call")).toBeNull();
  });

  it("refuses accounts without a verified email", async () => {
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("12121212-1212-4121-8121-121212121212");
    const access = await accessFor(account.id);
    expect(access.emailRequired).toBe(true);
    expect(await beginCall(access, "call")).toBe(verifyEmailMessage());
  });

  it("does not let parallel calls pass the daily cap", async () => {
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("22222222-2222-4222-8222-222222222222", "parallel@example.com");
    const access = await accessFor(account.id);
    store.usage.set(`${account.id}|${etDay()}`, { calls: 99, packages: 0, plan_upgrade_calls: 0 });
    const results = await Promise.all([beginCall(access, "call"), beginCall(access, "call")]);
    expect(results.filter((result) => result === null)).toHaveLength(1);
    expect(store.usage.get(`${account.id}|${etDay()}`)?.calls).toBe(100);
  });

  it("checks a package from fixtures", async () => {
    installFakeUpstream();
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("33333333-3333-4333-8333-333333333333", "fixture@example.com");
    const access = await accessFor(account.id);
    const result = await checkPackages(access, [{ ecosystem: "npm", name: "express", version: "4.17.1" }]);
    const text = JSON.stringify(result.structuredContent);
    expect(text).toContain("GHSA-test-test-test");
    expect(text).toContain("4.18.0");
    expect(text.toLowerCase()).not.toMatch(/\bsafe\b/);
  });
});

describe("free plan gating", () => {
  async function freeAccess() {
    setClockForTests(1_700_000_000_000);
    const store = memoryStoreForTests();
    const account = await store.ensureAccount("55555555-5555-4555-8555-555555555555", "free@example.com");
    setClockForTests(1_700_000_000_000 + 8 * 24 * 60 * 60 * 1000);
    const access = await accessFor(account.id);
    expect(access.plan).toBe("free");
    return { store, access };
  }

  it("keeps the free caps small", () => {
    expect(LIMITS.free.callsPerDay).toBe(15);
    expect(LIMITS.free.packagesPerCall).toBe(10);
    expect(LIMITS.free.manifestBytes).toBe(20_000);
    expect(LIMITS.free.watches).toBe(0);
    expect(LIMITS.free.planUpgradePerDay).toBe(0);
  });

  it("allows one-off checks", async () => {
    installFakeUpstream();
    const { access } = await freeAccess();
    expect((await checkPackages(access, [{ ecosystem: "npm", name: "express", version: "4.17.1" }])).isError).toBeUndefined();
    expect((await verifyPackageExists(access, { ecosystem: "npm", names: ["express"], maxSimilar: 3 })).isError).toBeUndefined();
    expect((await runtimeEolTool(access, "node", "18")).isError).toBeUndefined();
    expect((await auditManifest(access, { filename: "package.json", content: JSON.stringify({ dependencies: { express: "4.17.1" } }) })).isError).toBeUndefined();
  });

  it("returns a Pro-only message for watch, alerts, and upgrade plans without counting a call", async () => {
    const { store, access } = await freeAccess();
    for (const result of [
      await watchManifest(access, { label: "x", filename: "package.json", content: "{}" }),
      await listAlerts(access, { limit: 10 }),
      await planUpgrade(access, { ecosystem: "npm", name: "express", fromVersion: "4.17.1" })
    ]) {
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.structuredContent)).toContain(proOnlyMessage());
      expect(JSON.stringify(result.structuredContent)).toContain("/checkout");
    }
    expect(store.usage.get(`${access.accountId}|${etDay()}`)?.calls ?? 0).toBe(0);
  });

  it("still lets a free account delete a leftover watch", async () => {
    const { access } = await freeAccess();
    expect((await unwatchManifest(access, "missing")).isError).toBeUndefined();
  });

  it("enforces the free per-call, manifest, and daily limits", async () => {
    installFakeUpstream();
    const { store, access } = await freeAccess();
    const eleven = Array.from({ length: 11 }, (_, i) => ({ ecosystem: "npm" as const, name: `p${i}` }));
    expect((await checkPackages(access, eleven)).isError).toBe(true);
    expect((await auditManifest(access, { filename: "package.json", content: " ".repeat(20_001) })).isError).toBe(true);
    store.usage.set(`${access.accountId}|${etDay()}`, { calls: 15, packages: 0, plan_upgrade_calls: 0 });
    const capped = await runtimeEolTool(access, "node", "18");
    expect(capped.isError).toBe(true);
    expect(JSON.stringify(capped.structuredContent)).toContain("Daily limit reached");
  });

  it("does not use banned wording in free-plan messages", () => {
    for (const text of [proOnlyMessage(), verifyEmailMessage()]) {
      expect(text.toLowerCase()).not.toMatch(/\bsafe\b|cheaper than free|free forever/);
    }
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
