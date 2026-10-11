import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { assessLicenses } from "../src/license.js";
import { planUpgrade, watchManifest } from "../src/operations.js";
import { similarPopular } from "../src/names.js";
import { resetStoreForTests } from "../src/store.js";
import { setFetchForTests, resetUpstreamForTests } from "../src/upstream/http.js";
import { packageVerdict, publishedUnder72Hours } from "../src/verdict.js";
import { postWebhook, webhookKind } from "../src/webhooks.js";
import { executeCron } from "../src/watch-job.js";
import { installFakeUpstream } from "./fake-upstream.js";

afterEach(() => {
  resetStoreForTests();
  resetUpstreamForTests();
  delete process.env.CRON_SECRET;
});

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

describe("launch bar", () => {
  it("picks the newest version with no known advisories and emits toolchain commands", async () => {
    installFakeUpstream();
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("66666666-6666-4666-8666-666666666666", "plans@example.com");
    await getStore().setPlan(account.id, "pro");
    const access = await accessFor(account.id);
    const planned = await planUpgrade(access, { ecosystem: "npm", name: "express", fromVersion: "4.17.1" });
    const body = JSON.stringify(planned.structuredContent);
    expect(body).toContain("\"to_version\":\"4.18.2\"");
    expect(body).toContain("Newest version with no known advisories");
    expect(body).not.toContain("/releases/tag/");
    const maven = await planUpgrade(access, { ecosystem: "maven", name: "org.slf4j:slf4j-api", fromVersion: "2.0.9", toVersion: "2.0.16" });
    const cargo = await planUpgrade(access, { ecosystem: "cargo", name: "serde", fromVersion: "1.0.0", toVersion: "1.0.210" });
    const nuget = await planUpgrade(access, { ecosystem: "nuget", name: "Newtonsoft.Json", fromVersion: "12.0.3", toVersion: "13.0.3" });
    expect(JSON.stringify(maven.structuredContent)).toContain("mvn versions:use-dep-version");
    expect(JSON.stringify(cargo.structuredContent)).toContain("cargo add serde@1.0.210");
    expect(JSON.stringify(nuget.structuredContent)).toContain("dotnet add package Newtonsoft.Json --version 13.0.3");
    expect(JSON.stringify(maven.structuredContent)).toContain("for you to run");
  });

  it("does not choose a latest version that still has a known advisory", async () => {
    setFetchForTests(async (url, init) => {
      const parsed = new URL(url);
      if (parsed.hostname === "api.deps.dev") {
        if (parsed.pathname.includes("/versions/")) return json({ licenses: ["MIT"], links: [] });
        return json({
          versions: [
            { versionKey: { version: "1.0.0" }, publishedAt: "2020-01-01T00:00:00.000Z" },
            { versionKey: { version: "1.1.0" }, publishedAt: "2021-01-01T00:00:00.000Z" },
            { versionKey: { version: "1.2.0" }, publishedAt: "2024-01-01T00:00:00.000Z", isDefault: true }
          ]
        });
      }
      if (parsed.hostname === "registry.npmjs.org") {
        return json({ name: "left-pad", "dist-tags": { latest: "1.2.0" }, versions: { "1.0.0": {}, "1.1.0": {}, "1.2.0": {} } });
      }
      if (parsed.hostname === "api.osv.dev" && parsed.pathname.endsWith("/querybatch")) {
        const body = JSON.parse(String(init?.body ?? "{}")) as { queries?: { version?: string }[] };
        return json({
          results: (body.queries ?? []).map((query) => query.version === "1.2.0" ? { vulns: [{ id: "GHSA-aaaa-bbbb-cccc" }] } : { vulns: [] })
        });
      }
      if (parsed.hostname === "api.osv.dev") {
        return json({ id: "GHSA-aaaa-bbbb-cccc", summary: "Example", database_specific: { severity: "HIGH" }, affected: [] });
      }
      return new Response("no", { status: 404 });
    });
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("77777777-7777-4777-8777-777777777777", "plans@example.com");
    await getStore().setPlan(account.id, "pro");
    const access = await accessFor(account.id);
    const planned = await planUpgrade(access, { ecosystem: "npm", name: "left-pad", fromVersion: "1.0.0" });
    const body = JSON.stringify(planned.structuredContent);
    expect(body).toContain("\"to_version\":\"1.1.0\"");
    expect(body).toContain("\"latest_stable\":\"1.2.0\"");
  });

  it("alerts on known malware below the severity minimum and posts only to the allowlisted webhook", async () => {
    let mode: "clean" | "malware" = "clean";
    const calls: string[] = [];
    setFetchForTests(async (url, init) => {
      const parsed = new URL(url);
      calls.push(parsed.hostname);
      if (parsed.hostname === "hooks.slack.com") {
        if (init?.redirect === "manual") return json({ ok: true });
        return new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } });
      }
      if (parsed.hostname === "api.deps.dev") {
        return json({ versions: [{ versionKey: { version: "1.2.3" }, publishedAt: "2020-01-01T00:00:00.000Z", isDefault: true }], licenses: ["MIT"] });
      }
      if (parsed.hostname === "registry.npmjs.org") {
        return json({ name: "left-pad", "dist-tags": { latest: "1.2.3" }, versions: { "1.2.3": {} } });
      }
      if (parsed.hostname === "api.osv.dev" && parsed.pathname.endsWith("/querybatch")) {
        return json({ results: [{ vulns: mode === "malware" ? [{ id: "MAL-2024-0001" }] : [] }] });
      }
      if (parsed.hostname === "api.osv.dev") {
        return json({ id: "MAL-2024-0001", summary: "Known malware record.", database_specific: { severity: "LOW" }, affected: [] });
      }
      return new Response("no", { status: 404 });
    });
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("88888888-8888-4888-8888-888888888888", "watch@example.com");
    await getStore().setPlan(account.id, "pro");
    const access = await accessFor(account.id);
    const saved = await watchManifest(access, {
      label: "api",
      filename: "package.json",
      content: JSON.stringify({ dependencies: { "left-pad": "1.2.3" } }),
      minSeverity: "critical",
      webhookUrl: "https://hooks.slack.com/services/T00/B00/secret"
    });
    expect(JSON.stringify(saved.structuredContent)).toContain("hooks.slack.com");
    const rejected = await watchManifest(access, {
      label: "bad",
      filename: "package.json",
      content: JSON.stringify({ dependencies: { "left-pad": "1.2.3" } }),
      webhookUrl: "https://evil.example/hook"
    });
    expect(JSON.stringify(rejected.structuredContent)).toContain("Webhook host is not allowed");
    mode = "malware";
    await getStore().purgeExpiredCache("2999-01-01T00:00:00.000Z");
    await getStore().updateWatchMeta(account.id, "api", { last_checked_at: "2000-01-01T00:00:00.000Z" });
    process.env.CRON_SECRET = "cron-test-secret";
    const result = await executeCron("Bearer cron-test-secret", undefined, "http://127.0.0.1");
    expect(result.body.checked).toBe(1);
    expect(result.body.alerts).toBe(1);
    expect(calls.filter((host) => host === "hooks.slack.com").length).toBe(1);
    expect(calls).not.toContain("evil.example");
  });

  it("refuses webhook redirects and unknown hosts", async () => {
    expect(webhookKind("https://hooks.slack.com/services/T/B/x")).toBe("slack");
    expect(webhookKind("https://discord.com/api/webhooks/1/token")).toBe("discord");
    expect(webhookKind("https://evil.example/hook")).toBeNull();
    expect(webhookKind("http://hooks.slack.com/services/T/B/x")).toBeNull();
    let hits = 0;
    setFetchForTests(async () => {
      hits += 1;
      return new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } });
    });
    expect(await postWebhook("https://discord.com/api/webhooks/1/token", "hello")).toBe("rejected");
    expect(hits).toBe(1);
  });

  it("checks every due watch in the time budget instead of stopping at 40", async () => {
    installFakeUpstream();
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("99999999-9999-4999-8999-999999999999", "scale@example.com");
    for (let index = 0; index < 41; index += 1) {
      await getStore().saveWatch({
        account_id: account.id,
        label: `project-${index}`,
        filename: "package.json",
        ecosystem_summary: { npm: 1 },
        deps: [{ ecosystem: "npm", name: "express", version: "4.18.2" }],
        min_severity: "low",
        last_checked_at: "2000-01-01T00:00:00.000Z",
        baseline_complete: true,
        email: null,
        webhook_url: null,
        license_allow: [],
        license_deny: []
      });
    }
    process.env.CRON_SECRET = "cron-test-secret";
    const result = await executeCron("Bearer cron-test-secret", undefined, "http://127.0.0.1");
    expect(result.status).toBe(200);
    expect(result.body.checked).toBe(41);
    expect(result.body.remaining).toBe(0);
  });

  it("names verdicts without calling a package safe, and flags recent publishes and licenses", () => {
    const recent = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    expect(publishedUnder72Hours(recent)).toBe(true);
    expect(publishedUnder72Hours("2020-01-01T00:00:00.000Z")).toBe(false);
    const avoid = packageVerdict({
      exists: true,
      advisoriesKnown: true,
      advisories: [{ id: "MAL-2024-1", malicious: true }],
      deprecated: false,
      publishedUnder30Days: false,
      publishedUnder72Hours: false,
      similar: false,
      licenseFlags: [],
      licenseReasons: []
    });
    expect(avoid.verdict).toBe("avoid");
    expect(avoid.reasons.join(" ")).toContain("Known malware");
    const review = packageVerdict({
      exists: true,
      advisoriesKnown: true,
      advisories: [],
      deprecated: false,
      publishedUnder30Days: false,
      publishedUnder72Hours: true,
      similar: false,
      licenseFlags: ["no_license"],
      licenseReasons: ["No license is declared in package metadata."]
    });
    expect(review.verdict).toBe("review");
    const licenses = assessLicenses(["GPL-3.0-only"], { deny: ["MIT"] }, true);
    expect(licenses.flags).toContain("strong_copyleft");
    expect(assessLicenses([], undefined, true).flags).toContain("no_license");
    expect(assessLicenses(["MIT"], { deny: ["MIT"] }, true).flags).toContain("license_denied");
    expect(assessLicenses(["LGPL-2.1-only"], undefined, true).flags).not.toContain("strong_copyleft");
    expect(similarPopular("go", "github.com/gin-gonic/gin", 3)).toEqual([]);
    expect(similarPopular("cargo", "tokip", 3).map((item) => item.name)).toContain("tokio");
    expect(similarPopular("maven", "com.google.guava:guavb", 3).map((item) => item.name)).toContain("com.google.guava:guava");
  });
});
