import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { proUpsell } from "../src/config.js";
import { listAlerts, unwatchManifest, watchManifest } from "../src/operations.js";
import { resetStoreForTests } from "../src/store.js";
import { resetUpstreamForTests } from "../src/upstream/http.js";
import { executeCron } from "../src/watch-job.js";
import { installFakeUpstream } from "./fake-upstream.js";

afterEach(() => {
  resetStoreForTests();
  resetUpstreamForTests();
  delete process.env.CRON_SECRET;
});

describe("watches", () => {
  it("allows one trial project and deletes it", async () => {
    installFakeUpstream();
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("44444444-4444-4444-8444-444444444444", "person@example.com");
    const access = await accessFor(account.id);
    const content = JSON.stringify({ dependencies: { express: "4.17.1" } });
    const saved = await watchManifest(access, { label: "app", filename: "package.json", content, alertEmail: "account" });
    expect(JSON.stringify(saved.structuredContent)).toContain("parsed dependency list and filename only");
    const again = await watchManifest(access, { label: "other", filename: "package.json", content });
    expect(JSON.stringify(again.structuredContent)).toContain(proUpsell());
    const removed = await unwatchManifest(access, "app");
    expect(JSON.stringify(removed.structuredContent)).toContain("\"deleted\":true");
    const missing = await listAlerts(access, { limit: 10 });
    expect(JSON.stringify(missing.structuredContent)).toContain("\"alerts\":[]");
  });

  it("rechecks a due watch from the cron handler", async () => {
    installFakeUpstream();
    const { getStore } = await import("../src/store.js");
    const account = await getStore().ensureAccount("55555555-5555-4555-8555-555555555555");
    await getStore().setPlan(account.id, "pro");
    const access = await accessFor(account.id);
    await watchManifest(access, {
      label: "api",
      filename: "package.json",
      content: JSON.stringify({ dependencies: { express: "4.17.1" } })
    });
    await getStore().updateWatchMeta(account.id, "api", { last_checked_at: "2000-01-01T00:00:00.000Z" });
    process.env.CRON_SECRET = "cron-test-secret";
    const result = await executeCron("Bearer cron-test-secret", undefined, "http://127.0.0.1");
    expect(result.status).toBe(200);
    expect(result.body.checked).toBe(1);
  });
});
