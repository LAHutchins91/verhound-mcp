/**
 * Opt-in live calls. Not part of npm test.
 * VERHOUND_LIVE_SMOKE=1 npm run smoke
 */
import { checkPackages, planUpgrade, runtimeEolTool, verifyPackageExists, watchManifest, listAlerts, unwatchManifest } from "../src/operations.js";
import { resetUpstreamForTests } from "../src/upstream/http.js";
import { getStore, resetStoreForTests } from "../src/store.js";
import { accessFor } from "../src/billing.js";
import { executeCron } from "../src/watch-job.js";

if (process.env.VERHOUND_LIVE_SMOKE !== "1") {
  console.log("Set VERHOUND_LIVE_SMOKE=1 to run live checks.");
  process.exit(0);
}

process.env.MAIL_PROVIDER = "none";
resetStoreForTests();
resetUpstreamForTests();

const account = await getStore().ensureAccount("66666666-6666-4666-8666-666666666666", "smoke@example.com");
await getStore().setPlan(account.id, "pro");
const access = await accessFor(account.id);

const checked = await checkPackages(access, [{ ecosystem: "npm", name: "express", version: "4.17.1" }]);
if (JSON.stringify(checked.structuredContent).includes("\"isError\":true")) throw new Error("check_packages failed");

const real = await verifyPackageExists(access, { ecosystem: "npm", names: ["express"], maxSimilar: 1 });
const missing = await verifyPackageExists(access, { ecosystem: "npm", names: ["verhound-nonsense-package-name"], maxSimilar: 1 });
const realText = JSON.stringify(real.structuredContent);
const missingText = JSON.stringify(missing.structuredContent);
if (!realText.includes("\"exists\":true") || !missingText.includes("\"exists\":false")) {
  throw new Error("verify_package_exists did not match the registry");
}

const eol = await runtimeEolTool(access, "nodejs", "18");
if (!JSON.stringify(eol.structuredContent).includes("nodejs")) throw new Error("runtime_eol failed");

const auditContent = JSON.stringify({ dependencies: { express: "4.17.1" } });
const { auditManifest } = await import("../src/operations.js");
await auditManifest(access, { filename: "package.json", content: auditContent });
await planUpgrade(access, { ecosystem: "npm", name: "express", fromVersion: "4.17.1", toVersion: "4.18.2" });

await watchManifest(access, { label: "smoke", filename: "package.json", content: auditContent, alertEmail: "account" });
await getStore().updateWatchMeta(account.id, "smoke", { last_checked_at: "2000-01-01T00:00:00.000Z" });
process.env.CRON_SECRET = process.env.CRON_SECRET || "smoke-cron";
await executeCron(`Bearer ${process.env.CRON_SECRET}`, undefined, "http://127.0.0.1");
await listAlerts(access, { limit: 10 });
await unwatchManifest(access, "smoke");
console.log("live smoke finished");
