import type { Express, Request, Response } from "express";
import { advisoryFromOsv, severityRank } from "./advisories.js";
import { nowDate, nowMs } from "./clock.js";
import { WATCH_STALE_MS, nextEtMidnight, publicBase, type Ecosystem } from "./config.js";
import { getMailer, type DigestAlert } from "./mailer.js";
import { recordNewAlert } from "./operations.js";
import { timingSafeEqualText } from "./reviewer.js";
import { cronBlocked } from "./runtime-config.js";
import { getStore, type AlertRecord, type WatchRecord } from "./store.js";
import { logCronTiming } from "./timing.js";
import { getVuln, queryBatch } from "./upstream/osv.js";
import { postWebhook, webhookHostLabel } from "./webhooks.js";

const BUDGET_MS = 20_000;
const RETRY_MS = 60 * 60 * 1000;

function authorized(authorization: string | undefined, alt: string | undefined): "ok" | "missing" | "rejected" {
  const secret = process.env.CRON_SECRET?.trim() ?? "";
  if (!secret) return "missing";
  const bearer = authorization?.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  const provided = bearer || (alt ?? "").trim();
  if (!provided || !timingSafeEqualText(provided, secret)) return "rejected";
  return "ok";
}

function isMalware(id: string, malicious: boolean | undefined): boolean {
  return malicious === true || id.startsWith("MAL-");
}

function meetsSeverity(level: string | undefined, minimum: string, malicious: boolean): boolean {
  if (malicious) return true;
  // Unknown level: alert rather than hide it.
  if (!level) return true;
  return severityRank(level) >= severityRank(minimum);
}

async function checkWatch(watch: WatchRecord): Promise<{ alerts: AlertRecord[]; failed: boolean }> {
  const store = getStore();
  const queries = watch.deps.map((dep) => ({
    ecosystem: dep.ecosystem as Ecosystem,
    name: dep.name,
    version: dep.version
  }));
  const batch = queries.length ? await queryBatch(queries) : { ids: [], notes: [], age: 0, stale: false };
  const failed = batch.notes.some((note) => note.includes("OSV.dev did not respond"));
  if (failed) {
    // Leave the watch due again in about an hour. Do not stamp it as checked for the full stale window.
    const stamp = new Date(nowMs() - WATCH_STALE_MS + RETRY_MS).toISOString();
    await store.updateWatchMeta(watch.account_id, watch.label, { last_checked_at: stamp });
    console.error(JSON.stringify({ event: "watch_check_failed" }));
    return { alerts: [], failed: true };
  }
  const created: AlertRecord[] = [];
  const ids = [...new Set(batch.ids.flat())];
  for (const id of ids) {
    let raw: unknown = null;
    try {
      raw = (await getVuln(id)).json;
    } catch {
      raw = null;
    }
    const advisory = raw ? advisoryFromOsv(raw) : null;
    const malicious = isMalware(id, advisory?.malicious);
    if (advisory && !meetsSeverity(advisory.severity?.level, watch.min_severity, malicious)) continue;
    for (let index = 0; index < watch.deps.length; index += 1) {
      const dep = watch.deps[index];
      if (!(batch.ids[index] ?? []).includes(id)) continue;
      const fresh = await store.markSeen(watch.id, id, dep.name, dep.version, nowDate().toISOString());
      if (!fresh || !watch.baseline_complete) continue;
      created.push(await recordNewAlert(watch, {
        watch_id: watch.id,
        account_id: watch.account_id,
        advisory_id: id,
        package: dep.name,
        version: dep.version,
        severity: advisory?.severity?.level ?? advisory?.severity?.score ?? null,
        first_fixed_version: advisory?.first_fixed_version ?? null,
        url: advisory?.url ?? `https://osv.dev/vulnerability/${id}`,
        malicious
      }));
    }
  }
  await store.updateWatchMeta(watch.account_id, watch.label, {
    last_checked_at: nowDate().toISOString(),
    baseline_complete: true
  });
  if (created.length && watch.webhook_url) {
    const text = webhookText(watch.label, created);
    const posted = await postWebhook(watch.webhook_url, text);
    if (posted !== "ok") {
      console.error(JSON.stringify({ event: "webhook_failed", host: webhookHostLabel(watch.webhook_url), result: posted }));
    }
  }
  return { alerts: created, failed: false };
}

function webhookText(label: string, alerts: AlertRecord[]): string {
  const ordered = [...alerts].sort((a, b) => Number(b.malicious) - Number(a.malicious));
  const lines = ordered.map((alert) => {
    const prefix = alert.malicious ? "Known malware record. " : "";
    return `${prefix}${alert.package}@${alert.version} ${alert.advisory_id} ${alert.url}`;
  });
  return [`Verhound: ${alerts.length} new advisories in ${label}`, ...lines, "Verhound has not changed your project."].join("\n");
}

export async function runWatchCron(baseUrl: string): Promise<{ checked: number; alerts: number; failed: number; remaining: number }> {
  const started = nowMs();
  const store = getStore();
  const olderThan = new Date(nowMs() - WATCH_STALE_MS).toISOString();
  const fresh: AlertRecord[] = [];
  let checked = 0;
  let failed = 0;
  while (nowMs() - started < BUDGET_MS) {
    const due = await store.listDueWatches(4, 0, olderThan);
    if (!due.length) break;
    let progressed = false;
    for (const watch of due) {
      if (nowMs() - started >= BUDGET_MS) break;
      const result = await checkWatch(watch);
      fresh.push(...result.alerts);
      if (result.failed) failed += 1;
      checked += 1;
      progressed = true;
    }
    if (!progressed) break;
  }
  const remaining = await store.countDueWatches(olderThan).catch(() => -1);
  if (remaining > 0) {
    console.error(JSON.stringify({ event: "watch_backlog", remaining, checked, failed }));
  }
  const byAccount = new Map<string, AlertRecord[]>();
  for (const alert of fresh) {
    const list = byAccount.get(alert.account_id) ?? [];
    list.push(alert);
    byAccount.set(alert.account_id, list);
  }
  const dayStart = new Date(nextEtMidnight().getTime() - 24 * 60 * 60 * 1000).toISOString();
  const mailer = getMailer();
  for (const [accountId, alerts] of byAccount) {
    const account = await store.getAccount(accountId);
    const email = account?.email;
    if (!email) continue;
    const ordered = [...alerts].sort((a, b) => Number(b.malicious) - Number(a.malicious));
    const malware = ordered.filter((alert) => alert.malicious);
    const rest = ordered.filter((alert) => !alert.malicious);
    const already = await store.emailedOnDay(accountId, dayStart);
    const batches = [
      malware,
      already ? [] : rest
    ];
    for (const batch of batches) {
      if (!batch.length) continue;
      try {
        await mailer.sendAlert(email, { alerts: batch.map(digestAlert), accountUrl: `${baseUrl}/account` });
        await store.markEmailed(batch.map((alert) => alert.id), nowDate().toISOString());
      } catch (error) {
        const name = error instanceof Error ? error.name : "Error";
        console.error(JSON.stringify({ event: "alert_email_failed", name }));
      }
    }
  }
  const purgeBefore = new Date(nowMs() - 7 * 24 * 60 * 60 * 1000).toISOString();
  await store.purgeExpiredCache(purgeBefore).catch(() => 0);
  logCronTiming(checked, fresh.length, nowMs() - started, Math.max(0, remaining), failed);
  return { checked, alerts: fresh.length, failed, remaining: Math.max(0, remaining) };
}

function digestAlert(alert: AlertRecord): DigestAlert {
  return {
    label: alert.label,
    package: alert.package,
    version: alert.version,
    advisory_id: alert.advisory_id,
    severity: alert.severity,
    first_fixed_version: alert.first_fixed_version,
    url: alert.url,
    malicious: alert.malicious
  };
}

export async function executeCron(authorization: string | undefined, cronSecretHeader: string | undefined, baseUrl: string): Promise<{ status: number; body: Record<string, unknown> }> {
  if (cronBlocked()) return { status: 503, body: { ok: false, error: "This service is temporarily unavailable." } };
  const verdict = authorized(authorization, cronSecretHeader);
  if (verdict === "missing") return { status: 503, body: { ok: false, error: "Cron is not configured." } };
  if (verdict === "rejected") return { status: 401, body: { ok: false, error: "Cron credentials were rejected." } };
  const result = await runWatchCron(baseUrl);
  return { status: 200, body: { ok: true, ...result } };
}

export function installCron(app: Express): void {
  const handler = async (req: Request, res: Response) => {
    const result = await executeCron(req.header("authorization"), req.header("x-cron-secret"), publicBase(req));
    res.status(result.status).json(result.body);
  };
  app.get("/api/cron/watch", handler);
  app.post("/api/cron/watch", handler);
}
