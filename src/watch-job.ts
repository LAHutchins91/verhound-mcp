import type { Express, Request, Response } from "express";
import { advisoryFromOsv, severityRank } from "./advisories.js";
import { nowDate, nowMs } from "./clock.js";
import { nextEtMidnight, publicBase } from "./config.js";
import { getMailer } from "./mailer.js";
import { recordNewAlert } from "./operations.js";
import { timingSafeEqualText } from "./reviewer.js";
import { getStore, type AlertRecord, type WatchRecord } from "./store.js";
import { logCronTiming } from "./timing.js";
import { getVuln, queryBatch } from "./upstream/osv.js";
import type { Ecosystem } from "./config.js";

const BUDGET_MS = 20_000;
const STALE_MS = 20 * 60 * 60 * 1000;

function authorized(authorization: string | undefined, alt: string | undefined): "ok" | "missing" | "rejected" {
  const secret = process.env.CRON_SECRET?.trim() ?? "";
  if (!secret) return "missing";
  const bearer = authorization?.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  const provided = bearer || (alt ?? "").trim();
  if (!provided || !timingSafeEqualText(provided, secret)) return "rejected";
  return "ok";
}

function meetsSeverity(score: string | undefined, minimum: string): boolean {
  if (!score) return true;
  return severityRank(score) >= severityRank(minimum);
}

async function checkWatch(watch: WatchRecord): Promise<AlertRecord[]> {
  const store = getStore();
  const queries = watch.deps.map((dep) => ({
    ecosystem: dep.ecosystem as Ecosystem,
    name: dep.name,
    version: dep.version
  }));
  const batch = queries.length ? await queryBatch(queries) : { ids: [], notes: [], age: 0, stale: false };
  const failed = batch.notes.some((note) => note.includes("OSV.dev did not respond"));
  if (failed) {
    await store.updateWatchMeta(watch.account_id, watch.label, { last_checked_at: nowDate().toISOString() });
    return [];
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
    if (advisory && !meetsSeverity(advisory.severity?.score, watch.min_severity)) continue;
    for (let index = 0; index < watch.deps.length; index += 1) {
      const dep = watch.deps[index];
      if (!(batch.ids[index] ?? []).includes(id)) continue;
      const fresh = await store.markSeen(watch.id, id, dep.name, dep.version, nowDate().toISOString());
      if (!fresh || !watch.baseline_complete) continue;
      created.push(await recordNewAlert(watch, {
        watch_id: watch.id,
        account_id: watch.account_id,
        label: watch.label,
        advisory_id: id,
        package: dep.name,
        version: dep.version,
        severity: advisory?.severity?.score ?? null,
        first_fixed_version: advisory?.first_fixed_version ?? null,
        url: advisory?.url ?? `https://osv.dev/vulnerability/${id}`
      }));
    }
  }
  await store.updateWatchMeta(watch.account_id, watch.label, {
    last_checked_at: nowDate().toISOString(),
    baseline_complete: true
  });
  return created;
}

export async function runWatchCron(baseUrl: string): Promise<{ checked: number; alerts: number }> {
  const started = nowMs();
  const store = getStore();
  const olderThan = new Date(nowMs() - STALE_MS).toISOString();
  const fresh: AlertRecord[] = [];
  let checked = 0;
  while (nowMs() - started < BUDGET_MS && checked < 40) {
    const due = await store.listDueWatches(4, 0, olderThan);
    if (!due.length) break;
    for (const watch of due) {
      if (nowMs() - started >= BUDGET_MS) break;
      fresh.push(...await checkWatch(watch));
      checked += 1;
    }
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
    if (await store.emailedOnDay(accountId, dayStart)) continue;
    try {
      await mailer.sendAlert(email, { alerts: alerts.map((alert) => ({
        label: alert.label,
        package: alert.package,
        version: alert.version,
        advisory_id: alert.advisory_id,
        severity: alert.severity,
        first_fixed_version: alert.first_fixed_version,
        url: alert.url
      })), accountUrl: `${baseUrl}/account` });
      await store.markEmailed(alerts.map((alert) => alert.id), nowDate().toISOString());
    } catch (error) {
      const name = error instanceof Error ? error.name : "Error";
      console.error(JSON.stringify({ event: "alert_email_failed", name }));
    }
  }
  const purgeBefore = new Date(nowMs() - 7 * 24 * 60 * 60 * 1000).toISOString();
  await store.purgeExpiredCache(purgeBefore).catch(() => 0);
  logCronTiming(checked, fresh.length, nowMs() - started);
  return { checked, alerts: fresh.length };
}

export async function executeCron(authorization: string | undefined, cronSecretHeader: string | undefined, baseUrl: string): Promise<{ status: number; body: Record<string, unknown> }> {
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
