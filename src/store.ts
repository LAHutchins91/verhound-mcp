import crypto from "node:crypto";
import { nowDate } from "./clock.js";
import type { Plan } from "./config.js";

export interface Account {
  id: string;
  email: string | null;
  plan: Plan;
  created_at: string;
  trial_started_at: string;
}

export interface UsageRow {
  calls: number;
  packages: number;
  plan_upgrade_calls: number;
}

export interface CacheRow {
  key: string;
  source: string;
  body: unknown;
  etag: string | null;
  last_modified: string | null;
  fetched_at: string;
  expires_at: string;
}

export interface DepRecord {
  ecosystem: string;
  name: string;
  version: string;
}

export interface WatchRecord {
  id: string;
  account_id: string;
  label: string;
  filename: string;
  ecosystem_summary: Record<string, number>;
  deps: DepRecord[];
  min_severity: string;
  created_at: string;
  updated_at: string;
  last_checked_at: string | null;
  baseline_complete: boolean;
  email: string | null;
}

export interface AlertRecord {
  id: string;
  watch_id: string;
  account_id: string;
  label: string;
  advisory_id: string;
  package: string;
  version: string;
  severity: string | null;
  first_fixed_version: string | null;
  url: string;
  detected_at: string;
  emailed_at: string | null;
}

export interface ConsumeResult {
  allowed: boolean;
  usage: UsageRow;
}

export interface DataStore {
  backend: "memory" | "supabase";
  ensureAccount(id: string, email?: string | null, plan?: Plan): Promise<Account>;
  getAccount(id: string): Promise<Account | null>;
  setPlan(id: string, plan: Plan): Promise<void>;
  deleteAccount(id: string): Promise<void>;
  tryConsumeCall(accountId: string, day: string, delta: { calls: number; packages: number; planUpgrade: number }, limits: { calls: number; planUpgrade: number }): Promise<ConsumeResult>;
  getCache(key: string): Promise<CacheRow | null>;
  putCache(row: CacheRow): Promise<void>;
  purgeExpiredCache(beforeIso: string): Promise<number>;
  getUpstreamCount(source: string, month: string): Promise<number>;
  addUpstreamCount(source: string, month: string, delta: number): Promise<number>;
  saveWatch(watch: Omit<WatchRecord, "id" | "created_at" | "updated_at"> & { id?: string }): Promise<WatchRecord>;
  updateWatchMeta(accountId: string, label: string, patch: Partial<Pick<WatchRecord, "last_checked_at" | "baseline_complete" | "email">>): Promise<void>;
  listWatches(accountId: string): Promise<WatchRecord[]>;
  getWatch(accountId: string, label: string): Promise<WatchRecord | null>;
  deleteWatch(accountId: string, label: string): Promise<boolean>;
  countWatches(accountId: string): Promise<number>;
  listDueWatches(limit: number, offset: number, olderThanIso: string): Promise<WatchRecord[]>;
  markSeen(watchId: string, advisoryId: string, pkg: string, version: string, at: string): Promise<boolean>;
  addAlert(alert: AlertRecord): Promise<void>;
  listAlerts(accountId: string, opts: { label?: string; since?: string; limit: number }): Promise<AlertRecord[]>;
  markEmailed(ids: string[], at: string): Promise<void>;
  emailedOnDay(accountId: string, dayStartIso: string): Promise<boolean>;
}

const locks = new Map<string, Promise<unknown>>();

function locked<T>(key: string, fn: () => Promise<T> | T): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  locks.set(key, run.then(() => undefined, () => undefined));
  return run;
}

function emptyUsage(): UsageRow {
  return { calls: 0, packages: 0, plan_upgrade_calls: 0 };
}

class MemoryStore implements DataStore {
  backend = "memory" as const;
  accounts = new Map<string, Account>();
  usage = new Map<string, UsageRow>();
  cache = new Map<string, CacheRow>();
  upstream = new Map<string, number>();
  watches = new Map<string, WatchRecord>();
  seen = new Set<string>();
  alerts: AlertRecord[] = [];

  async ensureAccount(id: string, email?: string | null, plan?: Plan): Promise<Account> {
    const existing = this.accounts.get(id);
    if (existing) {
      if (email && !existing.email) existing.email = email;
      if (plan === "pro") existing.plan = "pro";
      return existing;
    }
    const createdAt = nowDate().toISOString();
    const account: Account = {
      id,
      email: email ?? null,
      plan: plan ?? "trial",
      created_at: createdAt,
      trial_started_at: createdAt
    };
    this.accounts.set(id, account);
    return account;
  }

  async getAccount(id: string): Promise<Account | null> {
    return this.accounts.get(id) ?? null;
  }

  async setPlan(id: string, plan: Plan): Promise<void> {
    const account = await this.ensureAccount(id);
    account.plan = plan;
  }

  async deleteAccount(id: string): Promise<void> {
    this.accounts.delete(id);
    for (const key of [...this.usage.keys()]) {
      if (key.startsWith(`${id}|`)) this.usage.delete(key);
    }
    const watchIds = new Set<string>();
    for (const [key, watch] of this.watches) {
      if (watch.account_id === id) {
        watchIds.add(watch.id);
        this.watches.delete(key);
      }
    }
    for (const key of [...this.seen]) {
      const watchId = key.split("|")[0];
      if (watchIds.has(watchId)) this.seen.delete(key);
    }
    this.alerts = this.alerts.filter((alert) => alert.account_id !== id);
  }

  async tryConsumeCall(accountId: string, day: string, delta: { calls: number; packages: number; planUpgrade: number }, limits: { calls: number; planUpgrade: number }): Promise<ConsumeResult> {
    return locked(`usage:${accountId}:${day}`, () => {
      const key = `${accountId}|${day}`;
      const row = this.usage.get(key) ?? emptyUsage();
      const nextCalls = row.calls + delta.calls;
      const nextPlan = row.plan_upgrade_calls + delta.planUpgrade;
      if (nextCalls > limits.calls || nextPlan > limits.planUpgrade) {
        return { allowed: false, usage: { ...row } };
      }
      const next = {
        calls: nextCalls,
        packages: row.packages + delta.packages,
        plan_upgrade_calls: nextPlan
      };
      this.usage.set(key, next);
      return { allowed: true, usage: next };
    });
  }

  async getCache(key: string): Promise<CacheRow | null> {
    return this.cache.get(key) ?? null;
  }

  async putCache(row: CacheRow): Promise<void> {
    if (this.cache.size > 6000 && !this.cache.has(row.key)) {
      const first = this.cache.keys().next().value;
      if (first) this.cache.delete(first);
    }
    this.cache.set(row.key, row);
  }

  async purgeExpiredCache(beforeIso: string): Promise<number> {
    let removed = 0;
    for (const [key, row] of this.cache) {
      if (row.expires_at < beforeIso) {
        this.cache.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  async getUpstreamCount(source: string, month: string): Promise<number> {
    return this.upstream.get(`${source}|${month}`) ?? 0;
  }

  async addUpstreamCount(source: string, month: string, delta: number): Promise<number> {
    return locked(`up:${source}:${month}`, () => {
      const key = `${source}|${month}`;
      const next = (this.upstream.get(key) ?? 0) + delta;
      this.upstream.set(key, next);
      return next;
    });
  }

  async saveWatch(input: Omit<WatchRecord, "id" | "created_at" | "updated_at"> & { id?: string }): Promise<WatchRecord> {
    const key = `${input.account_id}|${input.label}`;
    const existing = this.watches.get(key);
    const now = nowDate().toISOString();
    const watch: WatchRecord = {
      ...input,
      id: existing?.id ?? input.id ?? crypto.randomUUID(),
      created_at: existing?.created_at ?? now,
      updated_at: now
    };
    this.watches.set(key, watch);
    if (existing) {
      for (const seenKey of [...this.seen]) {
        if (seenKey.startsWith(`${watch.id}|`)) this.seen.delete(seenKey);
      }
      this.alerts = this.alerts.filter((alert) => alert.watch_id !== watch.id);
    }
    return watch;
  }

  async updateWatchMeta(accountId: string, label: string, patch: Partial<Pick<WatchRecord, "last_checked_at" | "baseline_complete" | "email">>): Promise<void> {
    const watch = this.watches.get(`${accountId}|${label}`);
    if (!watch) return;
    Object.assign(watch, patch, { updated_at: nowDate().toISOString() });
  }

  async listWatches(accountId: string): Promise<WatchRecord[]> {
    return [...this.watches.values()].filter((watch) => watch.account_id === accountId);
  }

  async getWatch(accountId: string, label: string): Promise<WatchRecord | null> {
    return this.watches.get(`${accountId}|${label}`) ?? null;
  }

  async deleteWatch(accountId: string, label: string): Promise<boolean> {
    const watch = this.watches.get(`${accountId}|${label}`);
    if (!watch) return false;
    this.watches.delete(`${accountId}|${label}`);
    for (const key of [...this.seen]) {
      if (key.startsWith(`${watch.id}|`)) this.seen.delete(key);
    }
    this.alerts = this.alerts.filter((alert) => alert.watch_id !== watch.id);
    return true;
  }

  async countWatches(accountId: string): Promise<number> {
    return (await this.listWatches(accountId)).length;
  }

  async listDueWatches(limit: number, offset: number, olderThanIso: string): Promise<WatchRecord[]> {
    const due = [...this.watches.values()].filter((watch) => !watch.last_checked_at || watch.last_checked_at < olderThanIso);
    due.sort((a, b) => {
      if (!a.last_checked_at && b.last_checked_at) return -1;
      if (a.last_checked_at && !b.last_checked_at) return 1;
      return (a.last_checked_at ?? "").localeCompare(b.last_checked_at ?? "");
    });
    return due.slice(offset, offset + limit);
  }

  async markSeen(watchId: string, advisoryId: string, pkg: string, version: string, _at: string): Promise<boolean> {
    const key = `${watchId}|${advisoryId}|${pkg}|${version}`;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }

  async addAlert(alert: AlertRecord): Promise<void> {
    this.alerts.push(alert);
  }

  async listAlerts(accountId: string, opts: { label?: string; since?: string; limit: number }): Promise<AlertRecord[]> {
    return this.alerts
      .filter((alert) => alert.account_id === accountId)
      .filter((alert) => !opts.label || alert.label === opts.label)
      .filter((alert) => !opts.since || alert.detected_at >= opts.since)
      .sort((a, b) => b.detected_at.localeCompare(a.detected_at))
      .slice(0, opts.limit);
  }

  async markEmailed(ids: string[], at: string): Promise<void> {
    const wanted = new Set(ids);
    for (const alert of this.alerts) {
      if (wanted.has(alert.id)) alert.emailed_at = at;
    }
  }

  async emailedOnDay(accountId: string, dayStartIso: string): Promise<boolean> {
    return this.alerts.some((alert) => alert.account_id === accountId && alert.emailed_at !== null && alert.emailed_at >= dayStartIso);
  }
}

function supabaseConfigured(): boolean {
  return Boolean(process.env.SUPABASE_URL?.trim() && process.env.SUPABASE_SERVICE_ROLE_KEY?.trim());
}

function sbConfig(): { url: string; key: string } {
  return {
    url: (process.env.SUPABASE_URL ?? "").replace(/\/$/, ""),
    key: process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
  };
}

async function sb(path: string, init: RequestInit & { prefer?: string } = {}): Promise<Response> {
  const { url, key } = sbConfig();
  const headers = new Headers(init.headers);
  headers.set("apikey", key);
  headers.set("Authorization", `Bearer ${key}`);
  headers.set("Content-Type", "application/json");
  if (init.prefer) headers.set("Prefer", init.prefer);
  return fetch(`${url}/rest/v1/${path}`, { ...init, headers });
}

class SupabaseStore implements DataStore {
  backend = "supabase" as const;

  async ensureAccount(id: string, email?: string | null, plan?: Plan): Promise<Account> {
    const existing = await this.getAccount(id);
    if (!existing) {
      const createdAt = nowDate().toISOString();
      const created: Account = { id, email: email ?? null, plan: plan ?? "trial", created_at: createdAt, trial_started_at: createdAt };
      const response = await sb("accounts", { method: "POST", prefer: "return=representation", body: JSON.stringify(created) });
      if (!response.ok) throw new Error("Could not save the account.");
      const rows = await response.json() as Account[];
      return rows[0] ?? created;
    }
    if ((email && email !== existing.email) || (plan === "pro" && existing.plan !== "pro")) {
      const patch: Partial<Account> = {};
      if (email && !existing.email) patch.email = email;
      if (plan === "pro") patch.plan = "pro";
      if (Object.keys(patch).length) {
        await sb(`accounts?id=eq.${encodeURIComponent(id)}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify(patch) });
        return { ...existing, ...patch };
      }
    }
    return existing;
  }

  async getAccount(id: string): Promise<Account | null> {
    const response = await sb(`accounts?id=eq.${encodeURIComponent(id)}&select=*`, { method: "GET" });
    if (!response.ok) throw new Error("Could not read the account.");
    const rows = await response.json() as Account[];
    return rows[0] ?? null;
  }

  async setPlan(id: string, plan: Plan): Promise<void> {
    await this.ensureAccount(id);
    const response = await sb(`accounts?id=eq.${encodeURIComponent(id)}`, {
      method: "PATCH",
      prefer: "return=minimal",
      body: JSON.stringify({ plan })
    });
    if (!response.ok) throw new Error("Could not update the plan.");
  }

  async deleteAccount(id: string): Promise<void> {
    const encoded = encodeURIComponent(id);
    await sb(`alerts?account_id=eq.${encoded}`, { method: "DELETE", prefer: "return=minimal" });
    await sb(`watches?account_id=eq.${encoded}`, { method: "DELETE", prefer: "return=minimal" });
    await sb(`usage_daily?account_id=eq.${encoded}`, { method: "DELETE", prefer: "return=minimal" });
    await sb(`accounts?id=eq.${encoded}`, { method: "DELETE", prefer: "return=minimal" });
  }

  async tryConsumeCall(accountId: string, day: string, delta: { calls: number; packages: number; planUpgrade: number }, limits: { calls: number; planUpgrade: number }): Promise<ConsumeResult> {
    const response = await sb("rpc/consume_usage", {
      method: "POST",
      body: JSON.stringify({
        p_account_id: accountId,
        p_day: day,
        p_calls: delta.calls,
        p_packages: delta.packages,
        p_plan: delta.planUpgrade,
        p_call_limit: limits.calls,
        p_plan_limit: limits.planUpgrade
      })
    });
    if (!response.ok) throw new Error("Could not record usage.");
    const body = await response.json() as { allowed: boolean; calls: number; packages: number; plan_upgrade_calls: number };
    return {
      allowed: Boolean(body.allowed),
      usage: {
        calls: Number(body.calls ?? 0),
        packages: Number(body.packages ?? 0),
        plan_upgrade_calls: Number(body.plan_upgrade_calls ?? 0)
      }
    };
  }

  async getCache(key: string): Promise<CacheRow | null> {
    const response = await sb(`cache_entries?key=eq.${encodeURIComponent(key)}&select=*`, { method: "GET" });
    if (!response.ok) return null;
    const rows = await response.json() as CacheRow[];
    return rows[0] ?? null;
  }

  async putCache(row: CacheRow): Promise<void> {
    const response = await sb("cache_entries?on_conflict=key", {
      method: "POST",
      prefer: "resolution=merge-duplicates,return=minimal",
      body: JSON.stringify(row)
    });
    if (!response.ok) throw new Error("Could not write the cache.");
  }

  async purgeExpiredCache(beforeIso: string): Promise<number> {
    const response = await sb("rpc/purge_expired_cache", { method: "POST", body: JSON.stringify({ p_before: beforeIso }) });
    if (!response.ok) return 0;
    const body = await response.json() as number;
    return Number(body) || 0;
  }

  async getUpstreamCount(source: string, month: string): Promise<number> {
    const response = await sb(`upstream_usage?source=eq.${encodeURIComponent(source)}&month=eq.${month}&select=requests`, { method: "GET" });
    if (!response.ok) return 0;
    const rows = await response.json() as { requests: number }[];
    return Number(rows[0]?.requests ?? 0);
  }

  async addUpstreamCount(source: string, month: string, delta: number): Promise<number> {
    const response = await sb("rpc/add_upstream_usage", {
      method: "POST",
      body: JSON.stringify({ p_source: source, p_month: month, p_delta: delta })
    });
    if (!response.ok) throw new Error("Could not record upstream usage.");
    return Number(await response.json());
  }

  async saveWatch(input: Omit<WatchRecord, "id" | "created_at" | "updated_at"> & { id?: string }): Promise<WatchRecord> {
    const existing = await this.getWatch(input.account_id, input.label);
    const now = nowDate().toISOString();
    const watch: WatchRecord = {
      ...input,
      id: existing?.id ?? input.id ?? crypto.randomUUID(),
      created_at: existing?.created_at ?? now,
      updated_at: now
    };
    const response = await sb("watches?on_conflict=account_id,label", {
      method: "POST",
      prefer: "resolution=merge-duplicates,return=representation",
      body: JSON.stringify(watch)
    });
    if (!response.ok) throw new Error("Could not save the watch.");
    if (existing) {
      await sb(`watch_seen?watch_id=eq.${encodeURIComponent(watch.id)}`, { method: "DELETE", prefer: "return=minimal" });
      await sb(`alerts?watch_id=eq.${encodeURIComponent(watch.id)}`, { method: "DELETE", prefer: "return=minimal" });
    }
    const rows = await response.json() as WatchRecord[];
    return rows[0] ?? watch;
  }

  async updateWatchMeta(accountId: string, label: string, patch: Partial<Pick<WatchRecord, "last_checked_at" | "baseline_complete" | "email">>): Promise<void> {
    const response = await sb(`watches?account_id=eq.${encodeURIComponent(accountId)}&label=eq.${encodeURIComponent(label)}`, {
      method: "PATCH",
      prefer: "return=minimal",
      body: JSON.stringify({ ...patch, updated_at: nowDate().toISOString() })
    });
    if (!response.ok) throw new Error("Could not update the watch.");
  }

  async listWatches(accountId: string): Promise<WatchRecord[]> {
    const response = await sb(`watches?account_id=eq.${encodeURIComponent(accountId)}&select=*`, { method: "GET" });
    if (!response.ok) throw new Error("Could not list watches.");
    return await response.json() as WatchRecord[];
  }

  async getWatch(accountId: string, label: string): Promise<WatchRecord | null> {
    const response = await sb(`watches?account_id=eq.${encodeURIComponent(accountId)}&label=eq.${encodeURIComponent(label)}&select=*`, { method: "GET" });
    if (!response.ok) throw new Error("Could not read the watch.");
    const rows = await response.json() as WatchRecord[];
    return rows[0] ?? null;
  }

  async deleteWatch(accountId: string, label: string): Promise<boolean> {
    const existing = await this.getWatch(accountId, label);
    if (!existing) return false;
    const response = await sb(`watches?id=eq.${encodeURIComponent(existing.id)}`, { method: "DELETE", prefer: "return=minimal" });
    if (!response.ok) throw new Error("Could not delete the watch.");
    return true;
  }

  async countWatches(accountId: string): Promise<number> {
    const response = await sb(`watches?account_id=eq.${encodeURIComponent(accountId)}&select=id`, {
      method: "GET",
      headers: { Prefer: "count=exact" }
    });
    const range = response.headers.get("content-range");
    if (range && range.includes("/")) {
      const total = Number(range.split("/")[1]);
      if (Number.isFinite(total)) return total;
    }
    const rows = await response.json() as unknown[];
    return rows.length;
  }

  async listDueWatches(limit: number, offset: number, olderThanIso: string): Promise<WatchRecord[]> {
    const path = `watches?or=(last_checked_at.is.null,last_checked_at.lt.${encodeURIComponent(olderThanIso)})&order=last_checked_at.asc.nullsfirst&limit=${limit}&offset=${offset}&select=*`;
    const response = await sb(path, { method: "GET" });
    if (!response.ok) throw new Error("Could not list due watches.");
    return await response.json() as WatchRecord[];
  }

  async markSeen(watchId: string, advisoryId: string, pkg: string, version: string, at: string): Promise<boolean> {
    const response = await sb("watch_seen?on_conflict=watch_id,advisory_id,package,version", {
      method: "POST",
      prefer: "resolution=ignore-duplicates,return=representation",
      body: JSON.stringify({ watch_id: watchId, advisory_id: advisoryId, package: pkg, version, first_seen_at: at })
    });
    if (!response.ok) throw new Error("Could not record a seen advisory.");
    const rows = await response.json() as unknown[];
    return rows.length > 0;
  }

  async addAlert(alert: AlertRecord): Promise<void> {
    const response = await sb("alerts", { method: "POST", prefer: "return=minimal", body: JSON.stringify(alert) });
    if (!response.ok) throw new Error("Could not record an alert.");
  }

  async listAlerts(accountId: string, opts: { label?: string; since?: string; limit: number }): Promise<AlertRecord[]> {
    let path = `alerts?account_id=eq.${encodeURIComponent(accountId)}&select=*,watches(label)&order=detected_at.desc&limit=${opts.limit}`;
    if (opts.since) path += `&detected_at=gte.${encodeURIComponent(opts.since)}`;
    if (opts.label) path += `&watches.label=eq.${encodeURIComponent(opts.label)}`;
    const response = await sb(path, { method: "GET" });
    if (!response.ok) throw new Error("Could not list alerts.");
    const rows = await response.json() as (AlertRecord & { watches?: { label?: string } | { label?: string }[] })[];
    return rows.map((row) => {
      const embedded = Array.isArray(row.watches) ? row.watches[0] : row.watches;
      return { ...row, label: row.label || embedded?.label || "" };
    });
  }

  async markEmailed(ids: string[], at: string): Promise<void> {
    if (!ids.length) return;
    const list = ids.map((id) => `"${id}"`).join(",");
    const response = await sb(`alerts?id=in.(${list})`, {
      method: "PATCH",
      prefer: "return=minimal",
      body: JSON.stringify({ emailed_at: at })
    });
    if (!response.ok) throw new Error("Could not mark alerts emailed.");
  }

  async emailedOnDay(accountId: string, dayStartIso: string): Promise<boolean> {
    const response = await sb(`alerts?account_id=eq.${encodeURIComponent(accountId)}&emailed_at=gte.${encodeURIComponent(dayStartIso)}&select=id&limit=1`, { method: "GET" });
    if (!response.ok) return false;
    const rows = await response.json() as unknown[];
    return rows.length > 0;
  }
}

let memory = new MemoryStore();
let supabase: SupabaseStore | null = null;

export function storageBackendName(): "memory" | "supabase" {
  if (process.env.VITEST && process.env.VERHOUND_USE_SUPABASE !== "1") return "memory";
  return supabaseConfigured() ? "supabase" : "memory";
}

export function getStore(): DataStore {
  if (storageBackendName() === "supabase") {
    if (!supabase) supabase = new SupabaseStore();
    return supabase;
  }
  return memory;
}

export function resetStoreForTests(): void {
  memory = new MemoryStore();
  supabase = null;
  locks.clear();
}

export function memoryStoreForTests(): MemoryStore {
  return memory;
}
