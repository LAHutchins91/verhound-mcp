import type { NextFunction, Request, Response } from "express";
import { nowMs } from "./clock.js";
import { storageBackendName } from "./store.js";

const REQUIRED_IN_PRODUCTION = ["AUTH_SECRET", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

export type ConfigStatus = "ok" | "missing_required_env" | "memory_fallback" | "ephemeral_auth_secret";

/** Names (never values) of required env vars missing on a production deployment. */
export function missingProductionEnv(): string[] {
  if (process.env.VERCEL_ENV !== "production") return [];
  return REQUIRED_IN_PRODUCTION.filter((name) => !process.env[name]?.trim());
}

export function configStatus(): ConfigStatus {
  if (missingProductionEnv().length) return "missing_required_env";
  if (storageBackendName() === "memory") return "memory_fallback";
  if (!process.env.AUTH_SECRET?.trim()) return "ephemeral_auth_secret";
  return "ok";
}

let lastLogged = 0;

function logMissing(path: string, missing: string[]): void {
  const now = nowMs();
  if (now - lastLogged < 60_000) return;
  lastLogged = now;
  console.error(JSON.stringify({
    event: "config_missing",
    message: "Production is missing required environment variables, so /mcp, OAuth, and cron return 503.",
    missing,
    path
  }));
}

/** 503 for /mcp, OAuth, and cron when production is missing a required env var. */
export function failClosed(req: Request, res: Response, next: NextFunction): void {
  const missing = missingProductionEnv();
  if (!missing.length) return next();
  logMissing(req.path, missing);
  res.status(503).set("Retry-After", "300").json({ error: "This service is temporarily unavailable." });
}

export function resetConfigLogForTests(): void {
  lastLogged = 0;
}

export function cronBlocked(): boolean {
  const missing = missingProductionEnv();
  if (missing.length) logMissing("/api/cron/watch", missing);
  return missing.length > 0;
}
