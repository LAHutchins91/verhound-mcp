import type { Access } from "./billing.js";
import { capMessage, etDay, limitsFor, overPlanLimitMessage, trialEndedMessage } from "./config.js";
import { getStore } from "./store.js";

export async function beginCall(access: Access, kind: "call" | "plan_upgrade", extras: { packages?: number; bytes?: number } = {}): Promise<string | null> {
  if (access.expired) return trialEndedMessage();
  const limits = limitsFor(access.plan);
  const packages = extras.packages ?? 0;
  const bytes = extras.bytes ?? 0;
  const oversized = packages > limits.packagesPerCall || bytes > limits.manifestBytes;
  const delta = {
    calls: 1,
    packages: oversized ? 0 : packages,
    planUpgrade: kind === "plan_upgrade" ? 1 : 0
  };
  const result = await getStore().tryConsumeCall(access.accountId, etDay(), delta, {
    calls: limits.callsPerDay,
    planUpgrade: limits.planUpgradePerDay
  });
  if (!result.allowed) return capMessage();
  if (oversized) return overPlanLimitMessage();
  return null;
}
