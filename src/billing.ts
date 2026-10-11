import { nowMs } from "./clock.js";
import { TRIAL_DAYS, type Plan } from "./config.js";
import { configuredReviewerEmail, isReviewerAccount } from "./reviewer.js";
import { getStore } from "./store.js";

/** Checkout is not wired. Pro is an account flag, not a payment call. */
export function isBillingConfigured(): boolean {
  return false;
}

export interface Access {
  accountId: string;
  plan: Plan;
  expired: boolean;
  trialEndsAt: string | null;
  email: string | null;
}

export function trialEndsAt(startedIso: string, days = TRIAL_DAYS): string {
  const start = Date.parse(startedIso);
  const base = Number.isFinite(start) ? start : nowMs();
  return new Date(base + days * 24 * 60 * 60 * 1000).toISOString();
}

export async function accessFor(accountId: string): Promise<Access> {
  if (isReviewerAccount(accountId)) {
    const account = await getStore().getAccount(accountId);
    return {
      accountId,
      plan: "pro",
      expired: false,
      trialEndsAt: null,
      email: account?.email ?? configuredReviewerEmail()
    };
  }
  const account = await getStore().getAccount(accountId);
  const email = account?.email ?? null;
  if (account?.plan === "pro") {
    return { accountId, plan: "pro", expired: false, trialEndsAt: null, email };
  }
  const started = account?.trial_started_at ?? account?.created_at ?? new Date(nowMs()).toISOString();
  const ends = trialEndsAt(started);
  return {
    accountId,
    plan: "trial",
    expired: nowMs() >= Date.parse(ends),
    trialEndsAt: ends,
    email
  };
}

export async function isPro(accountId: string): Promise<boolean> {
  const access = await accessFor(accountId);
  return access.plan === "pro";
}

export async function planFor(accountId: string): Promise<Plan> {
  const access = await accessFor(accountId);
  return access.plan;
}
