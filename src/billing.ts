import { nowMs } from "./clock.js";
import { TRIAL_DAYS, type Plan } from "./config.js";
import { configuredReviewerEmail, isReviewerAccount } from "./reviewer.js";
import { getStore } from "./store.js";

/** Set only when checkout, the webhook, and both price ids are present. No Stripe objects are created here. */
export function billingConfig(): { secretKey: string; webhookSecret: string; monthlyPrice: string; yearlyPrice: string } | null {
  const secretKey = process.env.STRIPE_SECRET_KEY?.trim() ?? "";
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET?.trim() ?? "";
  const monthlyPrice = process.env.STRIPE_PRICE_MONTHLY?.trim() ?? "";
  const yearlyPrice = process.env.STRIPE_PRICE_YEARLY?.trim() ?? "";
  if (!secretKey || !webhookSecret || !monthlyPrice || !yearlyPrice) return null;
  return { secretKey, webhookSecret, monthlyPrice, yearlyPrice };
}

export function isBillingConfigured(): boolean {
  return billingConfig() !== null;
}

export interface Access {
  accountId: string;
  plan: Plan;
  /** True when a trial existed and has ended. The account then uses the free plan. */
  expired: boolean;
  /** True when the account has no verified email. Tool calls are refused until it has one. */
  emailRequired: boolean;
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
      emailRequired: false,
      trialEndsAt: null,
      email: account?.email ?? configuredReviewerEmail()
    };
  }
  const account = await getStore().getAccount(accountId);
  const email = account?.email ?? null;
  if (account?.plan === "pro") {
    return { accountId, plan: "pro", expired: false, emailRequired: false, trialEndsAt: null, email };
  }
  if (isBillingConfigured()) {
    return {
      accountId,
      plan: "free",
      expired: account?.plan === "free",
      emailRequired: !email,
      trialEndsAt: null,
      email
    };
  }
  if (!email) {
    return { accountId, plan: "free", expired: false, emailRequired: true, trialEndsAt: null, email: null };
  }
  const started = account?.trial_started_at ?? account?.created_at ?? new Date(nowMs()).toISOString();
  const ends = trialEndsAt(started);
  const expired = nowMs() >= Date.parse(ends);
  return {
    accountId,
    plan: expired ? "free" : "trial",
    expired,
    emailRequired: false,
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
