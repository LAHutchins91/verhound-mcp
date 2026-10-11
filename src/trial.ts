import crypto from "node:crypto";
import { nowDate } from "./clock.js";
import { getStore } from "./store.js";

const GMAIL_DOMAINS = new Set(["gmail.com", "googlemail.com"]);

/**
 * Normalize an email for the one-trial-per-person check only.
 * Lowercases, drops a +tag, and for Gmail drops dots and maps googlemail.com to gmail.com.
 * The account keeps the address as entered.
 */
export function normalizeTrialEmail(email: string): string {
  const value = email.trim().toLowerCase();
  const at = value.lastIndexOf("@");
  if (at <= 0) return value;
  let local = value.slice(0, at);
  let domain = value.slice(at + 1);
  const plus = local.indexOf("+");
  if (plus >= 0) local = local.slice(0, plus);
  if (GMAIL_DOMAINS.has(domain)) {
    local = local.replace(/\./g, "");
    domain = "gmail.com";
  }
  return `${local}@${domain}`;
}

/** Stored instead of the address, so the marker can outlive account deletion without keeping the email. */
export function trialKey(email: string): string {
  return crypto.createHash("sha256").update(`verhound-trial-v1\0${normalizeTrialEmail(email)}`).digest("hex");
}

/**
 * Record the trial for this verified email. If the normalized email already used a trial,
 * the account's trial start moves back to that first use, so the trial is not repeated.
 */
export async function applyTrialMarker(accountId: string, email: string): Promise<void> {
  const store = getStore();
  const firstUsed = await store.claimTrial(trialKey(email), accountId, nowDate().toISOString());
  const account = await store.getAccount(accountId);
  if (!account || account.plan === "pro") return;
  if (Date.parse(firstUsed) < Date.parse(account.trial_started_at)) {
    await store.setTrialStart(accountId, firstUsed);
  }
}
