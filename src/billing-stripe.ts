import crypto from "node:crypto";
import type { Express, Request, Response } from "express";
import { accountIdFromRequest, readCookie } from "./auth.js";
import { billingConfig, isBillingConfigured } from "./billing.js";
import { nowDate } from "./clock.js";
import { PUBLIC_BRAND, TRIAL_DAYS, publicBase } from "./config.js";
import { page } from "./html.js";
import { getStore } from "./store.js";
import { trialKey } from "./trial.js";

const PAGE_CSRF = "verhound_page";
/** Stamped on every Verhound checkout and subscription. The Stripe account is shared with other apps. */
export const VERHOUND_APP = "verhound";
const TOLERANCE_SEC = 300;
const rawBodies = new WeakMap<Request, Buffer>();

export function captureStripeRawBody(req: Request, buf: Buffer): void {
  rawBodies.set(req, Buffer.from(buf));
}

export function verifyStripeSignature(payload: string, header: string, secret: string, nowSec = Math.floor(Date.now() / 1000)): boolean {
  let timestamp = "";
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t") timestamp = value;
    if (key === "v1" && value) signatures.push(value);
  }
  const t = Number(timestamp);
  if (!timestamp || !signatures.length || !Number.isFinite(t) || Math.abs(nowSec - t) > TOLERANCE_SEC) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
  const expectedBuf = Buffer.from(expected);
  return signatures.some((signature) => {
    const got = Buffer.from(signature);
    return got.length === expectedBuf.length && crypto.timingSafeEqual(got, expectedBuf);
  });
}

export function planForSubscriptionStatus(status: string): "pro" | "free" {
  return status === "active" || status === "trialing" ? "pro" : "free";
}

/** 7 days only when this normalized email has not already used a trial. */
export async function stripeTrialDays(email: string | null): Promise<number | null> {
  if (!email) return null;
  const used = await getStore().hasTrial(trialKey(email));
  return used ? null : TRIAL_DAYS;
}

function accountIdOf(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) ? value : null;
}

function customerIdOf(value: unknown): string | null {
  if (typeof value !== "string" || !/^cus_[A-Za-z0-9]+$/.test(value) || value.length > 255) return null;
  return value;
}

function textField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

async function stripeForm(path: string, fields: Record<string, string>, secretKey: string): Promise<Record<string, unknown>> {
  const response = await fetch(`https://api.stripe.com${path}`, {
    method: "POST",
    redirect: "manual",
    signal: AbortSignal.timeout(8_000),
    headers: {
      Authorization: `Bearer ${secretKey}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams(fields).toString()
  });
  if (response.status >= 300 && response.status < 400) throw new Error("Stripe redirected the request.");
  if (!response.ok) throw new Error("Stripe did not accept the request.");
  const body = await response.json() as unknown;
  if (!body || typeof body !== "object") throw new Error("Stripe returned an unexpected response.");
  return body as Record<string, unknown>;
}

export async function createCheckoutSession(input: { accountId: string; email: string | null; customerId?: string | null; interval: "monthly" | "yearly"; origin: string }): Promise<string> {
  const config = billingConfig();
  if (!config) throw new Error("Billing is not configured.");
  const trialDays = await stripeTrialDays(input.email);
  const fields: Record<string, string> = {
    mode: "subscription",
    "line_items[0][price]": input.interval === "yearly" ? config.yearlyPrice : config.monthlyPrice,
    "line_items[0][quantity]": "1",
    success_url: `${input.origin}/account?billing=return`,
    cancel_url: `${input.origin}/checkout?billing=cancel`,
    client_reference_id: input.accountId,
    "metadata[app]": VERHOUND_APP,
    "metadata[account_id]": input.accountId,
    "subscription_data[metadata][app]": VERHOUND_APP,
    "subscription_data[metadata][account_id]": input.accountId
  };
  // Reuse our own customer so later subscription events match the customer stored for this account.
  if (input.customerId) fields.customer = input.customerId;
  else if (input.email) fields.customer_email = input.email;
  if (trialDays) fields["subscription_data[trial_period_days]"] = String(trialDays);
  const payload = await stripeForm("/v1/checkout/sessions", fields, config.secretKey);
  const url = textField(payload.url);
  if (!url || !url.startsWith("https://")) throw new Error("Checkout did not return a URL.");
  return url;
}

export async function createPortalSession(customerId: string, origin: string): Promise<string> {
  const config = billingConfig();
  if (!config) throw new Error("Billing is not configured.");
  const payload = await stripeForm("/v1/billing_portal/sessions", {
    customer: customerId,
    return_url: `${origin}/account`
  }, config.secretKey);
  const url = textField(payload.url);
  if (!url || !url.startsWith("https://")) throw new Error("The billing portal did not return a URL.");
  return url;
}

/** Every price on a subscription, from items.data[].price (string or object). */
export function subscriptionPriceIds(record: Record<string, unknown>): string[] {
  const items = record.items && typeof record.items === "object" ? record.items as { data?: unknown } : {};
  const data = Array.isArray(items.data) ? items.data : [];
  return data.map((item) => {
    const price = item && typeof item === "object" ? (item as { price?: unknown }).price : undefined;
    if (typeof price === "string") return price;
    if (price && typeof price === "object" && typeof (price as { id?: unknown }).id === "string") return (price as { id: string }).id;
    return "";
  });
}

/**
 * Apply one verified Stripe event. Every app on the shared Stripe account gets every event,
 * so anything that is not provably Verhound's is ignored before any read or write:
 * - checkout.session.completed needs metadata.app=verhound, a matching account id in
 *   client_reference_id and metadata.account_id, and an account that already exists here.
 * - customer.subscription.* needs every item price to be STRIPE_PRICE_MONTHLY/YEARLY,
 *   metadata.app=verhound or the customer we stored, an existing account, and no conflicting stored customer.
 * A bare user id in metadata or client_reference_id is never enough on its own.
 */
export async function applyStripeEvent(event: unknown): Promise<"applied" | "ignored"> {
  const config = billingConfig();
  if (!config || !event || typeof event !== "object") return "ignored";
  const type = textField((event as { type?: unknown }).type);
  const object = (event as { data?: { object?: unknown } }).data?.object;
  if (!type || !object || typeof object !== "object") return "ignored";
  const record = object as Record<string, unknown>;
  const metadata = record.metadata && typeof record.metadata === "object" ? record.metadata as Record<string, unknown> : {};
  const ours = metadata.app === VERHOUND_APP;
  const store = getStore();
  if (type === "checkout.session.completed") {
    if (!ours) return "ignored";
    const fromRef = accountIdOf(record.client_reference_id);
    const fromMeta = accountIdOf(metadata.account_id);
    if (!fromRef || !fromMeta || fromRef !== fromMeta) return "ignored";
    const account = await store.getAccount(fromRef);
    if (!account) return "ignored";
    const customer = customerIdOf(record.customer);
    if (customer) await store.setStripeCustomer(fromRef, customer);
    const status = textField(record.status);
    const payment = textField(record.payment_status);
    if (status === "complete" || payment === "paid" || payment === "no_payment_required") {
      await store.setPlan(fromRef, "pro");
    }
    const details = record.customer_details && typeof record.customer_details === "object" ? record.customer_details as Record<string, unknown> : {};
    const email = textField(record.customer_email) ?? textField(details.email) ?? account.email ?? null;
    if (email) await store.claimTrial(trialKey(email), fromRef, nowDate().toISOString());
    return "applied";
  }
  if (type === "customer.subscription.created" || type === "customer.subscription.updated" || type === "customer.subscription.deleted") {
    const prices = subscriptionPriceIds(record);
    const allowed = [config.monthlyPrice, config.yearlyPrice];
    if (!prices.length || !prices.every((price) => allowed.includes(price))) return "ignored";
    const accountId = accountIdOf(metadata.account_id);
    const status = textField(record.status);
    if (!accountId || !status) return "ignored";
    const account = await store.getAccount(accountId);
    if (!account) return "ignored";
    const customer = customerIdOf(record.customer);
    const stored = account.stripe_customer_id ?? null;
    if (stored && customer !== stored) return "ignored";
    if (!ours && !(stored && customer === stored)) return "ignored";
    await store.setPlan(accountId, planForSubscriptionStatus(status));
    if (customer && !stored) await store.setStripeCustomer(accountId, customer);
    return "applied";
  }
  return "ignored";
}

function csrfOk(req: Request): boolean {
  const csrf = String(req.body?.csrf ?? "");
  return Boolean(csrf) && csrf === readCookie(req, PAGE_CSRF);
}

function html(res: Response, status: number, title: string, body: string, base: string): void {
  res.status(status).type("html").send(page(title, body, `${base}/logo.jpg`));
}

export function installBilling(app: Express): void {
  app.post("/billing/webhook", async (req, res) => {
    const raw = rawBodies.get(req);
    const config = billingConfig();
    if (!config) {
      // Not a failure of the request: billing is switched off on this deployment.
      res.status(503).json({ ok: false, error: "Billing is not configured." });
      return;
    }
    if (!raw) {
      res.status(400).json({ ok: false });
      return;
    }
    const header = req.header("stripe-signature") ?? "";
    if (!verifyStripeSignature(raw.toString("utf8"), header, config.webhookSecret)) {
      res.status(400).json({ ok: false });
      return;
    }
    try {
      await applyStripeEvent(JSON.parse(raw.toString("utf8")) as unknown);
      res.status(200).json({ ok: true });
    } catch (error) {
      const name = error instanceof Error ? error.name : "Error";
      console.error(JSON.stringify({ event: "billing_webhook_failed", name }));
      res.status(500).json({ ok: false });
    }
  });

  app.post("/billing/checkout", async (req, res) => {
    const base = publicBase(req);
    if (!isBillingConfigured()) {
      html(res, 400, PUBLIC_BRAND, "<h1>Billing is not configured.</h1>", base);
      return;
    }
    if (!csrfOk(req)) {
      html(res, 400, PUBLIC_BRAND, "<h1>The form expired.</h1>", base);
      return;
    }
    const accountId = accountIdFromRequest(req);
    if (!accountId) {
      html(res, 401, PUBLIC_BRAND, "<h1>Connect an assistant, then return to checkout.</h1>", base);
      return;
    }
    const interval = req.body?.interval === "yearly" ? "yearly" : req.body?.interval === "monthly" ? "monthly" : null;
    if (!interval) {
      html(res, 400, PUBLIC_BRAND, "<h1>Choose monthly or yearly.</h1>", base);
      return;
    }
    const account = await getStore().getAccount(accountId);
    try {
      const url = await createCheckoutSession({ accountId, email: account?.email ?? null, customerId: account?.stripe_customer_id ?? null, interval, origin: base });
      res.redirect(303, url);
    } catch (error) {
      const name = error instanceof Error ? error.name : "Error";
      console.error(JSON.stringify({ event: "billing_checkout_failed", name }));
      html(res, 502, PUBLIC_BRAND, "<h1>Checkout could not be started.</h1>", base);
    }
  });

  app.post("/billing/portal", async (req, res) => {
    const base = publicBase(req);
    if (!isBillingConfigured()) {
      html(res, 400, PUBLIC_BRAND, "<h1>Billing is not configured.</h1>", base);
      return;
    }
    if (!csrfOk(req)) {
      html(res, 400, PUBLIC_BRAND, "<h1>The form expired.</h1>", base);
      return;
    }
    const accountId = accountIdFromRequest(req);
    const account = accountId ? await getStore().getAccount(accountId) : null;
    const customer = account?.stripe_customer_id;
    if (!accountId || !customer) {
      res.redirect(303, `${base}/checkout`);
      return;
    }
    try {
      const url = await createPortalSession(customer, base);
      res.redirect(303, url);
    } catch (error) {
      const name = error instanceof Error ? error.name : "Error";
      console.error(JSON.stringify({ event: "billing_portal_failed", name }));
      html(res, 502, PUBLIC_BRAND, "<h1>The billing portal could not be opened.</h1>", base);
    }
  });
}
