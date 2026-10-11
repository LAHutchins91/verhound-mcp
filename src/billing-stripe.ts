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

export async function createCheckoutSession(input: { accountId: string; email: string | null; interval: "monthly" | "yearly"; origin: string }): Promise<string> {
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
    "metadata[account_id]": input.accountId,
    "subscription_data[metadata][account_id]": input.accountId
  };
  if (input.email) fields.customer_email = input.email;
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

export async function applyStripeEvent(event: unknown): Promise<void> {
  if (!event || typeof event !== "object") return;
  const type = textField((event as { type?: unknown }).type);
  const object = (event as { data?: { object?: unknown } }).data?.object;
  if (!type || !object || typeof object !== "object") return;
  const record = object as Record<string, unknown>;
  const metadata = record.metadata && typeof record.metadata === "object" ? record.metadata as Record<string, unknown> : {};
  const store = getStore();
  if (type === "checkout.session.completed") {
    const accountId = accountIdOf(record.client_reference_id) ?? accountIdOf(metadata.account_id);
    if (!accountId) return;
    await store.ensureAccount(accountId);
    const customer = customerIdOf(record.customer);
    if (customer) await store.setStripeCustomer(accountId, customer);
    const status = textField(record.status);
    const payment = textField(record.payment_status);
    if (status === "complete" || payment === "paid" || payment === "no_payment_required") {
      await store.setPlan(accountId, "pro");
    }
    const account = await store.getAccount(accountId);
    const details = record.customer_details && typeof record.customer_details === "object" ? record.customer_details as Record<string, unknown> : {};
    const email = textField(record.customer_email) ?? textField(details.email) ?? account?.email ?? null;
    if (email) await store.claimTrial(trialKey(email), accountId, nowDate().toISOString());
    return;
  }
  if (type === "customer.subscription.created" || type === "customer.subscription.updated" || type === "customer.subscription.deleted") {
    const accountId = accountIdOf(metadata.account_id);
    const status = textField(record.status);
    if (!accountId || !status) return;
    await store.ensureAccount(accountId);
    await store.setPlan(accountId, planForSubscriptionStatus(status));
    const customer = customerIdOf(record.customer);
    if (customer) await store.setStripeCustomer(accountId, customer);
  }
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
      const url = await createCheckoutSession({ accountId, email: account?.email ?? null, interval, origin: base });
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
