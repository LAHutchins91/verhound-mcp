import crypto from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { planForSubscriptionStatus, verifyStripeSignature } from "../src/billing-stripe.js";
import { app } from "../src/server.js";
import { setMailerForTests } from "../src/mailer.js";
import { recordNewAlert } from "../src/operations.js";
import { memoryStoreForTests, resetStoreForTests } from "../src/store.js";
import { trialKey } from "../src/trial.js";
import { resetUpstreamForTests, setFetchForTests } from "../src/upstream/http.js";
import { webhookNeedsKey, WEBHOOK_SEAL_PREFIX } from "../src/webhook-crypto.js";
import { executeCron, setWatchBudgetForTests } from "../src/watch-job.js";
import { signToken } from "../src/tokens.js";

const TEST_KEY = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const SLACK = "https://hooks.slack.com/services/T00/B00/secret";
const ACCOUNT = "11111111-1111-4111-8111-111111111111";

let server: Server;
let base = "";
const originalFetch = globalThis.fetch.bind(globalThis);

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

afterEach(() => {
  resetStoreForTests();
  resetUpstreamForTests();
  setMailerForTests(null);
  setWatchBudgetForTests(null);
  setFetchForTests(null);
  process.env.WEBHOOK_ENC_KEY = TEST_KEY;
  delete process.env.VERCEL_ENV;
  delete process.env.CRON_SECRET;
  delete process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  delete process.env.STRIPE_PRICE_MONTHLY;
  delete process.env.STRIPE_PRICE_YEARLY;
  globalThis.fetch = originalFetch;
});

function cookiesOf(response: Response): string {
  const list = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
  return list.map((cookie) => cookie.split(";")[0]).join("; ");
}

function stripeSig(secret: string, payload: string, t = Math.floor(Date.now() / 1000)): string {
  const v1 = crypto.createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex");
  return `t=${t},v1=${v1}`;
}

async function watchRow(webhook: string | null) {
  const store = memoryStoreForTests();
  await store.ensureAccount(ACCOUNT, "person@example.com", "pro");
  return store.saveWatch({
    account_id: ACCOUNT,
    label: "api",
    filename: "package.json",
    ecosystem_summary: { npm: 1 },
    deps: [{ ecosystem: "npm", name: "left-pad", version: "1.2.3" }],
    min_severity: "low",
    last_checked_at: new Date().toISOString(),
    baseline_complete: true,
    email: "person@example.com",
    webhook_url: webhook,
    license_allow: [],
    license_deny: []
  });
}

describe("webhook encryption", () => {
  it("stores ciphertext and rewrites a legacy plaintext URL", async () => {
    const opened = await watchRow(SLACK);
    expect(opened.webhook_url).toBe(SLACK);
    const raw = memoryStoreForTests().watches.get(`${ACCOUNT}|api`);
    expect(raw?.webhook_url?.startsWith(WEBHOOK_SEAL_PREFIX)).toBe(true);
    expect(raw?.webhook_url).not.toContain("hooks.slack.com");
    if (raw) raw.webhook_url = SLACK;
    const migrated = await memoryStoreForTests().getWatch(ACCOUNT, "api");
    expect(migrated?.webhook_url).toBe(SLACK);
    expect(memoryStoreForTests().watches.get(`${ACCOUNT}|api`)?.webhook_url?.startsWith(WEBHOOK_SEAL_PREFIX)).toBe(true);
  });

  it("fails closed in production when a webhook is used without the key", async () => {
    const saved = await watchRow(SLACK);
    const raw = memoryStoreForTests().watches.get(`${ACCOUNT}|api`);
    if (raw) raw.webhook_url = SLACK;
    delete process.env.WEBHOOK_ENC_KEY;
    process.env.VERCEL_ENV = "production";
    await expect(memoryStoreForTests().saveWatch({
      account_id: ACCOUNT,
      label: "other",
      filename: "package.json",
      ecosystem_summary: {},
      deps: [],
      min_severity: "low",
      last_checked_at: new Date().toISOString(),
      baseline_complete: true,
      email: null,
      webhook_url: SLACK,
      license_allow: [],
      license_deny: []
    })).rejects.toThrow(/WEBHOOK_ENC_KEY/);
    const opened = await memoryStoreForTests().getWatch(ACCOUNT, "api");
    expect(opened?.webhook_url).toBeNull();
    expect(opened && webhookNeedsKey(opened)).toBe(true);
    await recordNewAlert(saved, {
      watch_id: saved.id,
      account_id: ACCOUNT,
      advisory_id: "MAL-2024-0001",
      package: "left-pad",
      version: "1.2.3",
      severity: "critical",
      first_fixed_version: null,
      url: "https://osv.dev/vulnerability/MAL-2024-0001",
      malicious: true
    });
    const calls: string[] = [];
    setFetchForTests(async (url) => {
      calls.push(new URL(url).hostname);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    process.env.CRON_SECRET = "cron-test-secret";
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls).not.toContain("hooks.slack.com");
  });
});

describe("pending notifications", () => {
  it("sends a webhook that missed the time limit once, and does not send it again", async () => {
    const saved = await watchRow(SLACK);
    await recordNewAlert(saved, {
      watch_id: saved.id,
      account_id: ACCOUNT,
      advisory_id: "GHSA-test-test-test",
      package: "left-pad",
      version: "1.2.3",
      severity: "high",
      first_fixed_version: null,
      url: "https://osv.dev/vulnerability/GHSA-test-test-test",
      malicious: false
    });
    const calls: string[] = [];
    setFetchForTests(async (url) => {
      calls.push(String(url));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    process.env.CRON_SECRET = "cron-test-secret";
    setWatchBudgetForTests(0);
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(0);
    expect(memoryStoreForTests().alerts[0]?.webhook_sent_at).toBeNull();
    setWatchBudgetForTests(null);
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(1);
    expect(memoryStoreForTests().alerts[0]?.webhook_sent_at).toBeTruthy();
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(1);
  });

  it("stops retrying a deleted webhook and skips alerts pending for more than 72 hours", async () => {
    const saved = await watchRow(SLACK);
    const alert = (id: string) => ({
      watch_id: saved.id,
      account_id: ACCOUNT,
      advisory_id: id,
      package: "left-pad",
      version: "1.2.3",
      severity: "high",
      first_fixed_version: null,
      url: `https://osv.dev/vulnerability/${id}`,
      malicious: false
    });
    await recordNewAlert(saved, alert("GHSA-gone-gone-gone"));
    const calls: string[] = [];
    setFetchForTests(async (url) => {
      calls.push(String(url));
      return new Response("no_service", { status: 404 });
    });
    process.env.CRON_SECRET = "cron-test-secret";
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(1);
    expect(memoryStoreForTests().alerts[0]?.webhook_sent_at).toBeTruthy();
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(1);

    await recordNewAlert(saved, alert("GHSA-old0-old0-old0"));
    const old = memoryStoreForTests().alerts.find((row) => row.advisory_id === "GHSA-old0-old0-old0");
    if (old) old.detected_at = new Date(Date.now() - 73 * 60 * 60 * 1000).toISOString();
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(calls.filter((url) => url.startsWith("https://hooks.slack.com"))).toHaveLength(1);
  });

  it("retries an alert email that failed and does not send the same alert twice", async () => {
    const saved = await watchRow(null);
    await recordNewAlert(saved, {
      watch_id: saved.id,
      account_id: ACCOUNT,
      advisory_id: "GHSA-test-test-test",
      package: "left-pad",
      version: "1.2.3",
      severity: "low",
      first_fixed_version: null,
      url: "https://osv.dev/vulnerability/GHSA-test-test-test",
      malicious: false
    });
    let fail = true;
    let sends = 0;
    setMailerForTests({
      async sendAlert() {
        sends += 1;
        if (fail) throw new Error("mailbox down");
        return "sent";
      }
    });
    process.env.CRON_SECRET = "cron-test-secret";
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(sends).toBe(1);
    expect(memoryStoreForTests().alerts[0]?.emailed_at).toBeNull();
    fail = false;
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(sends).toBe(2);
    expect(memoryStoreForTests().alerts[0]?.emailed_at).toBeTruthy();
    await executeCron("Bearer cron-test-secret", undefined, base);
    expect(sends).toBe(2);
  });
});

describe("trial copy and billing", () => {
  it("says 7-day Pro trial until billing is configured", async () => {
    const landing = await (await fetch(`${base}/`)).text();
    const checkout = await (await fetch(`${base}/checkout`)).text();
    const privacy = await (await fetch(`${base}/privacy`)).text();
    for (const html of [landing, checkout]) {
      expect(html).toContain("7-day Pro trial");
      expect(html.toLowerCase()).not.toContain("card required");
    }
    expect(privacy).toContain("encrypted at rest");
    expect(privacy).toContain("hooks.slack.com");
    expect(privacy).toContain("discord.com/api/webhooks");
    expect(privacy.toLowerCase()).not.toContain("stripe");
    expect(privacy).toContain("advisory link");
  });

  it("answers the Stripe webhook with a clear 503 while billing is not configured", async () => {
    const response = await fetch(`${base}/billing/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", "stripe-signature": "t=1,v1=abc" },
      body: JSON.stringify({ type: "checkout.session.completed" })
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ ok: false, error: "Billing is not configured." });
  });

  it("says card required and talks to Stripe only through the mocked API", async () => {
    process.env.STRIPE_SECRET_KEY = "sk_test_mock";
    process.env.STRIPE_WEBHOOK_SECRET = "whsec_mock";
    process.env.STRIPE_PRICE_MONTHLY = "price_monthly_mock";
    process.env.STRIPE_PRICE_YEARLY = "price_yearly_mock";
    const landing = await (await fetch(`${base}/`)).text();
    expect(landing).toContain("7-day Pro trial, card required");
    const stripeCalls: { url: string; body: string }[] = [];
    globalThis.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://api.stripe.com")) {
        stripeCalls.push({ url, body: String(init?.body ?? "") });
        if (url.endsWith("/checkout/sessions")) {
          return Response.json({ id: "cs_test_mock", url: "https://checkout.stripe.com/c/pay/cs_test_mock" });
        }
        if (url.endsWith("/billing_portal/sessions")) {
          return Response.json({ id: "bps_test_mock", url: "https://billing.stripe.com/p/session/test_mock" });
        }
        return new Response("no", { status: 404 });
      }
      return originalFetch(input, init);
    };
    await memoryStoreForTests().ensureAccount(ACCOUNT, "pay@example.com", "trial");
    const accountCookie = `verhound_account=${signToken({ typ: "account", sub: ACCOUNT }, 3600)}`;
    const page = await fetch(`${base}/checkout`, { headers: { cookie: accountCookie } });
    const html = await page.text();
    expect(html).toContain("card required");
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
    const cookie = [accountCookie, cookiesOf(page)].filter(Boolean).join("; ");
    const started = await fetch(`${base}/billing/checkout`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({ csrf, interval: "monthly" })
    });
    expect(started.status).toBe(303);
    expect(started.headers.get("location")).toBe("https://checkout.stripe.com/c/pay/cs_test_mock");
    const first = new URLSearchParams(stripeCalls[0]?.body ?? "");
    expect(first.get("line_items[0][price]")).toBe("price_monthly_mock");
    expect(first.get("subscription_data[trial_period_days]")).toBe("7");
    expect(first.get("client_reference_id")).toBe(ACCOUNT);
    expect(stripeCalls[0]?.url).toBe("https://api.stripe.com/v1/checkout/sessions");
    await memoryStoreForTests().claimTrial(trialKey("pay@example.com"), ACCOUNT, new Date().toISOString());
    const again = await fetch(`${base}/billing/checkout`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({ csrf, interval: "yearly" })
    });
    expect(again.status).toBe(303);
    const second = new URLSearchParams(stripeCalls[1]?.body ?? "");
    expect(second.get("line_items[0][price]")).toBe("price_yearly_mock");
    expect(second.get("subscription_data[trial_period_days]")).toBeNull();

    const secret = "whsec_mock";
    const completed = JSON.stringify({
      type: "checkout.session.completed",
      data: {
        object: {
          client_reference_id: ACCOUNT,
          customer: "cus_test123",
          customer_email: "pay@example.com",
          status: "complete",
          payment_status: "paid"
        }
      }
    });
    const accepted = await fetch(`${base}/billing/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", "stripe-signature": stripeSig(secret, completed) },
      body: completed
    });
    expect(accepted.status).toBe(200);
    expect((await accessFor(ACCOUNT)).plan).toBe("pro");
    expect((await memoryStoreForTests().getAccount(ACCOUNT))?.stripe_customer_id).toBe("cus_test123");

    const canceled = JSON.stringify({
      type: "customer.subscription.deleted",
      data: { object: { status: "canceled", customer: "cus_test123", metadata: { account_id: ACCOUNT } } }
    });
    const dropped = await fetch(`${base}/billing/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", "stripe-signature": stripeSig(secret, canceled) },
      body: canceled
    });
    expect(dropped.status).toBe(200);
    expect((await accessFor(ACCOUNT)).plan).toBe("free");
    expect(planForSubscriptionStatus("trialing")).toBe("pro");
    expect(planForSubscriptionStatus("active")).toBe("pro");
    expect(planForSubscriptionStatus("canceled")).toBe("free");
    expect(planForSubscriptionStatus("unpaid")).toBe("free");

    const rejected = await fetch(`${base}/billing/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", "stripe-signature": stripeSig(secret, completed, 10) },
      body: completed
    });
    expect(rejected.status).toBe(400);
    expect(verifyStripeSignature(completed, "t=1,v1=nope", secret)).toBe(false);

    const accountPage = await fetch(`${base}/account`, { headers: { cookie: accountCookie } });
    const accountHtml = await accountPage.text();
    const portalCsrf = /name="csrf" value="([^"]+)"/.exec(accountHtml)?.[1] ?? "";
    const portalCookie = [accountCookie, cookiesOf(accountPage)].filter(Boolean).join("; ");
    const portal = await fetch(`${base}/billing/portal`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie: portalCookie },
      body: new URLSearchParams({ csrf: portalCsrf })
    });
    expect(portal.status).toBe(303);
    expect(portal.headers.get("location")).toBe("https://billing.stripe.com/p/session/test_mock");
    expect(stripeCalls.some((call) => call.url.endsWith("/billing_portal/sessions") && call.body.includes("cus_test123"))).toBe(true);
    expect(stripeCalls.every((call) => call.url.startsWith("https://api.stripe.com"))).toBe(true);
  });
});
