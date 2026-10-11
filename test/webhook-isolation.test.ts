import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { applyStripeEvent } from "../src/billing-stripe.js";
import { memoryStoreForTests, resetStoreForTests } from "../src/store.js";
import { trialKey } from "../src/trial.js";

const ACCOUNT = "22222222-2222-4222-8222-222222222222";
const STRANGER = "33333333-3333-4333-8333-333333333333";
const MONTHLY = "price_vh_monthly";
const YEARLY = "price_vh_yearly";

function sub(type: string, object: Record<string, unknown>) {
  return { type, data: { object } };
}
const ourItems = { data: [{ price: { id: MONTHLY } }] };
const foreignItems = { data: [{ price: { id: "price_skelwright_pro" } }] };

beforeEach(() => {
  process.env.STRIPE_SECRET_KEY = "sk_test_mock";
  process.env.STRIPE_WEBHOOK_SECRET = "whsec_mock";
  process.env.STRIPE_PRICE_MONTHLY = MONTHLY;
  process.env.STRIPE_PRICE_YEARLY = YEARLY;
});

afterEach(() => {
  resetStoreForTests();
  delete process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  delete process.env.STRIPE_PRICE_MONTHLY;
  delete process.env.STRIPE_PRICE_YEARLY;
});

describe("shared Stripe account: other apps' events are ignored", () => {
  it("ignores another app's checkout even when its user id is a UUID that matches ours", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "same@example.com", "free");
    const fillip = sub("checkout.session.completed", {
      client_reference_id: ACCOUNT,
      customer: "cus_fillip1",
      customer_email: "same@example.com",
      status: "complete",
      payment_status: "paid",
      metadata: { app: "fillip", supabase_user_id: ACCOUNT, account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(fillip)).toBe("ignored");
    const account = await store.getAccount(ACCOUNT);
    expect(account?.plan).toBe("free");
    expect(account?.stripe_customer_id ?? null).toBeNull();
    // The other app's checkout must not burn this person's Verhound trial.
    expect(await store.hasTrial(trialKey("same@example.com"))).toBe(false);
  });

  it("ignores a checkout with no app marker or mismatched ids, and never creates accounts", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "a@example.com", "free");
    const bare = sub("checkout.session.completed", { client_reference_id: ACCOUNT, status: "complete", payment_status: "paid" });
    expect(await applyStripeEvent(bare)).toBe("ignored");
    const mismatched = sub("checkout.session.completed", {
      client_reference_id: ACCOUNT, status: "complete", metadata: { app: "verhound", account_id: STRANGER }
    });
    expect(await applyStripeEvent(mismatched)).toBe("ignored");
    const unknown = sub("checkout.session.completed", {
      client_reference_id: STRANGER, status: "complete", metadata: { app: "verhound", account_id: STRANGER }
    });
    expect(await applyStripeEvent(unknown)).toBe("ignored");
    expect(await store.getAccount(STRANGER)).toBeNull();
    expect((await accessFor(ACCOUNT)).plan).toBe("free");
  });

  it("ignores another app's subscription.deleted for the same account id and customer", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "p@example.com", "pro");
    await store.setStripeCustomer(ACCOUNT, "cus_shared");
    const skelwright = sub("customer.subscription.deleted", {
      id: "sub_skel", status: "canceled", customer: "cus_shared", items: foreignItems,
      metadata: { app: "skelwright", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(skelwright)).toBe("ignored");
    const mixed = sub("customer.subscription.deleted", {
      id: "sub_mix", status: "canceled", customer: "cus_shared",
      items: { data: [{ price: { id: MONTHLY } }, { price: { id: "price_other" } }] },
      metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(mixed)).toBe("ignored");
    const noItems = sub("customer.subscription.deleted", {
      id: "sub_none", status: "canceled", customer: "cus_shared", metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(noItems)).toBe("ignored");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("pro");
  });

  it("ignores our price on a different customer than the one stored, and unknown accounts", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "p@example.com", "pro");
    await store.setStripeCustomer(ACCOUNT, "cus_ours");
    const otherCustomer = sub("customer.subscription.deleted", {
      id: "sub_x", status: "canceled", customer: "cus_someone_else", items: ourItems,
      metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(otherCustomer)).toBe("ignored");
    const stranger = sub("customer.subscription.created", {
      id: "sub_y", status: "active", customer: "cus_y", items: ourItems, metadata: { app: "verhound", account_id: STRANGER }
    });
    expect(await applyStripeEvent(stranger)).toBe("ignored");
    expect(await store.getAccount(STRANGER)).toBeNull();
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("pro");
  });

  it("ignores our price with no app marker unless the customer is the one we stored", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "p@example.com", "free");
    const unmarked = sub("customer.subscription.created", {
      id: "sub_u", status: "active", customer: "cus_u", items: ourItems, metadata: { account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(unmarked)).toBe("ignored");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("free");
    await store.setStripeCustomer(ACCOUNT, "cus_u");
    expect(await applyStripeEvent(unmarked)).toBe("applied");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("pro");
  });

  it("still applies Verhound's own checkout and subscription lifecycle", async () => {
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "own@example.com", "free");
    const checkout = sub("checkout.session.completed", {
      client_reference_id: ACCOUNT, customer: "cus_own", customer_email: "own@example.com",
      status: "complete", payment_status: "no_payment_required", metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(checkout)).toBe("applied");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("pro");
    expect((await store.getAccount(ACCOUNT))?.stripe_customer_id).toBe("cus_own");
    expect(await store.hasTrial(trialKey("own@example.com"))).toBe(true);
    const yearly = sub("customer.subscription.updated", {
      id: "sub_own", status: "active", customer: "cus_own", items: { data: [{ price: YEARLY }] },
      metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(yearly)).toBe("applied");
    const deleted = sub("customer.subscription.deleted", {
      id: "sub_own", status: "canceled", customer: "cus_own", items: ourItems,
      metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(deleted)).toBe("applied");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("free");
  });

  it("ignores everything when billing is not configured", async () => {
    delete process.env.STRIPE_PRICE_MONTHLY;
    const store = memoryStoreForTests();
    await store.ensureAccount(ACCOUNT, "x@example.com", "free");
    const checkout = sub("checkout.session.completed", {
      client_reference_id: ACCOUNT, status: "complete", metadata: { app: "verhound", account_id: ACCOUNT }
    });
    expect(await applyStripeEvent(checkout)).toBe("ignored");
    expect((await store.getAccount(ACCOUNT))?.plan).toBe("free");
  });
});
