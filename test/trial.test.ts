import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { setClockForTests } from "../src/clock.js";
import { memoryStoreForTests, resetStoreForTests } from "../src/store.js";
import { applyTrialMarker, normalizeTrialEmail, trialKey } from "../src/trial.js";

afterEach(() => {
  setClockForTests(null);
  resetStoreForTests();
});

const DAY = 24 * 60 * 60 * 1000;

describe("one Pro trial per person", () => {
  it("normalizes +tags and Gmail dots", () => {
    expect(normalizeTrialEmail(" A.B+test@GoogleMail.com ")).toBe("ab@gmail.com");
    expect(normalizeTrialEmail("first.last+x@example.com")).toBe("first.last@example.com");
    expect(trialKey("j.doe+1@gmail.com")).toBe(trialKey("jdoe@gmail.com"));
    expect(trialKey("a@example.com")).not.toBe(trialKey("b@example.com"));
  });

  it("does not give a second trial to a variant address", async () => {
    const store = memoryStoreForTests();
    const start = 1_700_000_000_000;
    setClockForTests(start);
    await store.ensureAccount("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "jdoe@gmail.com");
    await applyTrialMarker("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "jdoe@gmail.com");
    setClockForTests(start + 10 * DAY);
    await store.ensureAccount("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "j.doe+again@gmail.com");
    await applyTrialMarker("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "j.doe+again@gmail.com");
    const second = await accessFor("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    expect(second.plan).toBe("free");
    expect(second.expired).toBe(true);
  });

  it("keeps the marker after the account is deleted", async () => {
    const store = memoryStoreForTests();
    const start = 1_700_000_000_000;
    setClockForTests(start);
    await store.ensureAccount("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "person@example.com");
    await applyTrialMarker("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "person@example.com");
    await store.deleteAccount("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    setClockForTests(start + 2 * DAY);
    await store.ensureAccount("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "person@example.com");
    await applyTrialMarker("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "person@example.com");
    const access = await accessFor("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    expect(access.plan).toBe("trial");
    expect(access.trialEndsAt).toBe(new Date(start + 7 * DAY).toISOString());
  });
});
