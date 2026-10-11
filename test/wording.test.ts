import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { LIMITS, TRIAL_DAYS } from "../src/config.js";
import { trialCardPhrase } from "../src/pages.js";

const BANNED = [
  /\bsafe\b/i,
  /\bsecure\b/i,
  /\bguaranteed\b/i,
  /vulnerability-free/i,
  /no vulnerabilities/i,
  /protects you from/i,
  /malware-free/i,
  /\blegit\b/i,
  /\btrusted\b/i
];

const SCAN = [
  "README.md",
  "src/tools.ts",
  "src/config.ts",
  "src/pages.ts",
  "src/html.ts",
  "src/mailer.ts",
  "src/operations.ts",
  "src/server.ts",
  "src/verdict.ts",
  "src/license.ts",
  "src/release-notes.ts",
  "src/webhooks.ts",
  "src/watch-job.ts"
];

function read(rel: string): string {
  return fs.readFileSync(path.resolve(rel), "utf8");
}

function splitPrices(text: string): { allowed: string; rest: string } {
  const re = /<!-- price-allowed:start -->([\s\S]*?)<!-- price-allowed:end -->/g;
  let allowed = "";
  const rest = text.replace(re, (_match, inner: string) => {
    allowed += inner;
    return "";
  });
  return { allowed, rest };
}

describe("public wording", () => {
  it("rejects banned security claims", () => {
    for (const file of SCAN) {
      const text = read(file);
      for (const pattern of BANNED) {
        expect(text, `${file} ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  it("rejects free-forever wording on the README and pages", () => {
    for (const file of ["README.md", "src/pages.ts", "src/html.ts"]) {
      expect(read(file).toLowerCase()).not.toContain("free forever");
    }
  });

  it("allows only the approved prices inside pricing copy", () => {
    const approved = new Set(["$7.99", "$79.99"]);
    const files = [...SCAN, "src/billing.ts", "src/auth.ts"];
    for (const file of files) {
      const { allowed, rest } = splitPrices(read(file));
      const amounts = (value: string) => [...value.matchAll(/\$\s?\d+(?:\.\d+)?/g)].map((match) => match[0].replace(/\s+/g, ""));
      expect(amounts(rest), file).toEqual([]);
      for (const amount of amounts(allowed)) expect(approved.has(amount), amount).toBe(true);
    }
    const pricing = splitPrices(read("README.md")).allowed;
    expect(pricing).toContain("$7.99/month");
    expect(pricing).toContain("$79.99/year");
    expect(pricing.toLowerCase()).not.toContain("card is required");
    expect(pricing.toLowerCase()).not.toContain("card required");
    const pages = splitPrices(read("src/pages.ts")).allowed;
    expect(pages).toContain("$7.99/month");
    expect(pages).toContain("$79.99/year");
    expect(trialCardPhrase()).toBe("");
  });

  it("keeps published plan numbers in config", () => {
    expect(TRIAL_DAYS).toBe(7);
    expect(LIMITS.trial.callsPerDay).toBe(100);
    expect(LIMITS.trial.watches).toBe(1);
    expect(LIMITS.pro.callsPerDay).toBe(300);
    expect(LIMITS.pro.watches).toBe(10);
  });
});
