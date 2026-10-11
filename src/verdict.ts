import { nowMs } from "./clock.js";
import { RECENT_RELEASE_MS } from "./config.js";

export type Verdict = "no_known_issues" | "review" | "avoid";

export interface VerdictInput {
  exists: boolean | null;
  advisoriesKnown: boolean;
  advisories: { id: string; malicious?: boolean; severity?: { level?: string } }[];
  deprecated: boolean;
  publishedUnder30Days: boolean;
  publishedUnder72Hours: boolean;
  similar: boolean;
  licenseFlags: string[];
  licenseReasons: string[];
}

export function publishedWithin(iso: string | undefined, windowMs: number): boolean {
  if (!iso) return false;
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return false;
  const age = nowMs() - then;
  return age >= 0 && age < windowMs;
}

export function publishedUnder72Hours(iso: string | undefined): boolean {
  return publishedWithin(iso, RECENT_RELEASE_MS);
}

function isMalware(advisory: { id: string; malicious?: boolean }): boolean {
  return advisory.malicious === true || advisory.id.startsWith("MAL-");
}

function isHigh(advisory: { severity?: { level?: string } }): boolean {
  const level = advisory.severity?.level?.toLowerCase() ?? "";
  return level === "high" || level === "critical";
}

/** Per-package verdict. Reasons stay factual and do not claim the package is free of problems. */
export function packageVerdict(input: VerdictInput): { verdict: Verdict; reasons: string[] } {
  const reasons: string[] = [];
  const malware = input.advisories.some(isMalware);
  const high = input.advisories.some((advisory) => !isMalware(advisory) && isHigh(advisory));
  const other = input.advisories.some((advisory) => !isMalware(advisory) && !isHigh(advisory));
  if (malware) reasons.push("Known malware record. Listed ahead of other advisories.");
  if (input.exists === false) reasons.push("The name was not found in the registry.");
  if (high) reasons.push("Known advisory at high or critical severity.");
  if (malware || input.exists === false || high) return { verdict: "avoid", reasons };

  if (!input.advisoriesKnown) reasons.push("The advisory lookup did not complete.");
  if (other) reasons.push("Known advisory. Severity is moderate, low, or not stated.");
  if (input.deprecated) reasons.push("The package version is deprecated.");
  if (input.similar) reasons.push("The name is similar to a widely used package name.");
  if (input.publishedUnder30Days) reasons.push("The package was first published less than 30 days ago.");
  if (input.publishedUnder72Hours) reasons.push("This version was published less than 72 hours ago.");
  for (const reason of input.licenseReasons) {
    if (!reasons.includes(reason)) reasons.push(reason);
  }
  if (reasons.length) return { verdict: "review", reasons };
  return {
    verdict: "no_known_issues",
    reasons: ["No known advisories in OSV.dev for this version, and none of the review flags matched."]
  };
}
