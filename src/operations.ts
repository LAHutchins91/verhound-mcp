import crypto from "node:crypto";
import type { Access } from "./billing.js";
import { nowDate, nowMs } from "./clock.js";
import { WATCH_STALE_MS, limitsFor, overPlanLimitMessage, proOnlyMessage, proUpsell, verifyEmailMessage, type Ecosystem } from "./config.js";
import { envelope, toolError, toolResult } from "./envelope.js";
import { assessLicenses, type LicensePolicy } from "./license.js";
import { parseManifest, type ParsedDep } from "./manifest/parse.js";
import { lookupPackages, type PackageFact } from "./lookup.js";
import { similarPopular, validPackageName } from "./names.js";
import { verifiedReleaseNotes } from "./release-notes.js";
import { runtimeEol } from "./runtime.js";
import { cmpVersion, isPrerelease, jump, satisfies } from "./semver.js";
import { SOURCE, mergeSources, type SourceCitation } from "./sources.js";
import { getStore, type AlertRecord, type DepRecord, type WatchRecord } from "./store.js";
import { contentHash } from "./text.js";
import { weeklyDownloads } from "./upstream/npm.js";
import { beginCall } from "./usage.js";
import { packageVerdict, publishedUnder72Hours, publishedWithin } from "./verdict.js";
import { WebhookKeyError } from "./webhook-crypto.js";
import { webhookHostLabel, webhookKind } from "./webhooks.js";

const LOW_DOWNLOADS = 100;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface ToolPayload {
  [key: string]: unknown;
  structuredContent: Record<string, unknown>;
  content: { type: "text"; text: string }[];
  isError?: true;
}

function malwareFirst<T extends { id: string; malicious?: boolean }>(advisories: T[]): T[] {
  return [...advisories].sort((a, b) => Number(Boolean(b.malicious || b.id.startsWith("MAL-"))) - Number(Boolean(a.malicious || a.id.startsWith("MAL-"))));
}

function decide(fact: PackageFact, policy?: LicensePolicy) {
  const license = assessLicenses(fact.declared_licenses, policy, fact.exists === true);
  const similar = similarPopular(fact.ecosystem, fact.name, 1).length > 0;
  const publishedAt = fact.requested_published_at || fact.latest_published_at;
  const recent = publishedUnder72Hours(publishedAt);
  const decision = packageVerdict({
    exists: fact.exists,
    advisoriesKnown: fact.advisories_known,
    advisories: fact.advisories,
    deprecated: fact.deprecated,
    publishedUnder30Days: Boolean(fact.first_published_at && publishedWithin(fact.first_published_at, 30 * DAY_MS)),
    publishedUnder72Hours: recent,
    similar,
    licenseFlags: license.flags,
    licenseReasons: license.reasons
  });
  return { ...decision, license, recent };
}

function publicFact(fact: PackageFact) {
  const decision = decide(fact);
  return {
    ecosystem: fact.ecosystem,
    name: fact.name,
    exists: fact.exists,
    requested_version: fact.requested_version,
    requested_version_found: fact.requested_version_found,
    latest_stable: fact.latest_stable,
    latest_published_at: fact.latest_published_at,
    requested_published_at: fact.requested_published_at,
    deprecated: fact.deprecated,
    deprecated_reason: fact.deprecated_reason,
    declared_licenses: fact.declared_licenses,
    license_note: fact.declared_licenses.length ? "declared license (from package metadata)" : undefined,
    advisories: malwareFirst(fact.advisories),
    advisories_known: fact.advisories_known,
    versions_behind: fact.versions_behind,
    published_under_72_hours: decision.recent,
    verdict: decision.verdict,
    reasons: decision.reasons,
    notes: fact.notes
  };
}

function finish(data: unknown, sources: SourceCitation[], notes: string[], age: number, stale: boolean): ToolPayload {
  return toolResult(envelope(data, sources, notes, age, stale));
}

/** Free accounts get a clear Pro-only message, and the call is not counted. */
function proOnly(access: Access): ToolPayload | null {
  if (access.emailRequired) return toolError(verifyEmailMessage());
  if (access.plan === "free") return toolError(proOnlyMessage());
  return null;
}

async function gate(access: Access, kind: "call" | "plan_upgrade", extras: { packages?: number; bytes?: number } = {}): Promise<string | null> {
  return beginCall(access, kind, extras);
}

export async function checkPackages(access: Access, packages: { ecosystem: Ecosystem; name: string; version?: string }[], includePrerelease = false): Promise<ToolPayload> {
  const limits = limitsFor(access.plan);
  const blocked = await gate(access, "call", { packages: packages.length });
  if (blocked) return toolError(blocked);
  if (packages.length > limits.packagesPerCall) return toolError(overPlanLimitMessage());
  const facts = await lookupPackages(packages.map((item) => ({ ...item, includePrerelease })));
  const notes = facts.flatMap((fact) => fact.notes);
  const age = Math.max(0, ...facts.map((fact) => fact.cacheAgeSeconds));
  return finish({
    packages: facts.map(publicFact)
  }, mergeSources(facts.map((fact) => fact.sources)), notes, age, facts.some((fact) => fact.stale));
}

function flagsFor(fact: PackageFact, weekly: number | null, similar: { name: string }[]): string[] {
  const flags: string[] = [];
  if (fact.exists === false) flags.push("not_found");
  if (fact.first_published_at && Date.parse(fact.first_published_at) > nowMs() - 30 * DAY_MS) flags.push("published_under_30_days");
  if (fact.ecosystem === "npm" && weekly !== null && weekly < LOW_DOWNLOADS) flags.push("low_downloads");
  if (similar.length) flags.push("similar_to_popular");
  if (fact.deprecated) flags.push("deprecated");
  if (fact.exists && !fact.repo_url) flags.push("no_repository_link");
  if (publishedUnder72Hours(fact.requested_published_at) || publishedUnder72Hours(fact.latest_published_at)) flags.push("published_under_72_hours");
  return flags;
}

export async function verifyPackageExists(access: Access, input: { ecosystem: Ecosystem; names: string[]; maxSimilar: number }): Promise<ToolPayload> {
  const limits = limitsFor(access.plan);
  const blocked = await gate(access, "call", { packages: input.names.length });
  if (blocked) return toolError(blocked);
  if (input.names.length > limits.packagesPerCall) return toolError(overPlanLimitMessage());
  const facts = await lookupPackages(input.names.map((name) => ({ ecosystem: input.ecosystem, name })));
  let downloads = new Map<string, number | null>();
  if (input.ecosystem === "npm") {
    try {
      downloads = await weeklyDownloads(facts.map((fact) => fact.name));
    } catch {
      downloads = new Map();
    }
  }
  const rows = facts.map((fact) => {
    const similar = similarPopular(fact.ecosystem, fact.name, input.maxSimilar);
    const weekly = input.ecosystem === "npm" ? (downloads.get(fact.name) ?? null) : null;
    return {
      ecosystem: fact.ecosystem,
      name: fact.name,
      exists: fact.exists,
      meaning: "exists_in_registry_only" as const,
      first_published_at: fact.first_published_at ?? null,
      latest_stable: fact.latest_stable ?? null,
      weekly_downloads: weekly,
      flags: flagsFor(fact, weekly, similar),
      similar,
      registry_url: fact.registry_url ?? null
    };
  });
  const notes = [
    "Existing in the registry does not mean a package is maintained, or that it is the one you intended.",
    ...facts.flatMap((fact) => fact.notes.filter((note) => !note.startsWith("No known advisories")))
  ];
  return finish({ packages: rows }, mergeSources(facts.map((fact) => fact.sources)), notes, Math.max(0, ...facts.map((fact) => fact.cacheAgeSeconds)), facts.some((fact) => fact.stale));
}

function findingFrom(fact: PackageFact, version: string | undefined, policy?: LicensePolicy) {
  const decision = decide(fact, policy);
  return {
    name: fact.name,
    version: version ?? fact.requested_version ?? fact.latest_stable ?? "",
    advisories: malwareFirst(fact.advisories),
    deprecated: fact.deprecated,
    latest_stable: fact.latest_stable ?? null,
    declared_licenses: fact.declared_licenses,
    license_note: fact.declared_licenses.length ? "declared license (from package metadata)" : undefined,
    license_flags: decision.license.flags,
    published_under_72_hours: decision.recent,
    verdict: decision.verdict,
    reasons: decision.reasons
  };
}

export async function auditManifest(access: Access, input: { filename: string; content: string; includeDev?: boolean; licenseAllow?: string[]; licenseDeny?: string[] }): Promise<ToolPayload> {
  const limits = limitsFor(access.plan);
  const bytes = Buffer.byteLength(input.content);
  // Check the size before parsing so an oversized input never reaches the parsers.
  if (bytes > limits.manifestBytes) {
    if (access.emailRequired) return toolError(verifyEmailMessage());
    return toolError(overPlanLimitMessage());
  }
  const parsed = parseManifest(input.filename, input.content, Boolean(input.includeDev));
  const depCount = parsed.dependencies.length;
  const blocked = await gate(access, "call", { bytes, packages: Math.min(depCount, limits.packagesPerCall) });
  if (blocked) return toolError(blocked);
  if (depCount > limits.manifestDeps) return toolError(overPlanLimitMessage());
  console.log(JSON.stringify({
    event: "manifest_audit",
    sha256: contentHash(input.content),
    bytes,
    dependencies: depCount
  }));

  // The function limit is 20s. Lookups not started by this deadline are reported as not checked.
  const deadline = nowMs() + AUDIT_LOOKUP_MS;
  const pinned = parsed.dependencies.filter((dep) => dep.version && !dep.range);
  const ranges = parsed.dependencies.filter((dep) => !dep.version || dep.range);
  const policy: LicensePolicy = { allow: input.licenseAllow, deny: input.licenseDeny };
  const pinnedFacts = pinned.length
    ? await lookupPackages(pinned.map((dep) => ({ ecosystem: dep.ecosystem, name: dep.name, version: dep.version })), { deadline })
    : [];
  const findings = pinned.map((dep, index) => findingFrom(pinnedFacts[index], dep.version, policy));
  const extraFacts: PackageFact[] = [];
  // Batch range lookups so a ranged package.json does not run one lookup at a time.
  const rangeMeta = ranges.length
    ? await lookupPackages(ranges.map((dep) => ({ ecosystem: dep.ecosystem, name: dep.name })), { deadline })
    : [];
  extraFacts.push(...rangeMeta);
  const pairRequests: { ecosystem: Ecosystem; name: string; version: string }[] = [];
  const pairPlan: { dep: ParsedDep; meta: PackageFact; low: string; high: string; at: number }[] = [];
  ranges.forEach((dep, index) => {
    const meta = rangeMeta[index];
    if (!meta) return;
    const matches = meta.version_list.filter((row) => satisfies(row.version, dep.spec));
    if (!matches.length) return;
    const low = matches[0].version;
    const high = matches[matches.length - 1].version;
    pairPlan.push({ dep, meta, low, high, at: pairRequests.length });
    pairRequests.push({ ecosystem: dep.ecosystem, name: dep.name, version: low });
    pairRequests.push({ ecosystem: dep.ecosystem, name: dep.name, version: high });
  });
  const pairFacts = pairRequests.length ? await lookupPackages(pairRequests, { deadline }) : [];
  extraFacts.push(...pairFacts);
  for (const item of pairPlan) {
    const pair = [pairFacts[item.at], pairFacts[item.at + 1]];
    const advisories = [...pair[0].advisories, ...pair[1].advisories.filter((entry) => !pair[0].advisories.some((other) => other.id === entry.id))];
    const combined: PackageFact = {
      ...pair[0],
      advisories,
      deprecated: pair[0].deprecated || pair[1].deprecated,
      latest_stable: item.meta.latest_stable,
      declared_licenses: pair[0].declared_licenses.length ? pair[0].declared_licenses : pair[1].declared_licenses
    };
    findings.push({
      ...findingFrom(combined, item.low === item.high ? item.low : `${item.low}..${item.high}`, policy),
      latest_stable: item.meta.latest_stable ?? null
    });
  }
  findings.sort((a, b) => Number(b.advisories.some((item) => item.malicious || item.id.startsWith("MAL-"))) - Number(a.advisories.some((item) => item.malicious || item.id.startsWith("MAL-"))));
  const runtime = [];
  for (const item of parsed.runtimes.slice(0, 5)) {
    const eol = await runtimeEol(item.product, item.declared);
    const data = eol.data as { release?: { is_eol?: boolean; eol_from?: string | null }; error?: string };
    runtime.push({
      product: item.product,
      declared: item.declared,
      eol: data.release?.is_eol,
      eol_date: data.release?.eol_from ?? undefined
    });
  }
  const allFacts = [...pinnedFacts, ...extraFacts];
  const advisories = findings.flatMap((finding) => finding.advisories);
  const bySeverity: Record<string, number> = {};
  for (const advisory of advisories) {
    const key = advisory.severity?.level ?? "unknown";
    bySeverity[key] = (bySeverity[key] ?? 0) + 1;
  }
  const notes = [
    ...parsed.notes,
    ...parsed.unresolved.map((item) => `${item.name}: ${item.reason}`),
    ...allFacts.flatMap((fact) => fact.notes)
  ];
  return finish({
    parsed: { format: parsed.format, dependency_count: depCount, unresolved: parsed.unresolved },
    findings,
    runtime,
    summary: {
      packages_with_advisories: findings.filter((finding) => finding.advisories.length).length,
      known_malware: findings.filter((finding) => finding.advisories.some((item) => item.malicious || item.id.startsWith("MAL-"))).length,
      total_advisories: advisories.length,
      by_severity: bySeverity,
      verdicts: {
        no_known_issues: findings.filter((finding) => finding.verdict === "no_known_issues").length,
        review: findings.filter((finding) => finding.verdict === "review").length,
        avoid: findings.filter((finding) => finding.verdict === "avoid").length
      }
    }
  }, mergeSources(allFacts.map((fact) => fact.sources)), notes, Math.max(0, ...allFacts.map((fact) => fact.cacheAgeSeconds), 0), allFacts.some((fact) => fact.stale));
}

/** Versions come from registries. Anything outside this set is not placed in a shell command. */
const COMMAND_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/;

const AUDIT_LOOKUP_MS = 13_000;

export function commandsFor(ecosystem: Ecosystem, name: string, version: string): string[] {
  if (!COMMAND_VERSION.test(version) || !validPackageName(ecosystem, name)) {
    return [`No command is shown because the version text has unexpected characters. Apply the upgrade with the ${ecosystem} toolchain after reviewing it.`];
  }
  if (ecosystem === "npm") return [`npm install ${name}@${version}`];
  if (ecosystem === "pypi") return [`python -m pip install '${name}==${version}'`];
  if (ecosystem === "go") {
    const goVersion = version.startsWith("v") ? version : `v${version}`;
    return [`go get ${name}@${goVersion}`];
  }
  if (ecosystem === "cargo") return [`cargo add ${name}@${version}`];
  if (ecosystem === "nuget") return [`dotnet add package ${name} --version ${version}`];
  if (ecosystem === "maven") {
    const [group, artifact] = name.split(":");
    const groupId = group || name;
    const artifactId = artifact || name;
    return [
      `mvn versions:use-dep-version -Dincludes=${groupId}:${artifactId} -DdepVersion=${version} -DforceVersion=true`,
      `<dependency><groupId>${groupId}</groupId><artifactId>${artifactId}</artifactId><version>${version}</version></dependency>`
    ];
  }
  if (ecosystem === "rubygems") return [`bundle add ${name} --version ${version}`];
  if (ecosystem === "composer") return [`composer require ${name}:${version}`];
  return [`Review ${name} ${version} and apply it with the ${ecosystem} toolchain.`];
}

function cleanTarget(facts: PackageFact[]): PackageFact | undefined {
  const clean = facts.filter((fact) => fact.advisories_known && fact.requested_version_found !== false && fact.advisories.length === 0 && fact.requested_version);
  clean.sort((a, b) => cmpVersion(b.requested_version || "", a.requested_version || ""));
  return clean[0];
}

export async function planUpgrade(access: Access, input: { ecosystem: Ecosystem; name: string; fromVersion: string; toVersion?: string; projectRuntime?: { node?: string; python?: string } }): Promise<ToolPayload> {
  const denied = proOnly(access);
  if (denied) return denied;
  const blocked = await gate(access, "plan_upgrade", { packages: 1 });
  if (blocked) return toolError(blocked);
  const [fromFact] = await lookupPackages([{ ecosystem: input.ecosystem, name: input.name, version: input.fromVersion }]);
  let target = input.toVersion;
  let targetReason = "the version you asked for";
  let toFact: PackageFact | undefined;
  if (target) {
    [toFact] = await lookupPackages([{ ecosystem: input.ecosystem, name: input.name, version: target }]);
  } else {
    const stable = fromFact.version_list.filter((row) => !isPrerelease(row.version));
    const newer = stable.filter((row) => cmpVersion(input.fromVersion, row.version) < 0).map((row) => row.version);
    const fixes = fromFact.advisories.map((item) => item.first_fixed_version).filter((item): item is string => Boolean(item));
    const pool = [...new Set([fromFact.latest_stable, ...fixes, ...newer].filter((item): item is string => Boolean(item)))]
      .filter((version) => cmpVersion(input.fromVersion, version) <= 0)
      .sort((a, b) => cmpVersion(b, a))
      .slice(0, 12);
    if (!pool.length) return toolError("No target version was found. Nothing was planned.");
    const checked = await lookupPackages(pool.map((version) => ({ ecosystem: input.ecosystem, name: input.name, version })));
    const chosen = cleanTarget(checked);
    if (chosen?.requested_version) {
      target = chosen.requested_version;
      toFact = chosen;
      targetReason = "Newest version with no known advisories in OSV.dev.";
    } else {
      target = fromFact.latest_stable || pool[0];
      toFact = checked.find((fact) => fact.requested_version === target) ?? checked[0];
      targetReason = "Every newer version that was checked still has known advisories, or the advisory lookup did not complete. This is the latest version.";
    }
  }
  if (!target || !toFact) return toolError("No target version was found. Nothing was planned.");
  const toIds = new Set(toFact.advisories.map((item) => item.id));
  const deprecatedBetween = fromFact.version_list
    .filter((row) => row.deprecated && cmpVersion(input.fromVersion, row.version) < 0 && cmpVersion(row.version, target) < 0)
    .map((row) => row.version);
  const repo = toFact.repo_url || fromFact.repo_url;
  const releaseNotes = await verifiedReleaseNotes(repo, target);
  const peerChanges = Object.keys({ ...fromFact.peers, ...toFact.peers }).sort().flatMap((name) => {
    const before = fromFact.peers[name] ?? "";
    const after = toFact.peers[name] ?? "";
    return before === after ? [] : [{ name, from: before || null, to: after || null }];
  });
  const notes = [
    "This is a plan only. Verhound has not changed your project.",
    ...releaseNotes.notes,
    ...fromFact.notes,
    ...toFact.notes
  ];
  return finish({
    ecosystem: input.ecosystem,
    name: toFact.name,
    from_version: input.fromVersion,
    to_version: target,
    latest_stable: fromFact.latest_stable ?? null,
    target_reason: targetReason,
    jump: jump(input.fromVersion, target),
    advisories_fixed: fromFact.advisories.filter((item) => !toIds.has(item.id)),
    advisories_remaining: toFact.advisories,
    engine_changes: {
      node: fromFact.engines_node === toFact.engines_node ? null : { from: fromFact.engines_node ?? null, to: toFact.engines_node ?? null },
      python: fromFact.python_requires === toFact.python_requires ? null : { from: fromFact.python_requires ?? null, to: toFact.python_requires ?? null },
      project_runtime: input.projectRuntime ?? null
    },
    peer_dependency_changes: peerChanges,
    deprecated_in_between: deprecatedBetween,
    release_notes_links: releaseNotes.links,
    suggested_steps: [
      "Read the advisories and the release notes links.",
      "Decide whether the version jump fits this project.",
      "Run the commands yourself after reviewing them."
    ],
    commands_for_user: commandsFor(input.ecosystem, toFact.name, target),
    commands_label: "for you to run after reviewing"
  }, mergeSources([fromFact.sources, toFact.sources]), notes, Math.max(fromFact.cacheAgeSeconds, toFact.cacheAgeSeconds), fromFact.stale || toFact.stale);
}

export async function runtimeEolTool(access: Access, productName: string, version?: string): Promise<ToolPayload> {
  const blocked = await gate(access, "call");
  if (blocked) return toolError(blocked);
  const value = await runtimeEol(productName, version);
  const failed = "error" in value.data;
  return toolResult(value, failed);
}

function pinnedDeps(deps: ParsedDep[]): DepRecord[] {
  const seen = new Set<string>();
  const out: DepRecord[] = [];
  for (const dep of deps) {
    if (!dep.version || dep.range) continue;
    const key = `${dep.ecosystem}|${dep.name}|${dep.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: dep.ecosystem, name: dep.name, version: dep.version });
  }
  return out;
}

async function baseline(deps: DepRecord[]): Promise<{ packagesWithAdvisories: number; total: number; notes: string[]; age: number; stale: boolean; sources: SourceCitation[]; failed: boolean }> {
  if (!deps.length) return { packagesWithAdvisories: 0, total: 0, notes: [], age: 0, stale: false, sources: [], failed: false };
  const facts = await lookupPackages(deps.map((dep) => ({ ecosystem: dep.ecosystem as Ecosystem, name: dep.name, version: dep.version })));
  const failed = facts.some((fact) => fact.exists !== false && !fact.advisories_known);
  return {
    packagesWithAdvisories: facts.filter((fact) => fact.advisories.length).length,
    total: facts.reduce((sum, fact) => sum + fact.advisories.length, 0),
    notes: facts.flatMap((fact) => fact.notes),
    age: Math.max(0, ...facts.map((fact) => fact.cacheAgeSeconds)),
    stale: facts.some((fact) => fact.stale),
    sources: mergeSources(facts.map((fact) => fact.sources)),
    failed
  };
}

export async function watchManifest(access: Access, input: { label: string; filename: string; content: string; minSeverity?: string; alertEmail?: "account"; webhookUrl?: string; licenseAllow?: string[]; licenseDeny?: string[] }): Promise<ToolPayload> {
  const denied = proOnly(access);
  if (denied) return denied;
  const limits = limitsFor(access.plan);
  const bytes = Buffer.byteLength(input.content);
  const blocked = await gate(access, "call", { bytes });
  if (blocked) return toolError(blocked);
  if (bytes > limits.manifestBytes) return toolError(overPlanLimitMessage());
  const store = getStore();
  const existing = await store.getWatch(access.accountId, input.label);
  const count = await store.countWatches(access.accountId);
  if (!existing && count >= limits.watches) {
    return toolError(access.plan === "pro" ? "This plan has no room for another watched project." : proUpsell());
  }
  const webhook = input.webhookUrl?.trim() ?? "";
  if (webhook && !webhookKind(webhook)) {
    return toolError("Webhook host is not allowed. Use an https incoming webhook on hooks.slack.com/services/ or discord.com/api/webhooks/.");
  }
  const parsed = parseManifest(input.filename, input.content, false);
  const deps = pinnedDeps(parsed.dependencies);
  if (deps.length > limits.manifestDeps) return toolError(overPlanLimitMessage());
  console.log(JSON.stringify({ event: "manifest_audit", sha256: contentHash(input.content), bytes, dependencies: deps.length }));
  const base = await baseline(deps);
  if (deps.length && base.failed) {
    return toolError("OSV.dev did not return a baseline. The watch was not saved, so an empty baseline is not stored.");
  }
  const summary: Record<string, number> = {};
  for (const dep of deps) summary[dep.ecosystem] = (summary[dep.ecosystem] ?? 0) + 1;
  const email = input.alertEmail === "account" ? access.email : null;
  const policy: LicensePolicy = { allow: input.licenseAllow, deny: input.licenseDeny };
  let watch;
  try {
    watch = await store.saveWatch({
      account_id: access.accountId,
      label: input.label,
      filename: input.filename.split(/[/\\]/).pop()?.slice(0, 120) || "manifest",
      ecosystem_summary: summary,
      deps,
      min_severity: input.minSeverity ?? "low",
      last_checked_at: nowDate().toISOString(),
      baseline_complete: true,
      email,
      webhook_url: webhook || null,
      license_allow: input.licenseAllow ?? [],
      license_deny: input.licenseDeny ?? []
    });
  } catch (error) {
    if (error instanceof WebhookKeyError) return toolError("Webhook storage is not configured.");
    throw error;
  }
  const seenAt = nowDate().toISOString();
  if (deps.length) {
    const facts = await lookupPackages(deps.map((dep) => ({ ecosystem: dep.ecosystem as Ecosystem, name: dep.name, version: dep.version })));
    for (const fact of facts) {
      for (const advisory of fact.advisories) {
        await store.markSeen(watch.id, advisory.id, fact.name, fact.requested_version || fact.latest_stable || "", seenAt);
      }
    }
  }
  const next = new Date(nowMs() + WATCH_STALE_MS);
  const licenseNotes: string[] = [];
  if (deps.length && (policy.allow?.length || policy.deny?.length)) {
    const facts = await lookupPackages(deps.map((dep) => ({ ecosystem: dep.ecosystem as Ecosystem, name: dep.name, version: dep.version })));
    for (const fact of facts) {
      const assessed = assessLicenses(fact.declared_licenses, policy, fact.exists === true);
      for (const reason of assessed.reasons) licenseNotes.push(`${fact.name}: ${reason}`);
    }
  }
  const notes = [
    ...parsed.notes,
    ...parsed.unresolved.map((item) => `${item.name} was not stored: ${item.reason}`),
    ...base.notes,
    ...licenseNotes,
    email ? "Alerts for this watch can be emailed to the account address." : "No account email is saved, so alerts stay available from list_alerts.",
    webhook ? `Alerts for this watch can be posted to ${webhookHostLabel(webhook)}.` : "No Slack or Discord webhook is saved for this watch."
  ];
  return finish({
    watch_id: watch.id,
    label: watch.label,
    dependency_count: deps.length,
    baseline: { packages_with_advisories: base.packagesWithAdvisories, total_advisories: base.total },
    next_check_at: next.toISOString(),
    stored: "parsed dependency list and filename only",
    unwatch_hint: "call unwatch_manifest with this label to delete it"
  }, base.sources.length ? base.sources : [SOURCE.osv], notes, base.age, base.stale);
}

export async function listAlerts(access: Access, input: { label?: string; since?: string; limit: number }): Promise<ToolPayload> {
  const denied = proOnly(access);
  if (denied) return denied;
  const blocked = await gate(access, "call");
  if (blocked) return toolError(blocked);
  const store = getStore();
  const watches = await store.listWatches(access.accountId);
  const alerts = await store.listAlerts(access.accountId, input);
  return finish({
    watches: watches.map((watch) => ({
      label: watch.label,
      dependency_count: watch.deps.length,
      last_checked_at: watch.last_checked_at
    })),
    alerts: alerts.map((alert) => ({
      id: alert.id,
      label: alert.label,
      package: alert.package,
      version: alert.version,
      advisory_id: alert.advisory_id,
      severity: alert.severity,
      malicious: alert.malicious,
      first_fixed_version: alert.first_fixed_version,
      url: alert.url,
      detected_at: alert.detected_at,
      emailed_at: alert.emailed_at
    }))
  }, [], [], 0, false);
}

export async function unwatchManifest(access: Access, label: string): Promise<ToolPayload> {
  const deleted = await getStore().deleteWatch(access.accountId, label);
  return finish({ deleted }, [], [], 0, false);
}

export async function recordNewAlert(watch: WatchRecord, alert: Omit<AlertRecord, "id" | "detected_at" | "emailed_at" | "webhook_sent_at" | "email_claim_at" | "webhook_claim_at" | "malicious" | "label"> & { malicious?: boolean }): Promise<AlertRecord> {
  const row: AlertRecord = {
    ...alert,
    id: crypto.randomUUID(),
    detected_at: nowDate().toISOString(),
    emailed_at: null,
    webhook_sent_at: null,
    email_claim_at: null,
    webhook_claim_at: null,
    label: watch.label,
    malicious: Boolean(alert.malicious || alert.advisory_id.startsWith("MAL-"))
  };
  await getStore().addAlert(row);
  return row;
}
