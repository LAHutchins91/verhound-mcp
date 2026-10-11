import { asDataText } from "./text.js";
import { cmpVersion } from "./semver.js";

export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  severity?: { type: string; score: string };
  source_database: string;
  url: string;
  affected_range_text: string;
  first_fixed_version?: string;
}

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRange {
  events?: OsvEvent[];
}

interface OsvVuln {
  id?: string;
  summary?: string;
  aliases?: unknown;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: unknown };
  references?: { type?: string; url?: string }[];
  affected?: { ranges?: OsvRange[] }[];
}

export function sourceDatabase(id: string): string {
  if (id.startsWith("GHSA-")) return "GitHub Advisory Database";
  if (id.startsWith("PYSEC-")) return "PyPA Advisory Database";
  if (id.startsWith("GO-")) return "Go Vulnerability Database";
  if (id.startsWith("RUSTSEC-")) return "RustSec";
  if (id.startsWith("MAL-")) return "OpenSSF Malicious Packages";
  return "OSV.dev";
}

export function advisoryUrl(id: string, references: { url?: string }[] = []): string {
  const match = references.find((item) => item.url && item.url.includes(id));
  if (match?.url) return match.url;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  if (id.startsWith("CVE-")) return `https://osv.dev/vulnerability/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function eventsOf(vuln: OsvVuln): OsvEvent[][] {
  const ranges: OsvEvent[][] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.events?.length) ranges.push(range.events);
    }
  }
  return ranges;
}

export function rangeContains(version: string, events: OsvEvent[]): boolean {
  let open = false;
  for (const event of events) {
    if (event.introduced !== undefined) {
      open = event.introduced === "0" || cmpVersion(version, event.introduced) >= 0;
    }
    if (event.fixed !== undefined) {
      if (open && cmpVersion(version, event.fixed) < 0) return true;
      open = false;
    }
    if (event.last_affected !== undefined) {
      if (open && cmpVersion(version, event.last_affected) <= 0) return true;
      open = false;
    }
  }
  return open;
}

function fixedOf(events: OsvEvent[]): string | undefined {
  const fixed = events.find((event) => event.fixed)?.fixed;
  return fixed || undefined;
}

export function firstFixed(vuln: OsvVuln, version?: string): string | undefined {
  const ranges = eventsOf(vuln);
  if (version) {
    for (const events of ranges) {
      if (rangeContains(version, events)) return fixedOf(events);
    }
  }
  const fixes = ranges.map(fixedOf).filter((item): item is string => Boolean(item));
  fixes.sort(cmpVersion);
  return fixes[0];
}

function rangeText(vuln: OsvVuln): string {
  const text = eventsOf(vuln).map((events) => events.map((event) => {
    const [key, value] = Object.entries(event)[0] ?? [];
    return key && value ? `${key} ${value}` : "";
  }).filter(Boolean).join(", ")).filter(Boolean).join(" | ");
  return asDataText(text, 300);
}

export function advisoryFromOsv(raw: unknown, version?: string): Advisory | null {
  if (!raw || typeof raw !== "object") return null;
  const vuln = raw as OsvVuln;
  const id = typeof vuln.id === "string" ? vuln.id : "";
  if (!id) return null;
  const aliases = Array.isArray(vuln.aliases) ? vuln.aliases.filter((item): item is string => typeof item === "string").slice(0, 20).map((item) => asDataText(item, 40)) : [];
  const cvss = (vuln.severity ?? []).find((item) => item.type && item.score);
  const dbSeverity = typeof vuln.database_specific?.severity === "string" ? vuln.database_specific.severity : "";
  const severity = cvss?.type && cvss.score
    ? { type: asDataText(cvss.type, 40), score: asDataText(cvss.score, 80) }
    : dbSeverity
      ? { type: "OSV", score: asDataText(dbSeverity, 40) }
      : undefined;
  const references = (vuln.references ?? []).filter((item) => typeof item.url === "string");
  const advisory: Advisory = {
    id,
    aliases,
    summary: asDataText(vuln.summary, 200),
    source_database: sourceDatabase(id),
    url: advisoryUrl(id, references),
    affected_range_text: rangeText(vuln)
  };
  if (severity) advisory.severity = severity;
  const fixed = firstFixed(vuln, version);
  if (fixed) advisory.first_fixed_version = fixed;
  return advisory;
}

export function severityRank(value: string | undefined): number {
  const key = (value ?? "").toLowerCase();
  if (key.includes("critical")) return 4;
  if (key.includes("high")) return 3;
  if (key.includes("moderate") || key.includes("medium")) return 2;
  if (key.includes("low")) return 1;
  return 0;
}
