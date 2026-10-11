import type { Advisory } from "../advisories.js";
import { TTL, type Ecosystem } from "../config.js";
import { asDataText } from "../text.js";
import { cachedJson, type CachedJson } from "./http.js";

const GITHUB_ECOSYSTEM: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "pip",
  go: "go",
  maven: "maven",
  cargo: "rust",
  nuget: "nuget",
  rubygems: "rubygems",
  composer: "composer"
};

export function githubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export function githubMalwareUrl(ecosystem: Ecosystem, name: string): string {
  const params = new URLSearchParams({
    ecosystem: GITHUB_ECOSYSTEM[ecosystem],
    affects: name,
    type: "malware",
    per_page: "20"
  });
  return `https://api.github.com/advisories?${params.toString()}`;
}

interface GithubAdvisory {
  ghsa_id?: string;
  summary?: string;
  severity?: string;
  html_url?: string;
  type?: string;
  vulnerabilities?: { vulnerable_version_range?: string; package?: { name?: string } }[];
}

function githubLevel(value: string): string | undefined {
  const key = value.trim().toLowerCase();
  if (key === "critical" || key === "high" || key === "moderate" || key === "low") return key;
  if (key === "medium") return "moderate";
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** Malware advisories from the GitHub Advisory Database. Empty when the check does not succeed. */
export async function githubMalware(ecosystem: Ecosystem, name: string): Promise<{ advisories: Advisory[]; note?: string; age: number; stale: boolean }> {
  let response: CachedJson;
  try {
    response = await cachedJson({
      source: "github",
      url: githubMalwareUrl(ecosystem, name),
      ttlSeconds: TTL.osvVuln,
      accept: "application/vnd.github+json",
      extraHeaders: githubHeaders()
    });
  } catch (error) {
    const note = error instanceof Error ? error.message : "The GitHub API did not respond; that source is omitted instead of a guess.";
    return { advisories: [], note, age: 0, stale: false };
  }
  if (response.negative || !Array.isArray(response.json)) {
    return { advisories: [], note: response.note, age: response.cacheAgeSeconds, stale: response.stale };
  }
  const advisories: Advisory[] = [];
  for (const entry of response.json) {
    const row = asRecord(entry) as GithubAdvisory | null;
    if (!row || row.type !== "malware") continue;
    const id = typeof row.ghsa_id === "string" ? row.ghsa_id : "";
    if (!id.startsWith("GHSA-")) continue;
    const listed = (row.vulnerabilities ?? []).some((item) => !item.package?.name || item.package.name.toLowerCase() === name.toLowerCase());
    if (!listed) continue;
    const range = (row.vulnerabilities ?? []).map((item) => item.vulnerable_version_range).filter((item): item is string => Boolean(item)).join(" | ");
    advisories.push({
      id,
      aliases: [],
      summary: asDataText(row.summary, 200),
      severity: row.severity ? { type: "GitHub", score: asDataText(row.severity, 40), level: githubLevel(row.severity) } : undefined,
      source_database: "GitHub Advisory Database",
      url: typeof row.html_url === "string" && row.html_url.startsWith("https://github.com/advisories/") ? row.html_url : `https://github.com/advisories/${id}`,
      affected_range_text: range.slice(0, 300),
      malicious: true
    });
  }
  return { advisories, note: response.note, age: response.cacheAgeSeconds, stale: response.stale };
}
