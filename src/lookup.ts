import { advisoryFromOsv, type Advisory } from "./advisories.js";
import { nowDate, nowMs } from "./clock.js";
import { GITHUB_MALWARE_PER_CALL, type Ecosystem } from "./config.js";
import { validPackageName } from "./names.js";
import { SOURCE, type SourceCitation } from "./sources.js";
import { cmpVersion, isPrerelease, versionsBehind } from "./semver.js";
import { uniqueNotes } from "./text.js";
import { getPackage, getVersion } from "./upstream/depsdev.js";
import { githubMalware } from "./upstream/github.js";
import { UpstreamError, type CachedJson } from "./upstream/http.js";
import { packument } from "./upstream/npm.js";
import { getVuln, queryBatch } from "./upstream/osv.js";
import { getComposerPackage } from "./upstream/packagist.js";
import { project } from "./upstream/pypi.js";
import { getGemVersions } from "./upstream/rubygems.js";

export interface LookupRequest {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  includePrerelease?: boolean;
}

export interface VersionRow {
  version: string;
  publishedAt?: string;
  deprecated: boolean;
  deprecatedReason?: string;
}

export interface PackageFact {
  ecosystem: Ecosystem;
  name: string;
  exists: boolean | null;
  requested_version?: string;
  requested_version_found?: boolean;
  latest_stable?: string;
  latest_published_at?: string;
  requested_published_at?: string;
  deprecated: boolean;
  deprecated_reason?: string;
  declared_licenses: string[];
  advisories: Advisory[];
  advisories_known: boolean;
  versions_behind?: { major: number; minor: number; patch: number };
  notes: string[];
  sources: SourceCitation[];
  cacheAgeSeconds: number;
  stale: boolean;
  version_list: VersionRow[];
  engines_node?: string;
  python_requires?: string;
  peers: Record<string, string>;
  repo_url?: string;
  first_published_at?: string;
  registry_url?: string;
}

interface Draft {
  request: LookupRequest;
  fact: PackageFact;
  queryVersion?: string;
}

function blank(request: LookupRequest, note?: string): PackageFact {
  return {
    ecosystem: request.ecosystem,
    name: request.name,
    exists: null,
    requested_version: request.version,
    deprecated: false,
    declared_licenses: [],
    advisories: [],
    advisories_known: false,
    notes: note ? [note] : [],
    sources: [],
    cacheAgeSeconds: 0,
    stale: false,
    version_list: [],
    peers: {}
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function githubHttps(raw: string): string | undefined {
  const cleaned = raw.replace(/^git\+/, "").replace(/\.git$/, "");
  try {
    const url = new URL(cleaned);
    if (url.hostname !== "github.com") return undefined;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return undefined;
    return `https://github.com/${parts[0]}/${parts[1]}`;
  } catch {
    return undefined;
  }
}

async function settle(source: "depsdev" | "npm" | "pypi" | "rubygems" | "packagist", run: () => Promise<CachedJson>): Promise<{ value?: CachedJson; error?: string }> {
  try {
    return { value: await run() };
  } catch (error) {
    const message = error instanceof UpstreamError ? error.message : error instanceof Error ? error.message : "The upstream did not respond; nothing was filled in instead of a guess.";
    return { error: message || source };
  }
}

function absorb(fact: PackageFact, response: CachedJson | undefined, source: SourceCitation): void {
  if (!response) return;
  fact.sources.push(source);
  fact.cacheAgeSeconds = Math.max(fact.cacheAgeSeconds, response.cacheAgeSeconds);
  fact.stale = fact.stale || response.stale;
  if (response.note) fact.notes.push(response.note);
}

/** Workers that load package metadata. The per-source gates in http.ts still limit each upstream. */
const METADATA_WORKERS = 24;

export const TIME_LIMIT_NOTE = "Not checked: this call reached its time limit before this package was looked up. Split the manifest or check this package on its own.";

export async function lookupPackages(requests: LookupRequest[], options: { deadline?: number } = {}): Promise<PackageFact[]> {
  const drafts: Draft[] = [];
  let next = 0;
  const worker = async () => {
    while (next < requests.length) {
      const index = next;
      next += 1;
      await loadDraft(requests[index], index);
    }
  };
  const loadDraft = async (request: LookupRequest, index: number) => {
    // Packages not started before the deadline are reported as not checked, so a large
    // manifest returns a partial answer instead of hitting the function time limit.
    if (options.deadline !== undefined && nowMs() >= options.deadline) {
      drafts[index] = { request, fact: blank(request, TIME_LIMIT_NOTE), queryVersion: undefined };
      return;
    }
    const fact = await loadMetadata(request);
    drafts[index] = { request, fact, queryVersion: fact.requested_version && fact.requested_version_found !== false ? fact.requested_version : fact.latest_stable };
    if (fact.requested_version && fact.requested_version_found === false && fact.exists) {
      drafts[index].queryVersion = fact.requested_version;
    }
  };
  await Promise.all(Array.from({ length: Math.min(METADATA_WORKERS, requests.length) }, worker));

  const queries = drafts.flatMap((draft) => draft.fact.exists && draft.queryVersion
    ? [{ ecosystem: draft.request.ecosystem, name: draft.fact.name, version: draft.queryVersion }]
    : []);
  const batch = queries.length ? await queryBatch(queries.map((query) => ({ ecosystem: query.ecosystem, name: query.name, version: query.version }))) : { ids: [], notes: [], age: 0, stale: false };
  const idLists: string[][] = drafts.map(() => []);
  let cursor = 0;
  drafts.forEach((draft, index) => {
    if (draft.fact.exists && draft.queryVersion) {
      idLists[index] = batch.ids[cursor] ?? [];
      cursor += 1;
    }
  });
  const uniqueIds = [...new Set(idLists.flat())];
  const vulns = new Map<string, { raw: unknown | null; note?: string; age: number; stale: boolean }>();
  await Promise.all(uniqueIds.map(async (id) => {
    try {
      const response = await getVuln(id);
      vulns.set(id, { raw: response.json, note: response.note, age: response.cacheAgeSeconds, stale: response.stale });
    } catch (error) {
      vulns.set(id, { raw: null, note: error instanceof Error ? error.message : undefined, age: 0, stale: false });
    }
  }));

  // GitHub malware lookups are capped per call. Unauthenticated GitHub allows 60 requests an hour,
  // and a large manifest must not turn into thousands of calls or run past the function time limit.
  // OSV.dev MAL- records still cover every package.
  const malwareNames = new Map<string, Promise<Awaited<ReturnType<typeof githubMalware>>>>();
  const malwareFor = (ecosystem: Ecosystem, name: string) => {
    const key = `${ecosystem}:${name.toLowerCase()}`;
    const known = malwareNames.get(key);
    if (known) return known;
    if (malwareNames.size >= GITHUB_MALWARE_PER_CALL) return null;
    const started = githubMalware(ecosystem, name);
    malwareNames.set(key, started);
    return started;
  };

  const facts = await Promise.all(drafts.map(async (draft, index) => {
    const fact = draft.fact;
    if (batch.notes.length) fact.notes.push(...batch.notes);
    fact.cacheAgeSeconds = Math.max(fact.cacheAgeSeconds, batch.age);
    fact.stale = fact.stale || batch.stale;
    if (fact.exists && draft.queryVersion) {
      if (batch.notes.some((note) => note.includes("OSV.dev did not respond"))) {
        fact.advisories_known = false;
      } else {
        fact.advisories_known = true;
        fact.sources.push(SOURCE.osv);
        const version = draft.queryVersion;
        for (const id of idLists[index] ?? []) {
          const loaded = vulns.get(id);
          if (loaded) {
            fact.cacheAgeSeconds = Math.max(fact.cacheAgeSeconds, loaded.age);
            fact.stale = fact.stale || loaded.stale;
          }
          const advisory = loaded?.raw ? advisoryFromOsv(loaded.raw, version) : null;
          if (advisory) fact.advisories.push(advisory);
          else {
            fact.advisories.push({
              id,
              aliases: [],
              summary: "",
              source_database: id.startsWith("GHSA-") ? "GitHub Advisory Database" : "OSV.dev",
              url: `https://osv.dev/vulnerability/${id}`,
              affected_range_text: ""
            });
            if (loaded?.note) fact.notes.push(loaded.note);
          }
        }
        if (fact.advisories_known && fact.advisories.length === 0) {
          fact.notes.push(`No known advisories in OSV.dev as of ${nowDate().toISOString()}.`);
        }
      }
    }
    const malwareLookup = fact.exists !== null ? malwareFor(draft.request.ecosystem, fact.name) : null;
    if (fact.exists !== null && !malwareLookup) {
      fact.notes.push(`The GitHub malware check covers the first ${GITHUB_MALWARE_PER_CALL} package names in a call; this package was not in it. OSV.dev malware records (MAL-) were still checked.`);
    }
    if (malwareLookup) {
      const malware = await malwareLookup;
      fact.cacheAgeSeconds = Math.max(fact.cacheAgeSeconds, malware.age);
      fact.stale = fact.stale || malware.stale;
      if (malware.note && !malware.note.includes("404")) fact.notes.push(malware.note);
      if (malware.advisories.length) {
        fact.sources.push(SOURCE.github);
        for (const advisory of malware.advisories) {
          if (!fact.advisories.some((item) => item.id === advisory.id)) fact.advisories.push(advisory);
        }
        fact.notes.push("Known malware records from the GitHub Advisory Database are included and attributed to that source.");
      }
    }
    fact.advisories.sort((a, b) => Number(Boolean(b.malicious || b.id.startsWith("MAL-"))) - Number(Boolean(a.malicious || a.id.startsWith("MAL-"))));
    const sourceMap = new Map(fact.sources.map((source) => [source.id, source]));
    fact.sources = [...sourceMap.values()];
    fact.notes = uniqueNotes(fact.notes);
    return fact;
  }));
  return facts;
}

async function loadMetadata(request: LookupRequest): Promise<PackageFact> {
  if (!validPackageName(request.ecosystem, request.name)) {
    return blank(request, "That package name is not valid for this ecosystem. Nothing was looked up.");
  }
  const fact = blank(request);
  const onDepsDev = request.ecosystem !== "composer";
  const deps = onDepsDev ? await settle("depsdev", () => getPackage(request.ecosystem, request.name)) : {};
  const registry = request.ecosystem === "npm"
    ? await settle("npm", () => packument(request.name))
    : request.ecosystem === "pypi"
      ? await settle("pypi", () => project(request.name))
      : request.ecosystem === "rubygems"
        ? await settle("rubygems", () => getGemVersions(request.name))
        : request.ecosystem === "composer"
          ? await settle("packagist", () => getComposerPackage(request.name))
          : undefined;
  if (deps.error) fact.notes.push(deps.error);
  if (registry?.error) fact.notes.push(registry.error);
  if (onDepsDev) absorb(fact, deps.value, SOURCE.depsdev);
  if (request.ecosystem === "npm") absorb(fact, registry?.value, SOURCE.npm);
  if (request.ecosystem === "pypi") absorb(fact, registry?.value, SOURCE.pypi);
  if (request.ecosystem === "rubygems") absorb(fact, registry?.value, SOURCE.rubygems);
  if (request.ecosystem === "composer") absorb(fact, registry?.value, SOURCE.packagist);

  const depsMissing = Boolean(deps.value?.negative);
  const registryMissing = Boolean(registry?.value?.negative);
  const depsKnown = Boolean(deps.value && !deps.value.negative);
  const registryKnown = Boolean(registry?.value && !registry.value.negative);
  if (request.ecosystem === "npm" || request.ecosystem === "pypi" || request.ecosystem === "rubygems" || request.ecosystem === "composer") {
    if (registryMissing) fact.exists = false;
    else if (registryKnown || (request.ecosystem !== "composer" && depsKnown)) fact.exists = true;
    else fact.exists = null;
  } else if (depsMissing) fact.exists = false;
  else if (depsKnown) fact.exists = true;
  else fact.exists = null;

  if (fact.exists === false) {
    fact.notes.push("The name was not found in the registry.");
    fact.notes = uniqueNotes(fact.notes);
    return fact;
  }

  const versions = new Map<string, VersionRow>();
  const depsBody = asRecord(deps.value?.json);
  const depsVersions = Array.isArray(depsBody?.versions) ? depsBody.versions : [];
  let defaultVersion = "";
  for (const entry of depsVersions) {
    const row = asRecord(entry);
    const key = asRecord(row?.versionKey);
    const version = typeof key?.version === "string" ? key.version : "";
    if (!version) continue;
    versions.set(version, {
      version,
      publishedAt: typeof row?.publishedAt === "string" ? row.publishedAt : undefined,
      deprecated: row?.isDeprecated === true,
      deprecatedReason: typeof row?.deprecatedReason === "string" && row.deprecatedReason ? row.deprecatedReason : undefined
    });
    if (row?.isDefault === true) defaultVersion = version;
  }

  const npmBody = request.ecosystem === "npm" ? asRecord(registry?.value?.json) : null;
  const npmVersions = asRecord(npmBody?.versions);
  const distTags = asRecord(npmBody?.["dist-tags"]);
  const npmLatest = typeof distTags?.latest === "string" ? distTags.latest : "";
  if (typeof npmBody?.name === "string" && npmBody.name) fact.name = npmBody.name;
  if (npmVersions) {
    for (const [version, meta] of Object.entries(npmVersions)) {
      const row = asRecord(meta);
      const current = versions.get(version) ?? { version, deprecated: false };
      if (typeof row?.deprecated === "string" && row.deprecated) {
        current.deprecated = true;
        current.deprecatedReason = current.deprecatedReason || row.deprecated;
      }
      versions.set(version, current);
    }
  }

  const pypiBody = request.ecosystem === "pypi" ? asRecord(registry?.value?.json) : null;
  const info = asRecord(pypiBody?.info);
  const releases = asRecord(pypiBody?.releases);
  if (typeof info?.name === "string" && info.name) fact.name = info.name;
  const gemVersions = request.ecosystem === "rubygems" && Array.isArray(registry?.value?.json) ? registry.value.json : [];
  for (const entry of gemVersions) {
    const row = asRecord(entry);
    const version = typeof row?.number === "string" ? row.number : "";
    if (!version) continue;
    const current = versions.get(version) ?? { version, deprecated: false };
    if (typeof row?.created_at === "string" && !current.publishedAt) current.publishedAt = row.created_at;
    if (row?.yanked === true) current.deprecated = true;
    versions.set(version, current);
  }
  let gemLatest = "";
  if (request.ecosystem === "rubygems" && gemVersions.length) {
    const newest = asRecord(gemVersions[0]);
    gemLatest = typeof newest?.number === "string" ? newest.number : "";
    const licenses = Array.isArray(newest?.licenses) ? newest.licenses.filter((item): item is string => typeof item === "string") : [];
    if (licenses.length && !fact.declared_licenses.length) fact.declared_licenses = licenses.slice(0, 20);
    fact.registry_url = `https://rubygems.org/gems/${encodeURIComponent(fact.name)}`;
  }

  const composerBody = request.ecosystem === "composer" ? asRecord(registry?.value?.json) : null;
  const composerPackages = asRecord(composerBody?.packages);
  const composerRows = composerPackages ? Object.values(composerPackages).flatMap((value) => Array.isArray(value) ? value : []) : [];
  for (const entry of composerRows) {
    const row = asRecord(entry);
    const version = composerVersionOf(row);
    if (!version || version.toLowerCase().includes("dev")) continue;
    const current = versions.get(version) ?? { version, deprecated: false };
    if (typeof row?.time === "string" && !current.publishedAt) current.publishedAt = row.time;
    if (row?.abandoned) current.deprecated = true;
    versions.set(version, current);
  }
  if (request.ecosystem === "composer" && fact.exists) {
    fact.registry_url = `https://packagist.org/packages/${fact.name}`;
    const newest = asRecord(composerRows[0]);
    const licenses = Array.isArray(newest?.license) ? newest.license.filter((item): item is string => typeof item === "string") : [];
    if (licenses.length) fact.declared_licenses = licenses.slice(0, 20);
    const source = asRecord(newest?.source);
    const repo = typeof source?.url === "string" ? githubHttps(source.url) : undefined;
    if (repo) fact.repo_url = repo;
  }

  if (releases) {
    for (const [version, files] of Object.entries(releases)) {
      const list = Array.isArray(files) ? files : [];
      const first = asRecord(list[0]);
      const current = versions.get(version) ?? { version, deprecated: false };
      const upload = typeof first?.upload_time_iso_8601 === "string" ? first.upload_time_iso_8601 : undefined;
      if (upload && !current.publishedAt) current.publishedAt = upload;
      if (first?.yanked === true) current.deprecated = true;
      versions.set(version, current);
    }
  }

  fact.version_list = [...versions.values()].sort((a, b) => cmpVersion(a.version, b.version));
  const published = fact.version_list.map((row) => row.publishedAt).filter((value): value is string => Boolean(value)).sort();
  if (published[0]) fact.first_published_at = published[0];

  const stable = fact.version_list.filter((row) => !isPrerelease(row.version));
  const pool = request.includePrerelease || stable.length === 0 ? fact.version_list : stable;
  let latest = pool[pool.length - 1]?.version ?? "";
  if (request.ecosystem === "npm" && npmLatest && (request.includePrerelease || !isPrerelease(npmLatest))) latest = npmLatest;
  else if (request.ecosystem === "pypi" && typeof info?.version === "string") latest = info.version;
  else if (gemLatest && (request.includePrerelease || !isPrerelease(gemLatest))) latest = gemLatest;
  else if (defaultVersion && (request.includePrerelease || !isPrerelease(defaultVersion))) latest = defaultVersion;
  if (latest) fact.latest_stable = latest;
  fact.latest_published_at = versions.get(latest)?.publishedAt;

  if (request.version) {
    fact.requested_version = request.version;
    fact.requested_version_found = versions.has(request.version) || (npmVersions ? request.version in npmVersions : false) || (releases ? request.version in releases : false);
    if (fact.version_list.length === 0 && fact.exists) fact.requested_version_found = undefined;
    fact.requested_published_at = versions.get(request.version)?.publishedAt;
  }

  const focus = request.version && fact.requested_version_found !== false ? request.version : latest;
  const focusRow = focus ? versions.get(focus) : undefined;
  fact.deprecated = Boolean(focusRow?.deprecated);
  if (focusRow?.deprecatedReason) fact.deprecated_reason = focusRow.deprecatedReason.slice(0, 200);
  if (request.ecosystem === "pypi" && info && (!request.version || request.version === info.version)) {
    if (info.yanked === true) fact.deprecated = true;
    const license = typeof info.license_expression === "string" && info.license_expression
      ? info.license_expression
      : typeof info.license === "string" ? info.license : "";
    if (license && license.toUpperCase() !== "UNKNOWN") fact.declared_licenses = [license.slice(0, 80)];
    if (typeof info.requires_python === "string") fact.python_requires = info.requires_python.slice(0, 80);
    fact.registry_url = typeof info.package_url === "string" ? info.package_url : `https://pypi.org/project/${encodeURIComponent(fact.name)}/`;
    const urls = asRecord(info.project_urls);
    const homepage = typeof info.home_page === "string" ? info.home_page : "";
    const repoCandidate = homepage || (urls ? Object.values(urls).find((value) => typeof value === "string") as string : "");
    const repo = repoCandidate ? githubHttps(repoCandidate) : undefined;
    if (repo) fact.repo_url = repo;
  }
  if (request.ecosystem === "npm") {
    fact.registry_url = `https://www.npmjs.com/package/${fact.name}`;
    const meta = npmVersions ? asRecord(npmVersions[focus]) : null;
    const engines = asRecord(meta?.engines);
    if (typeof engines?.node === "string") fact.engines_node = engines.node.slice(0, 80);
    const peers = asRecord(meta?.peerDependencies);
    if (peers) {
      for (const [name, spec] of Object.entries(peers)) {
        if (typeof spec === "string" && !["__proto__", "constructor", "prototype"].includes(name)) fact.peers[name] = spec.slice(0, 80);
      }
    }
  }

  if (request.ecosystem === "composer" && focus) {
    const match = composerRows.map((entry) => asRecord(entry)).find((row) => composerVersionOf(row) === focus);
    const licenses = Array.isArray(match?.license) ? match.license.filter((item): item is string => typeof item === "string") : [];
    if (licenses.length) fact.declared_licenses = licenses.slice(0, 20);
  }
  if (request.ecosystem === "rubygems" && focus) {
    const match = gemVersions.map((entry) => asRecord(entry)).find((row) => row?.number === focus);
    const licenses = Array.isArray(match?.licenses) ? match.licenses.filter((item): item is string => typeof item === "string") : [];
    if (licenses.length) fact.declared_licenses = licenses.slice(0, 20);
  }

  if (focus && fact.exists && request.ecosystem !== "composer") {
    const versionDoc = await settle("depsdev", () => getVersion(request.ecosystem, fact.name, focus));
    if (versionDoc.error) fact.notes.push(versionDoc.error);
    absorb(fact, versionDoc.value, SOURCE.depsdev);
    const body = asRecord(versionDoc.value?.json);
    const licenses = Array.isArray(body?.licenses) ? body.licenses.filter((item): item is string => typeof item === "string") : [];
    if (licenses.length) fact.declared_licenses = licenses.slice(0, 20).map((item) => item.slice(0, 80));
    if (body?.isDeprecated === true) fact.deprecated = true;
    if (typeof body?.deprecatedReason === "string" && body.deprecatedReason) fact.deprecated_reason = body.deprecatedReason.slice(0, 200);
    const links = Array.isArray(body?.links) ? body.links : [];
    for (const link of links) {
      const row = asRecord(link);
      if (row?.label === "SOURCE_REPO" && typeof row.url === "string") {
        fact.repo_url = githubHttps(row.url) ?? fact.repo_url;
      }
    }
    const related = Array.isArray(body?.relatedProjects) ? body.relatedProjects : [];
    for (const projectRow of related) {
      const row = asRecord(projectRow);
      const key = asRecord(row?.projectKey);
      if (row?.relationType === "SOURCE_REPO" && typeof key?.id === "string" && key.id.startsWith("github.com/")) {
        fact.repo_url = fact.repo_url ?? `https://${key.id}`;
      }
    }
  }

  if (fact.latest_stable && request.version && fact.requested_version_found) {
    const behind = versionsBehind(request.version, fact.latest_stable);
    if (behind) fact.versions_behind = behind;
  }
  if (fact.declared_licenses.length) {
    fact.notes.push("Licenses are the declared license from package metadata and may be wrong.");
  }
  fact.notes = uniqueNotes(fact.notes);
  return fact;
}

function composerVersionOf(row: Record<string, unknown> | null): string {
  if (!row) return "";
  const normalized = typeof row.version_normalized === "string" ? row.version_normalized : "";
  const parts = normalized.split(".").filter(Boolean);
  if (parts.length >= 3 && parts.slice(3).every((part) => part === "0")) return parts.slice(0, 3).join(".");
  if (normalized && !normalized.endsWith(".9999999")) return normalized;
  const raw = typeof row.version === "string" ? row.version : "";
  return raw.replace(/^v/i, "");
}

export async function versionMeta(ecosystem: Ecosystem, name: string, version: string): Promise<{ engines_node?: string; python_requires?: string; peers: Record<string, string> }> {
  const peers: Record<string, string> = {};
  if (ecosystem === "npm") {
    const doc = await packument(name);
    const versions = asRecord(asRecord(doc.json)?.versions);
    const meta = versions ? asRecord(versions[version]) : null;
    const engines = asRecord(meta?.engines);
    const peerMap = asRecord(meta?.peerDependencies);
    if (peerMap) {
      for (const [peer, spec] of Object.entries(peerMap)) {
        if (typeof spec === "string") peers[peer] = spec;
      }
    }
    return { engines_node: typeof engines?.node === "string" ? engines.node : undefined, peers };
  }
  if (ecosystem === "pypi") {
    const doc = await project(name, version);
    const info = asRecord(asRecord(doc.json)?.info);
    return { python_requires: typeof info?.requires_python === "string" ? info.requires_python : undefined, peers };
  }
  return { peers };
}
