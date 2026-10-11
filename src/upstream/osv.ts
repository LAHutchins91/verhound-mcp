import { TTL, type Ecosystem } from "../config.js";
import { cachedJson, type CachedJson } from "./http.js";

const OSV_ECOSYSTEM: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "PyPI",
  go: "Go",
  maven: "Maven",
  cargo: "crates.io",
  nuget: "NuGet"
};

export interface OsvQuery {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

export function osvEcosystem(ecosystem: Ecosystem): string {
  return OSV_ECOSYSTEM[ecosystem];
}

interface BatchResponse {
  results?: { vulns?: { id?: string; modified?: string }[]; next_page_token?: string }[];
  next_page_token?: string;
}

export async function queryBatch(queries: OsvQuery[]): Promise<{ ids: string[][]; notes: string[]; age: number; stale: boolean }> {
  const ids: string[][] = queries.map(() => []);
  const notes: string[] = [];
  let age = 0;
  let stale = false;
  if (!queries.length) return { ids, notes, age, stale };
  for (let offset = 0; offset < queries.length; offset += 500) {
    const slice = queries.slice(offset, offset + 500);
    let pageToken = "";
    const pageIds = slice.map(() => new Set<string>());
    do {
      const body: Record<string, unknown> = {
        queries: slice.map((query) => ({
          package: { name: query.name, ecosystem: OSV_ECOSYSTEM[query.ecosystem] },
          version: query.version
        }))
      };
      if (pageToken) body.page_token = pageToken;
      let response: CachedJson;
      try {
        response = await cachedJson({
          source: "osv",
          method: "POST",
          url: "https://api.osv.dev/v1/querybatch",
          body,
          ttlSeconds: TTL.osvQuery
        });
      } catch (error) {
        notes.push(error instanceof Error ? error.message : "OSV.dev did not respond; no advisory list is shown instead of a guess.");
        break;
      }
      age = Math.max(age, response.cacheAgeSeconds);
      stale = stale || response.stale;
      if (response.note) notes.push(response.note);
      const payload = response.json as BatchResponse | null;
      const results = payload?.results ?? [];
      results.forEach((result, index) => {
        for (const vuln of result.vulns ?? []) {
          if (vuln.id) pageIds[index]?.add(vuln.id);
        }
      });
      pageToken = payload?.next_page_token ?? "";
    } while (pageToken);
    pageIds.forEach((set, index) => {
      ids[offset + index] = [...set];
    });
  }
  return { ids, notes, age, stale };
}

export async function getVuln(id: string): Promise<CachedJson> {
  return cachedJson({
    source: "osv",
    url: `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
    ttlSeconds: TTL.osvVuln
  });
}
