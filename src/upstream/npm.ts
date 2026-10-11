import { TTL } from "../config.js";
import { encodePackageName } from "../names.js";
import { cachedJson, type CachedJson } from "./http.js";

export function packument(name: string): Promise<CachedJson> {
  return cachedJson({
    source: "npm",
    url: `https://registry.npmjs.org/${encodePackageName(name)}`,
    ttlSeconds: TTL.npmPackument,
    accept: "application/vnd.npm.install-v1+json",
    countNpm: true
  });
}

export async function weeklyDownloads(names: string[]): Promise<Map<string, number | null>> {
  const out = new Map<string, number | null>();
  const unscoped: string[] = [];
  for (const name of names) {
    if (name.startsWith("@")) {
      const single = await cachedJson({
        source: "npm",
        url: `https://api.npmjs.org/downloads/point/last-week/${encodePackageName(name)}`,
        ttlSeconds: TTL.npmDownloads,
        countNpm: true
      });
      const downloads = single.json && typeof single.json === "object" ? (single.json as { downloads?: unknown }).downloads : null;
      out.set(name, typeof downloads === "number" ? downloads : null);
    } else {
      unscoped.push(name);
    }
  }
  for (let i = 0; i < unscoped.length; i += 128) {
    const chunk = unscoped.slice(i, i + 128);
    const response = await cachedJson({
      source: "npm",
      url: `https://api.npmjs.org/downloads/point/last-week/${chunk.map(encodePackageName).join(",")}`,
      ttlSeconds: TTL.npmDownloads,
      countNpm: true
    });
    if (chunk.length === 1) {
      const downloads = response.json && typeof response.json === "object" ? (response.json as { downloads?: unknown }).downloads : null;
      out.set(chunk[0], typeof downloads === "number" ? downloads : null);
      continue;
    }
    const body = response.json && typeof response.json === "object" ? response.json as Record<string, { downloads?: unknown }> : {};
    for (const name of chunk) {
      const downloads = body[name]?.downloads;
      out.set(name, typeof downloads === "number" ? downloads : null);
    }
  }
  return out;
}
