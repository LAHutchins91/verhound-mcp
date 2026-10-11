import { TTL } from "../config.js";
import { pep503 } from "../names.js";
import { cachedJson, type CachedJson } from "./http.js";

export function project(name: string, version?: string): Promise<CachedJson> {
  const base = `https://pypi.org/pypi/${encodeURIComponent(pep503(name))}`;
  const url = version ? `${base}/${encodeURIComponent(version)}/json` : `${base}/json`;
  return cachedJson({ source: "pypi", url, ttlSeconds: TTL.pypi });
}
