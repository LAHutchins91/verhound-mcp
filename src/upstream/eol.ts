import { TTL } from "../config.js";
import { cachedJson, type CachedJson } from "./http.js";

const ALIASES: Record<string, string> = {
  node: "nodejs",
  "node.js": "nodejs",
  nodejs: "nodejs",
  python: "python",
  py: "python",
  postgres: "postgresql",
  postgresql: "postgresql",
  pg: "postgresql",
  go: "go",
  golang: "go",
  java: "java",
  "c#": "dotnet",
  dotnet: "dotnet",
  ".net": "dotnet"
};

export function eolSlug(product: string): string | null {
  const key = product.trim().toLowerCase();
  if (ALIASES[key]) return ALIASES[key];
  if (!/^[a-z0-9][a-z0-9.+-]{0,59}$/.test(key)) return null;
  return key;
}

export function product(slug: string): Promise<CachedJson> {
  return cachedJson({
    source: "eol",
    url: `https://endoflife.date/api/v1/products/${encodeURIComponent(slug)}`,
    ttlSeconds: TTL.eol
  });
}
