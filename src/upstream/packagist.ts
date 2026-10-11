import { TTL } from "../config.js";
import { cachedJson, type CachedJson } from "./http.js";

/** Packagist p2 metadata. The slash in vendor/package stays a path separator. */
export function packagistUrl(name: string): string {
  const [vendor, pkg] = name.split("/");
  return `https://repo.packagist.org/p2/${encodeURIComponent(vendor)}/${encodeURIComponent(pkg)}.json`;
}

export function getComposerPackage(name: string): Promise<CachedJson> {
  return cachedJson({ source: "packagist", url: packagistUrl(name), ttlSeconds: TTL.pypi });
}
