import { TTL } from "../config.js";
import { cachedJson, type CachedJson } from "./http.js";

export function rubygemsVersionsUrl(name: string): string {
  return `https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`;
}

export function rubygemsGemUrl(name: string): string {
  return `https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`;
}

export function getGemVersions(name: string): Promise<CachedJson> {
  return cachedJson({ source: "rubygems", url: rubygemsVersionsUrl(name), ttlSeconds: TTL.pypi });
}

export function getGem(name: string): Promise<CachedJson> {
  return cachedJson({ source: "rubygems", url: rubygemsGemUrl(name), ttlSeconds: TTL.pypi });
}
