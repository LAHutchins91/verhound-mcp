import { TTL, type Ecosystem } from "../config.js";
import { encodePackageName } from "../names.js";
import { cachedJson, type CachedJson } from "./http.js";

const SYSTEMS: Record<Ecosystem, string> = {
  npm: "NPM",
  pypi: "PYPI",
  go: "GO",
  maven: "MAVEN",
  cargo: "CARGO",
  nuget: "NUGET"
};

export function depsSystem(ecosystem: Ecosystem): string {
  return SYSTEMS[ecosystem];
}

export function packageUrl(ecosystem: Ecosystem, name: string): string {
  return `https://api.deps.dev/v3/systems/${SYSTEMS[ecosystem]}/packages/${encodePackageName(name)}`;
}

export function versionUrl(ecosystem: Ecosystem, name: string, version: string): string {
  return `${packageUrl(ecosystem, name)}/versions/${encodePackageName(version)}`;
}

export function getPackage(ecosystem: Ecosystem, name: string): Promise<CachedJson> {
  return cachedJson({ source: "depsdev", url: packageUrl(ecosystem, name), ttlSeconds: TTL.depsdev });
}

export function getVersion(ecosystem: Ecosystem, name: string, version: string): Promise<CachedJson> {
  return cachedJson({ source: "depsdev", url: versionUrl(ecosystem, name, version), ttlSeconds: TTL.depsdev });
}
