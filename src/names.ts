import type { Ecosystem } from "./config.js";
import { POPULAR } from "./data/popular.js";

const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const GO_NAME = /^[a-z0-9][a-z0-9.-]*(?:\/[A-Za-z0-9._~+-]+)+$/;
const MAVEN_NAME = /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/;
const SIMPLE_NAME = /^[A-Za-z0-9_.-]+$/;
const GEM_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const COMPOSER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;

export function pep503(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

export function normalizeName(ecosystem: Ecosystem, name: string): string {
  if (ecosystem === "pypi") return pep503(name);
  if (ecosystem === "npm" || ecosystem === "nuget" || ecosystem === "cargo" || ecosystem === "rubygems") return name.trim();
  if (ecosystem === "composer") return name.trim().toLowerCase();
  return name.trim();
}

export function validPackageName(ecosystem: Ecosystem, name: string): boolean {
  const value = name.trim();
  if (!value || value.length > 214) return false;
  if (value.includes("://") || value.includes("\\") || value.includes("..") || /[\s?#%]/.test(value)) return false;
  if (ecosystem === "npm") return NPM_NAME.test(value);
  if (ecosystem === "pypi") return PYPI_NAME.test(value);
  if (ecosystem === "go") return GO_NAME.test(value) && !value.split("/").includes("..");
  if (ecosystem === "maven") return MAVEN_NAME.test(value);
  if (ecosystem === "cargo") return /^[A-Za-z0-9_-]+$/.test(value);
  if (ecosystem === "rubygems") return GEM_NAME.test(value);
  if (ecosystem === "composer") return COMPOSER_NAME.test(value);
  return SIMPLE_NAME.test(value);
}

export function encodePackageName(name: string): string {
  return encodeURIComponent(name);
}

/** Optimal string alignment Damerau-Levenshtein distance. */
export function damerau(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 2) return 3;
  const rows = a.length + 1;
  const cols = b.length + 1;
  const matrix: number[][] = Array.from({ length: rows }, () => Array(cols).fill(0));
  for (let i = 0; i < rows; i += 1) matrix[i][0] = i;
  for (let j = 0; j < cols; j += 1) matrix[0][j] = j;
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, matrix[i - 2][j - 2] + 1);
      }
      matrix[i][j] = best;
    }
  }
  return matrix[a.length][b.length];
}

function compareKey(ecosystem: Ecosystem, name: string): string {
  if (ecosystem === "pypi") return pep503(name);
  return name.trim().toLowerCase();
}

export function similarPopular(ecosystem: Ecosystem, name: string, limit: number): { name: string }[] {
  const list = POPULAR[ecosystem] ?? [];
  const key = compareKey(ecosystem, name);
  if (key.length < 4) return [];
  // A name that is itself on the popular list is not flagged as a look-alike of another one.
  if (list.some((candidate) => compareKey(ecosystem, candidate) === key)) return [];
  const hits: { name: string; distance: number }[] = [];
  for (const candidate of list) {
    const other = compareKey(ecosystem, candidate);
    if (other === key) continue;
    const distance = damerau(key, other);
    if (distance <= 2) hits.push({ name: candidate, distance });
  }
  hits.sort((a, b) => a.distance - b.distance || a.name.localeCompare(b.name));
  return hits.slice(0, limit).map((hit) => ({ name: hit.name }));
}
