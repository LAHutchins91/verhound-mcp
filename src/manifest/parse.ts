import type { Ecosystem } from "../config.js";
import { validPackageName } from "../names.js";
import { isExactSpec } from "../semver.js";

export interface ParsedDep {
  ecosystem: Ecosystem;
  name: string;
  spec: string;
  version?: string;
  range: boolean;
  dev: boolean;
}

export interface ParsedRuntime {
  product: string;
  declared: string;
}

export interface ParseResult {
  format: string;
  dependencies: ParsedDep[];
  unresolved: { name: string; spec: string; reason: string }[];
  runtimes: ParsedRuntime[];
  notes: string[];
}

const BANNED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function empty(format: string, notes: string[] = []): ParseResult {
  return { format, dependencies: [], unresolved: [], runtimes: [], notes };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function ownEntries(value: unknown): [string, unknown][] {
  if (!isRecord(value)) return [];
  return Object.keys(value).filter((key) => !BANNED_KEYS.has(key)).map((key) => [key, value[key]]);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function pushDep(result: ParseResult, dep: ParsedDep, reason?: string): void {
  if (!validPackageName(dep.ecosystem, dep.name)) {
    result.unresolved.push({ name: dep.name.slice(0, 214), spec: dep.spec.slice(0, 200), reason: reason ?? "Name is not valid for this ecosystem." });
    return;
  }
  if (dep.range && !dep.version) {
    result.unresolved.push({
      name: dep.name,
      spec: dep.spec,
      reason: "range, not a pinned version; checked against the lowest matching version and the latest matching version"
    });
  }
  result.dependencies.push(dep);
}

function npmSpec(spec: string): { version?: string; range: boolean; skipReason?: string } {
  const value = spec.trim();
  if (!value || value === "*" || value === "latest" || value === "x") return { range: true };
  if (/^(workspace:|file:|link:|portal:|git\+|git:|github:|http:|https:|npm:)/.test(value) || value.includes("://")) {
    return { range: true, skipReason: "Not a registry version." };
  }
  const exact = isExactSpec(value.replace(/^=/, ""));
  if (exact && !value.startsWith("^") && !value.startsWith("~") && !value.includes(" ") && !/[<>]/.test(value)) {
    return { version: exact, range: false };
  }
  return { range: true };
}

function addNpm(result: ParseResult, name: string, spec: string, dev: boolean): void {
  if (typeof spec !== "string") return;
  const parsed = npmSpec(spec);
  if (parsed.skipReason) {
    result.unresolved.push({ name, spec: spec.slice(0, 200), reason: parsed.skipReason });
    return;
  }
  pushDep(result, { ecosystem: "npm", name, spec: spec.slice(0, 200), version: parsed.version, range: parsed.range, dev });
}

function nodeRuntime(spec: string | undefined): ParsedRuntime | null {
  if (!spec) return null;
  const match = /(\d+)/.exec(spec);
  if (!match) return null;
  return { product: "nodejs", declared: spec.slice(0, 60) };
}

export function parsePackageJson(content: string, includeDev: boolean): ParseResult {
  const json = safeJson(content);
  if (!isRecord(json)) return empty("package.json", ["package.json could not be read. Nothing was inferred."]);
  const result = empty("package.json");
  const sections = ["dependencies", "optionalDependencies", "peerDependencies"];
  if (includeDev) sections.push("devDependencies");
  for (const section of sections) {
    for (const [name, spec] of ownEntries(json[section])) {
      if (typeof spec === "string") addNpm(result, name, spec, section === "devDependencies");
    }
  }
  const engines = isRecord(json.engines) ? json.engines : null;
  const runtime = nodeRuntime(typeof engines?.node === "string" ? engines.node : undefined);
  if (runtime) result.runtimes.push(runtime);
  return result;
}

function addLocked(result: ParseResult, name: string, version: string, dev: boolean): void {
  if (!version || version.startsWith("file:") || version.startsWith("link:")) {
    result.unresolved.push({ name, spec: version, reason: "Not a registry version." });
    return;
  }
  pushDep(result, { ecosystem: "npm", name, spec: version, version, range: false, dev });
}

export function parseNpmLock(content: string, includeDev: boolean): ParseResult {
  const json = safeJson(content);
  if (!isRecord(json)) return empty("package-lock.json", ["package-lock.json could not be read. Nothing was inferred."]);
  const result = empty("package-lock.json");
  const packages = json.packages;
  if (isRecord(packages)) {
    result.format = `package-lock.json v${String(json.lockfileVersion ?? "2")}`;
    for (const [path, meta] of ownEntries(packages)) {
      if (!path || path === "" || !isRecord(meta)) continue;
      if (!includeDev && meta.dev === true) continue;
      const version = typeof meta.version === "string" ? meta.version : "";
      const name = path.startsWith("node_modules/") ? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length) : path;
      if (!version) continue;
      addLocked(result, name, version, meta.dev === true);
    }
    return result;
  }
  const dependencies = json.dependencies;
  if (isRecord(dependencies)) {
    result.format = "package-lock.json v1";
    const walk = (tree: Record<string, unknown>, devBranch: boolean) => {
      for (const [name, meta] of ownEntries(tree)) {
        if (!isRecord(meta)) continue;
        const dev = devBranch || meta.dev === true;
        if (includeDev || !dev) {
          const version = typeof meta.version === "string" ? meta.version : "";
          if (version) addLocked(result, name, version, dev);
        }
        if (isRecord(meta.dependencies)) walk(meta.dependencies, dev);
      }
    };
    walk(dependencies, false);
    return result;
  }
  result.notes.push("package-lock.json had no packages to read.");
  return result;
}

function pythonSpec(spec: string): { version?: string; range: boolean } {
  const value = spec.trim();
  const exact = /^(?:==|===)\s*([0-9][0-9A-Za-z.+_-]*)/.exec(value);
  if (exact) return { version: exact[1], range: false };
  return { range: true };
}

export function parseRequirements(content: string): ParseResult {
  const result = empty("requirements.txt");
  const text = content.replace(/\r\n/g, "\n").replace(/\\\n/g, " ");
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const withoutMarker = line.split(";")[0].split("--hash")[0].trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(withoutMarker);
    if (!match) {
      result.unresolved.push({ name: withoutMarker.slice(0, 80), spec: withoutMarker.slice(0, 200), reason: "Could not read this requirements line." });
      continue;
    }
    const spec = match[3] ?? "";
    const parsed = pythonSpec(spec);
    pushDep(result, { ecosystem: "pypi", name: match[1], spec: spec || match[1], version: parsed.version, range: parsed.range || !parsed.version, dev: false });
  }
  return result;
}

function tomlSection(content: string, header: string): string {
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let capture = false;
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      capture = trimmed === `[${header}]`;
      continue;
    }
    if (capture) out.push(line);
  }
  return out.join("\n");
}

function quotedStrings(block: string): string[] {
  const found: string[] = [];
  const re = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(block))) found.push(match[1].replace(/\\"/g, "\""));
  return found;
}

export function parsePyproject(content: string, includeDev: boolean): ParseResult {
  const result = empty("pyproject.toml");
  const project = tomlSection(content, "project");
  const depsLine = /dependencies\s*=\s*\[([\s\S]*?)\]/.exec(project);
  for (const spec of depsLine ? quotedStrings(depsLine[1]) : []) addPythonRequirement(result, spec, false);
  const python = /requires-python\s*=\s*"([^"]+)"/.exec(project);
  if (python) {
    const major = /(\d+\.\d+)/.exec(python[1]);
    result.runtimes.push({ product: "python", declared: major ? major[1] : python[1].slice(0, 30) });
  }
  const poetry = tomlSection(content, "tool.poetry.dependencies");
  for (const line of poetry.split("\n")) {
    const match = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*"([^"]+)"/.exec(line);
    if (!match || match[1] === "python") {
      const py = /^\s*python\s*=\s*"([^"]+)"/.exec(line);
      if (py && !result.runtimes.some((runtime) => runtime.product === "python")) {
        result.runtimes.push({ product: "python", declared: py[1].slice(0, 30) });
      }
      continue;
    }
    addPythonRequirement(result, `${match[1]}${match[2]}`, false, match[2]);
  }
  if (includeDev) {
    const dev = tomlSection(content, "project.optional-dependencies");
    for (const spec of quotedStrings(dev)) addPythonRequirement(result, spec, true);
  }
  if (!result.dependencies.length && !result.unresolved.length && !result.runtimes.length) {
    result.notes.push("No project dependencies were found in pyproject.toml.");
  }
  return result;
}

function addPythonRequirement(result: ParseResult, spec: string, dev: boolean, rawSpec?: string): void {
  const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(spec.trim());
  if (!match) return;
  const versionSpec = rawSpec ?? match[3] ?? "";
  const parsed = pythonSpec(versionSpec.startsWith("=") || versionSpec.startsWith(">") || versionSpec.startsWith("<") || versionSpec.startsWith("~") || versionSpec.startsWith("!") ? versionSpec : versionSpec);
  const caret = versionSpec.startsWith("^") || versionSpec.startsWith("~") || versionSpec.startsWith(">") || versionSpec.startsWith("<");
  const exact = !caret ? pythonSpec(versionSpec.startsWith("=") ? versionSpec : `==${versionSpec}`) : { range: true as const };
  const version = caret ? undefined : (parsed.version ?? (isExactSpec(versionSpec) ?? undefined));
  pushDep(result, {
    ecosystem: "pypi",
    name: match[1],
    spec: versionSpec || spec,
    version,
    range: !version,
    dev
  });
  void exact;
}

export function parsePoetryLock(content: string): ParseResult {
  const result = empty("poetry.lock");
  const blocks = content.replace(/\r\n/g, "\n").split(/\[\[package\]\]/);
  for (const block of blocks.slice(1)) {
    const name = /\nname\s*=\s*"([^"]+)"|^name\s*=\s*"([^"]+)"/.exec(block);
    const version = /\nversion\s*=\s*"([^"]+)"|^version\s*=\s*"([^"]+)"/.exec(block);
    const pkg = name?.[1] || name?.[2];
    const ver = version?.[1] || version?.[2];
    if (pkg && ver) pushDep(result, { ecosystem: "pypi", name: pkg, spec: ver, version: ver, range: false, dev: false });
  }
  return result;
}

export function parseGoMod(content: string): ParseResult {
  const result = empty("go.mod");
  const text = content.replace(/\r\n/g, "\n");
  const goLine = /^go\s+(\S+)/m.exec(text);
  if (goLine) result.runtimes.push({ product: "go", declared: goLine[1] });
  const replaces = new Map<string, { path: string; version?: string; local: boolean }>();
  const replaceRe = /replace\s+(\S+)\s+=>\s+(\S+)(?:\s+(\S+))?/g;
  let replace: RegExpExecArray | null;
  while ((replace = replaceRe.exec(text))) {
    const target = replace[2];
    const local = target.startsWith(".") || target.startsWith("/");
    replaces.set(replace[1], { path: target, version: replace[3]?.replace(/^v/, ""), local });
  }
  const requireRe = /^\s*(require\s+)?(\S+)\s+v?(\d[\w.+-]*)/gm;
  let match: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((match = requireRe.exec(text))) {
    const name = match[2];
    if (name === "go" || name === "module" || name === "replace" || name === "(" || name === ")") continue;
    if (!name.includes("/")) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const replacement = replaces.get(name);
    if (replacement?.local) {
      result.unresolved.push({ name, spec: match[3], reason: "Replaced with a local path." });
      continue;
    }
    const version = replacement?.version || match[3];
    const finalName = replacement && !replacement.local ? replacement.path : name;
    pushDep(result, { ecosystem: "go", name: finalName, spec: version, version, range: false, dev: false });
  }
  return result;
}

export function parseManifest(filename: string, content: string, includeDev = false): ParseResult {
  const base = filename.split(/[/\\]/).pop()?.toLowerCase() ?? "";
  if (base === "pnpm-lock.yaml" || base === "yarn.lock") {
    return empty(base, [`${base} is not parsed in this version. Paste a package-lock.json, package.json, requirements.txt, pyproject.toml, poetry.lock, or go.mod.`]);
  }
  if (base === "package-lock.json") return parseNpmLock(content, includeDev);
  if (base === "package.json") return parsePackageJson(content, includeDev);
  if (base === "requirements.txt" || base.endsWith("-requirements.txt")) return parseRequirements(content);
  if (base === "pyproject.toml") return parsePyproject(content, includeDev);
  if (base === "poetry.lock") return parsePoetryLock(content);
  if (base === "go.mod") return parseGoMod(content);
  const trimmed = content.trimStart();
  if (trimmed.startsWith("{") && content.includes("\"lockfileVersion\"")) return parseNpmLock(content, includeDev);
  if (trimmed.startsWith("{") && content.includes("\"dependencies\"")) return parsePackageJson(content, includeDev);
  if (base.endsWith(".txt")) return parseRequirements(content);
  return empty("unknown", ["This file format is not recognized. Nothing was inferred."]);
}
