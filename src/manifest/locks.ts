import type { Ecosystem } from "../config.js";
import { validPackageName } from "../names.js";
import type { ParseResult } from "./parse.js";

function result(format: string, notes: string[] = []): ParseResult {
  return { format, dependencies: [], unresolved: [], runtimes: [], notes };
}

function add(parsed: ParseResult, ecosystem: Ecosystem, name: string, version: string, dev = false): void {
  const spec = version.slice(0, 200);
  if (!validPackageName(ecosystem, name)) {
    parsed.unresolved.push({ name: name.slice(0, 214), spec, reason: "Name is not valid for this ecosystem." });
    return;
  }
  if (!version || version.includes("${") || version === "*" || version === "latest") {
    parsed.unresolved.push({ name, spec, reason: "range, not a pinned version; checked against the lowest matching version and the latest matching version" });
    parsed.dependencies.push({ ecosystem, name, spec, range: true, dev });
    return;
  }
  parsed.dependencies.push({ ecosystem, name, spec, version, range: false, dev });
}

function skip(parsed: ParseResult, name: string, spec: string, reason: string): void {
  parsed.unresolved.push({ name: name.slice(0, 214), spec: spec.slice(0, 200), reason });
}

export function parseCargoLock(content: string): ParseResult {
  const parsed = result("Cargo.lock");
  const blocks = content.replace(/\r\n/g, "\n").split(/\n?\[\[package\]\]\n?/);
  for (const block of blocks) {
    const name = /^name = "([^"]+)"/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"/m.exec(block)?.[1];
    if (!name || !version) continue;
    const source = /^source = "([^"]*)"/m.exec(block)?.[1] ?? "";
    if (source.startsWith("git+")) {
      skip(parsed, name, version, "Git source, not a crates.io version.");
      continue;
    }
    if (!source.startsWith("registry+")) continue;
    add(parsed, "cargo", name, version);
  }
  if (!parsed.dependencies.length && !parsed.unresolved.length) parsed.notes.push("Cargo.lock had no crates.io packages to read.");
  return parsed;
}

/** Removes XML comments in one pass. An unclosed comment drops the rest of the text. */
function stripComments(text: string): string {
  let out = "";
  let pos = 0;
  for (;;) {
    const open = text.indexOf("<!--", pos);
    if (open === -1) return out + text.slice(pos);
    out += text.slice(pos, open);
    const close = text.indexOf("-->", open + 4);
    if (close === -1) return out;
    pos = close + 3;
  }
}

interface XmlBlock {
  start: number;
  end: number;
  attrs: string;
  inner: string;
}

/**
 * Finds <tag ...>inner</tag> and <tag .../> blocks with indexOf, so the cost stays linear.
 * Lazy regexes re-scan to the end of the input for every unclosed tag, which is quadratic on hostile input.
 * Scanning stops at the first unclosed tag.
 */
function findBlocks(text: string, tag: string): XmlBlock[] {
  const lower = text.toLowerCase();
  const name = tag.toLowerCase();
  const closeTag = `</${name}>`;
  const found: XmlBlock[] = [];
  let pos = 0;
  for (;;) {
    const open = lower.indexOf(`<${name}`, pos);
    if (open === -1) break;
    const after = lower.charAt(open + name.length + 1);
    if (after !== ">" && after !== "/" && !/\s/.test(after)) {
      pos = open + 1;
      continue;
    }
    const gt = lower.indexOf(">", open);
    if (gt === -1) break;
    if (lower.charAt(gt - 1) === "/") {
      found.push({ start: open, end: gt + 1, attrs: text.slice(open + name.length + 1, gt - 1), inner: "" });
      pos = gt + 1;
      continue;
    }
    const close = lower.indexOf(closeTag, gt + 1);
    if (close === -1) break;
    found.push({ start: open, end: close + closeTag.length, attrs: text.slice(open + name.length + 1, gt), inner: text.slice(gt + 1, close) });
    pos = close + closeTag.length;
  }
  return found;
}

function removeBlocks(text: string, tag: string): string {
  let out = "";
  let pos = 0;
  for (const block of findBlocks(text, tag)) {
    out += text.slice(pos, block.start);
    pos = block.end;
  }
  return out + text.slice(pos);
}

function xmlBlocks(content: string, tag: string): string[] {
  return findBlocks(content, tag).map((block) => block.inner);
}

function xmlTag(block: string, tag: string): string {
  const match = new RegExp(`<${tag}\\b[^>]*>([^<]*)</${tag}>`, "i").exec(block);
  return match?.[1]?.trim() ?? "";
}

export function parsePom(content: string): ParseResult {
  const parsed = result("pom.xml");
  const withoutPlugins = removeBlocks(removeBlocks(stripComments(content), "plugins"), "plugin");
  const dependencySections = xmlBlocks(withoutPlugins, "dependencies");
  for (const section of dependencySections) {
    for (const block of xmlBlocks(section, "dependency")) {
      const group = xmlTag(block, "groupId");
      const artifact = xmlTag(block, "artifactId");
      const version = xmlTag(block, "version");
      const scope = xmlTag(block, "scope");
      const name = group && artifact ? `${group}:${artifact}` : artifact || group;
      if (!name) continue;
      if (scope === "import" || xmlTag(block, "type") === "pom") {
        skip(parsed, name, version || scope, "Maven import or pom packaging was not expanded.");
        continue;
      }
      if (!version || version.includes("${")) {
        skip(parsed, name, version || "(none)", "Maven property or missing version, not a pinned version.");
        continue;
      }
      add(parsed, "maven", name, version, scope === "test");
    }
  }
  const java = /<maven\.compiler\.(?:source|release)>([^<]+)</i.exec(content) || /<java\.version>([^<]+)</i.exec(content);
  if (java) parsed.runtimes.push({ product: "java", declared: java[1].trim().slice(0, 30) });
  if (!parsed.dependencies.length && !parsed.unresolved.length) parsed.notes.push("pom.xml had no pinned dependencies to read.");
  return parsed;
}

export function parseCsproj(content: string, includeDev: boolean): ParseResult {
  const parsed = result(".csproj");
  const text = stripComments(content);
  for (const block of findBlocks(text, "PackageReference")) {
    const attrs = block.attrs;
    const inner = block.inner;
    const include = /Include\s*=\s*"([^"]+)"/i.exec(attrs)?.[1] ?? "";
    const version = /Version\s*=\s*"([^"]+)"/i.exec(attrs)?.[1] || xmlTag(inner, "Version");
    if (!include) continue;
    const dev = /PrivateAssets\s*=\s*"all"/i.test(attrs + inner);
    if (dev && !includeDev) continue;
    if (!version) {
      skip(parsed, include, "(none)", "PackageReference has no version.");
      continue;
    }
    add(parsed, "nuget", include, version, dev);
  }
  if (!parsed.dependencies.length && !parsed.unresolved.length) parsed.notes.push(".csproj had no package references to read.");
  return parsed;
}

export function parsePackagesLock(content: string): ParseResult {
  const parsed = result("packages.lock.json");
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    parsed.notes.push("packages.lock.json could not be read. Nothing was inferred.");
    return parsed;
  }
  const root = json && typeof json === "object" ? json as { dependencies?: unknown } : {};
  const frameworks = root.dependencies && typeof root.dependencies === "object" ? root.dependencies as Record<string, unknown> : {};
  for (const framework of Object.values(frameworks)) {
    if (!framework || typeof framework !== "object") continue;
    for (const [name, meta] of Object.entries(framework as Record<string, unknown>)) {
      if (name === "__proto__" || name === "constructor" || name === "prototype") continue;
      const row = meta && typeof meta === "object" ? meta as { resolved?: unknown; type?: unknown } : {};
      const version = typeof row.resolved === "string" ? row.resolved : "";
      if (!version) {
        skip(parsed, name, "", "No resolved NuGet version.");
        continue;
      }
      add(parsed, "nuget", name, version);
    }
  }
  return parsed;
}

function yarnNames(header: string): string[] {
  const body = header.trim().replace(/:$/, "");
  const parts = body.split(",").map((part) => part.trim().replace(/^"|"$/g, ""));
  const names: string[] = [];
  for (const part of parts) {
    const match = /^(@[^/\s]+\/[^@\s]+|[^@\s]+)@/.exec(part);
    if (match) names.push(match[1]);
  }
  return names;
}

export function parseYarnLock(content: string): ParseResult {
  const parsed = result("yarn.lock");
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let names: string[] = [];
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      names = yarnNames(line);
      continue;
    }
    const classic = /^\s+version\s+"([^"]+)"/.exec(line);
    const berry = /^\s+version:\s+"?([^"\s]+)"?/.exec(line);
    const version = classic?.[1] || berry?.[1] || "";
    if (!version || !names.length) continue;
    for (const name of names) add(parsed, "npm", name, version);
    names = [];
  }
  if (!parsed.dependencies.length) parsed.notes.push("yarn.lock had no packages to read.");
  return parsed;
}

function pnpmPackageKey(line: string): { name: string; version: string } | null {
  const match = /^ {2}(?:\/)?((?:@[^/\s]+\/)?[^@\s]+)@(\d[^(:\s]*)/.exec(line);
  if (!match) return null;
  return { name: match[1], version: match[2] };
}

function pnpmDevNames(lines: string[]): Set<string> {
  const names = new Set<string>();
  let capture = false;
  let indent = 0;
  for (const line of lines) {
    const heading = /^(\s*)devDependencies:\s*$/.exec(line);
    if (heading) {
      capture = true;
      indent = heading[1].length;
      continue;
    }
    if (!capture) continue;
    const current = /^(\s*)/.exec(line)?.[1].length ?? 0;
    if (line.trim() && current <= indent) {
      capture = false;
      continue;
    }
    const dev = /^\s+['"]?((?:@[^/\s'"]+\/)?[^:'"\s]+)['"]?:/.exec(line);
    if (dev && !dev[1].includes(" ")) names.add(dev[1]);
  }
  return names;
}

export function parsePnpmLock(content: string, includeDev: boolean): ParseResult {
  const parsed = result("pnpm-lock.yaml");
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const devNames = includeDev ? new Set<string>() : pnpmDevNames(lines);
  let inPackages = false;
  for (const line of lines) {
    if (!/^\s/.test(line) && line.trim().endsWith(":")) {
      inPackages = line.trim() === "packages:";
      continue;
    }
    if (!inPackages) continue;
    const key = pnpmPackageKey(line);
    if (!key) continue;
    if (devNames.has(key.name)) continue;
    add(parsed, "npm", key.name, key.version);
  }
  if (!parsed.dependencies.length) parsed.notes.push("pnpm-lock.yaml had no packages to read.");
  return parsed;
}

export function parseGemfileLock(content: string): ParseResult {
  const parsed = result("Gemfile.lock");
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let inSpecs = false;
  for (const line of lines) {
    if (!/^\s/.test(line) && line.trim()) {
      inSpecs = false;
    }
    if (/^\s{2}specs:\s*$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (!inSpecs) continue;
    const match = /^\s{4}([A-Za-z0-9][A-Za-z0-9_-]*) \(([^)]+)\)/.exec(line);
    if (!match) continue;
    const version = match[2].split(",")[0].trim().replace(/^[^\d]*/, "");
    if (!version) {
      skip(parsed, match[1], match[2], "Could not read the gem version.");
      continue;
    }
    add(parsed, "rubygems", match[1], version);
  }
  if (!parsed.dependencies.length) parsed.notes.push("Gemfile.lock had no gems to read.");
  return parsed;
}

export function parseComposerLock(content: string, includeDev: boolean): ParseResult {
  const parsed = result("composer.lock");
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    parsed.notes.push("composer.lock could not be read. Nothing was inferred.");
    return parsed;
  }
  const root = json && typeof json === "object" ? json as { packages?: unknown; "packages-dev"?: unknown } : {};
  const groups: { rows: unknown; dev: boolean }[] = [{ rows: root.packages, dev: false }];
  if (includeDev) groups.push({ rows: root["packages-dev"], dev: true });
  for (const group of groups) {
    if (!Array.isArray(group.rows)) continue;
    for (const entry of group.rows) {
      const row = entry && typeof entry === "object" ? entry as { name?: unknown; version?: unknown; version_normalized?: unknown } : {};
      const name = typeof row.name === "string" ? row.name : "";
      const normalized = typeof row.version_normalized === "string" ? row.version_normalized : "";
      const parts = normalized.split(".").filter(Boolean);
      const version = parts.length >= 3 && parts.slice(3).every((part) => part === "0")
        ? parts.slice(0, 3).join(".")
        : typeof row.version === "string" ? row.version.replace(/^v/i, "") : "";
      if (!name || !version) {
        if (name) skip(parsed, name, "", "No pinned Composer version.");
        continue;
      }
      add(parsed, "composer", name, version, group.dev);
    }
  }
  return parsed;
}
