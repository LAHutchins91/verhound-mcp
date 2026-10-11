export interface Parts {
  nums: number[];
  pre: string[];
}

export function parseVersion(input: string): Parts | null {
  const raw = input.trim().replace(/^v/i, "");
  if (!raw || raw.includes(" ") || raw.includes("/")) return null;
  const [main, pre = ""] = raw.split("-", 2);
  if (!/^\d+(\.\d+){0,5}$/.test(main)) return null;
  const nums = main.split(".").map((part) => Number(part));
  const preParts = pre ? pre.split(".").filter(Boolean) : [];
  return { nums, pre: preParts };
}

function cmpIdent(a: string, b: string): number {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) return Number(a) - Number(b);
  if (aNum && !bNum) return -1;
  if (!aNum && bNum) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function cmpVersion(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return a === b ? 0 : a < b ? -1 : 1;
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;
  const preLen = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < preLen; i += 1) {
    if (pa.pre[i] === undefined) return -1;
    if (pb.pre[i] === undefined) return 1;
    const diff = cmpIdent(pa.pre[i], pb.pre[i]);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function jump(from: string, to: string): "major" | "minor" | "patch" | "none" {
  if (cmpVersion(from, to) === 0) return "none";
  const a = parseVersion(from);
  const b = parseVersion(to);
  if (!a || !b) return "major";
  if ((a.nums[0] ?? 0) !== (b.nums[0] ?? 0)) return "major";
  if ((a.nums[1] ?? 0) !== (b.nums[1] ?? 0)) return "minor";
  return "patch";
}

export function versionsBehind(from: string, latest: string): { major: number; minor: number; patch: number } | undefined {
  if (cmpVersion(from, latest) >= 0) return undefined;
  const a = parseVersion(from);
  const b = parseVersion(latest);
  if (!a || !b) return undefined;
  const major = Math.max(0, (b.nums[0] ?? 0) - (a.nums[0] ?? 0));
  if (major > 0) return { major, minor: 0, patch: 0 };
  const minor = Math.max(0, (b.nums[1] ?? 0) - (a.nums[1] ?? 0));
  if (minor > 0) return { major: 0, minor, patch: 0 };
  return { major: 0, minor: 0, patch: Math.max(0, (b.nums[2] ?? 0) - (a.nums[2] ?? 0)) };
}

function satisfiesOne(version: string, token: string): boolean {
  const trimmed = token.trim();
  if (!trimmed || trimmed === "*" || trimmed === "x" || trimmed === "X") return true;
  const match = /^(>=|<=|>|<|=|\^|~)?v?(\d[\w.+-]*)$/.exec(trimmed);
  if (!match) return false;
  const op = match[1] ?? "=";
  const target = match[2];
  const cmp = cmpVersion(version, target);
  if (op === "=") return cmp === 0;
  if (op === ">") return cmp > 0;
  if (op === ">=") return cmp >= 0;
  if (op === "<") return cmp < 0;
  if (op === "<=") return cmp <= 0;
  const parsed = parseVersion(target);
  const current = parseVersion(version);
  if (!parsed || !current) return false;
  if (cmp < 0) return false;
  if (op === "~") {
    const upper = [parsed.nums[0] ?? 0, (parsed.nums[1] ?? 0) + 1, 0];
    return cmpVersion(version, upper.join(".")) < 0;
  }
  const major = parsed.nums[0] ?? 0;
  const minor = parsed.nums[1] ?? 0;
  let upper: string;
  if (major > 0) upper = `${major + 1}.0.0`;
  else if (minor > 0) upper = `0.${minor + 1}.0`;
  else upper = `0.0.${(parsed.nums[2] ?? 0) + 1}`;
  return cmpVersion(version, upper) < 0;
}

export function satisfies(version: string, range: string): boolean {
  const orParts = range.split("||").map((part) => part.trim()).filter(Boolean);
  if (!orParts.length) return false;
  return orParts.some((part) => {
    const tokens = part.split(/\s+/).filter(Boolean);
    return tokens.length > 0 && tokens.every((token) => satisfiesOne(version, token));
  });
}

export function isExactSpec(spec: string): string | null {
  const match = /^(?:==|===|=|v)?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$/.exec(spec.trim());
  return match ? match[1] : null;
}

export function isPrerelease(version: string): boolean {
  const parsed = parseVersion(version);
  return Boolean(parsed && parsed.pre.length > 0);
}
