import crypto from "node:crypto";

/** Advisory and registry text is returned as data. It is truncated and stripped of control characters. */
export function asDataText(value: unknown, max = 200): string {
  if (typeof value !== "string") return "";
  let cleaned = "";
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    cleaned += code <= 31 || code === 127 ? " " : char;
  }
  cleaned = cleaned.replace(/\s+/g, " ").trim();
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned;
}

export function contentHash(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function uniqueNotes(notes: string[]): string[] {
  const out: string[] = [];
  for (const note of notes) {
    const text = note.trim();
    if (text && !out.includes(text)) out.push(text);
  }
  return out;
}
