import { nowDate } from "./clock.js";
import type { SourceCitation } from "./sources.js";
import { uniqueNotes } from "./text.js";

export interface Envelope<T> {
  data: T;
  sources: SourceCitation[];
  checked_at: string;
  cache_age_seconds: number;
  notes: string[];
  stale: boolean;
}

export function envelope<T>(data: T, sources: SourceCitation[], notes: string[], cacheAgeSeconds: number, stale: boolean): Envelope<T> {
  const sourceMap = new Map(sources.map((source) => [source.id, source]));
  return {
    data,
    sources: [...sourceMap.values()],
    checked_at: nowDate().toISOString(),
    cache_age_seconds: Math.max(0, Math.floor(cacheAgeSeconds)),
    notes: uniqueNotes(notes),
    stale
  };
}

export function toolResult<T>(value: Envelope<T>, isError = false) {
  const text = JSON.stringify(value);
  return {
    structuredContent: value as Envelope<T> & Record<string, unknown>,
    content: [{ type: "text" as const, text }],
    ...(isError ? { isError: true as const } : {})
  };
}

export function toolError(message: string) {
  return toolResult(envelope({ error: message }, [], [message], 0, false), true);
}
