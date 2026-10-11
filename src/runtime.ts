import { envelope, type Envelope } from "./envelope.js";
import { SOURCE } from "./sources.js";
import { eolSlug, product } from "./upstream/eol.js";
import { UpstreamError } from "./upstream/http.js";

export interface EolRelease {
  name: string;
  label: string;
  release_date: string | null;
  is_lts: boolean;
  lts_from: string | null;
  eoas_from: string | null;
  eol_from: string | null;
  is_eol: boolean;
  is_maintained: boolean;
  latest: { name: string | null; date: string | null; link: string | null };
}

export interface EolData {
  product: string;
  release?: EolRelease;
  all_releases?: EolRelease[];
  source_link: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function mapRelease(value: unknown): EolRelease | null {
  const row = asRecord(value);
  if (!row || typeof row.name !== "string") return null;
  const latest = asRecord(row.latest);
  return {
    name: row.name,
    label: typeof row.label === "string" ? row.label : row.name,
    release_date: typeof row.releaseDate === "string" ? row.releaseDate : null,
    is_lts: row.isLts === true,
    lts_from: typeof row.ltsFrom === "string" ? row.ltsFrom : null,
    eoas_from: typeof row.eoasFrom === "string" ? row.eoasFrom : null,
    eol_from: typeof row.eolFrom === "string" ? row.eolFrom : null,
    is_eol: row.isEol === true,
    is_maintained: row.isMaintained === true,
    latest: {
      name: typeof latest?.name === "string" ? latest.name : null,
      date: typeof latest?.date === "string" ? latest.date : null,
      link: typeof latest?.link === "string" ? latest.link : null
    }
  };
}

export async function runtimeEol(productName: string, version?: string): Promise<Envelope<EolData | { error: string }>> {
  const slug = eolSlug(productName);
  if (!slug) {
    return envelope({ error: "That product name is not a usable endoflife.date slug. No date was invented." }, [], ["That product name is not a usable endoflife.date slug. No date was invented."], 0, false);
  }
  try {
    const response = await product(slug);
    const body = asRecord(response.json);
    const result = asRecord(body?.result);
    const releases = Array.isArray(result?.releases) ? result.releases.map(mapRelease).filter((item): item is EolRelease => Boolean(item)) : [];
    const notes = ["Dates are as published by endoflife.date and may change."];
    if (response.note) notes.push(response.note);
    const link = `https://endoflife.date/${slug}`;
    if (version) {
      const wanted = version.trim().replace(/^v/i, "");
      const match = releases.find((release) => release.name === wanted || release.latest.name === wanted || wanted.startsWith(`${release.name}.`));
      if (!match) {
        notes.push(`No ${slug} release named ${wanted} was in the endoflife.date response. No date was invented.`);
        return envelope({ product: slug, source_link: link }, [SOURCE.eol], notes, response.cacheAgeSeconds, response.stale);
      }
      return envelope({ product: slug, release: match, source_link: link }, [SOURCE.eol], notes, response.cacheAgeSeconds, response.stale);
    }
    return envelope({
      product: slug,
      all_releases: releases.slice(0, 15),
      source_link: link
    }, [SOURCE.eol], notes, response.cacheAgeSeconds, response.stale);
  } catch (error) {
    const message = error instanceof UpstreamError ? error.message : "endoflife.date did not respond; no end-of-life date is shown instead of a guess.";
    return envelope({ error: message }, [], [message], 0, false);
  }
}
