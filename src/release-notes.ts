import { TTL } from "./config.js";
import { githubHeaders } from "./upstream/github.js";
import { cachedJson } from "./upstream/http.js";

export interface ReleaseNoteCheck {
  links: string[];
  notes: string[];
}

function githubRepo(repoUrl: string | undefined): { owner: string; repo: string } | null {
  if (!repoUrl) return null;
  try {
    const url = new URL(repoUrl);
    if (url.hostname !== "github.com") return null;
    const [owner, repo] = url.pathname.split("/").filter(Boolean);
    if (!owner || !repo || owner === "." || repo === "..") return null;
    return { owner, repo: repo.replace(/\.git$/, "") };
  } catch {
    return null;
  }
}

async function githubGet(url: string): Promise<{ ok: boolean; html?: string; failed: boolean }> {
  try {
    const response = await cachedJson({
      source: "github",
      url,
      ttlSeconds: TTL.depsdev,
      accept: "application/vnd.github+json",
      extraHeaders: githubHeaders()
    });
    if (response.negative || response.status >= 300) return { ok: false, failed: false };
    const body = response.json as { html_url?: string } | null;
    const html = typeof body?.html_url === "string" && body.html_url.startsWith("https://github.com/") ? body.html_url : undefined;
    return { ok: true, html, failed: false };
  } catch {
    return { ok: false, failed: true };
  }
}

const CHANGELOG_NAMES = new Set(["changelog.md", "changelog", "changes.md", "history.md", "changelog.rst", "changes.rst"]);

async function githubChangelog(repo: { owner: string; repo: string }): Promise<{ html?: string; failed: boolean }> {
  try {
    const response = await cachedJson({
      source: "github",
      url: `https://api.github.com/repos/${repo.owner}/${repo.repo}/contents`,
      ttlSeconds: TTL.depsdev,
      accept: "application/vnd.github+json",
      extraHeaders: githubHeaders()
    });
    if (response.negative || !Array.isArray(response.json)) return { failed: false };
    for (const entry of response.json as { name?: unknown; type?: unknown; html_url?: unknown }[]) {
      if (entry?.type !== "file" || typeof entry.name !== "string" || typeof entry.html_url !== "string") continue;
      if (!CHANGELOG_NAMES.has(entry.name.toLowerCase())) continue;
      if (!entry.html_url.toLowerCase().startsWith(`https://github.com/${repo.owner}/${repo.repo}/`.toLowerCase())) continue;
      return { html: entry.html_url, failed: false };
    }
    return { failed: false };
  } catch {
    return { failed: true };
  }
}

/**
 * Release-notes links are returned only when a GitHub API check succeeds.
 * A missing check omits the link. Nothing is filled in from the repository URL alone.
 */
export async function verifiedReleaseNotes(repoUrl: string | undefined, version: string): Promise<ReleaseNoteCheck> {
  const repo = githubRepo(repoUrl);
  if (!repo) return { links: [], notes: [] };
  const tags = version.startsWith("v") ? [version, version.slice(1)] : [`v${version}`, version];
  const links: string[] = [];
  let failed = false;
  for (const tag of [...new Set(tags)]) {
    const checked = await githubGet(`https://api.github.com/repos/${repo.owner}/${repo.repo}/releases/tags/${encodeURIComponent(tag)}`);
    failed = failed || checked.failed;
    if (!checked.ok) continue;
    links.push(checked.html ?? `https://github.com/${repo.owner}/${repo.repo}/releases/tag/${encodeURIComponent(tag)}`);
    break;
  }
  // The root listing names the changelog without downloading it. Fetching contents/CHANGELOG.md
  // would pull and cache the whole file (base64), which can be up to 1 MB.
  const changelog = await githubChangelog(repo);
  failed = failed || changelog.failed;
  if (changelog.html) links.push(changelog.html);
  const notes = links.length || !failed ? [] : ["Release-notes links were omitted because the check did not succeed."];
  if (!links.length && !failed) notes.push("No release-notes link was verified for this version.");
  return { links, notes };
}
