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
  const changelog = await githubGet(`https://api.github.com/repos/${repo.owner}/${repo.repo}/contents/CHANGELOG.md`);
  failed = failed || changelog.failed;
  if (changelog.ok && changelog.html) links.push(changelog.html);
  const notes = links.length || !failed ? [] : ["Release-notes links were omitted because the check did not succeed."];
  if (!links.length && !failed) notes.push("No release-notes link was verified for this version.");
  return { links, notes };
}
