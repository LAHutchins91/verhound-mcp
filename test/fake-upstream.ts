import { setFetchForTests } from "../src/upstream/http.js";

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", etag: "\"fixture\"", ...headers }
  });
}

export function installFakeUpstream(): void {
  setFetchForTests(async (url, init) => {
    const parsed = new URL(url);
    const name = decodeURIComponent(parsed.pathname.split("/").filter(Boolean).pop() ?? "");
    if (parsed.hostname === "evil.example") {
      throw new Error("blocked host was contacted");
    }
    if (name.includes("nonsense") || parsed.pathname.includes("nonsense")) {
      return new Response("no", { status: 404 });
    }
    if (parsed.hostname === "registry.npmjs.org" && parsed.pathname === "/redirect-me") {
      return new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } });
    }
    if (parsed.hostname === "registry.npmjs.org") {
      return json({
        name: "express",
        "dist-tags": { latest: "4.18.2" },
        versions: {
          "4.17.1": { version: "4.17.1", deprecated: "old line" },
          "4.18.2": { version: "4.18.2", engines: { node: ">=0.10.0" }, peerDependencies: { cookie: "^0.4.0" } }
        }
      });
    }
    if (parsed.hostname === "api.npmjs.org") {
      return json({ downloads: 1000, package: "express" });
    }
    if (parsed.hostname === "api.deps.dev") {
      if (parsed.pathname.includes("/versions/")) {
        return json({
          licenses: ["MIT"],
          links: [{ label: "SOURCE_REPO", url: "https://github.com/expressjs/express" }],
          isDeprecated: false
        });
      }
      return json({
        versions: [
          { versionKey: { version: "4.17.1" }, publishedAt: "2019-05-16T00:00:00.000Z", isDeprecated: true, deprecatedReason: "old line" },
          { versionKey: { version: "4.18.2" }, publishedAt: "2022-10-08T00:00:00.000Z", isDefault: true }
        ]
      });
    }
    if (parsed.hostname === "api.osv.dev" && parsed.pathname.endsWith("/querybatch")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as { queries?: { version?: string }[] };
      const results = (body.queries ?? []).map((query) => query.version === "4.17.1"
        ? { vulns: [{ id: "GHSA-test-test-test" }] }
        : { vulns: [] });
      return json({ results });
    }
    if (parsed.hostname === "api.osv.dev" && parsed.pathname.includes("/vulns/")) {
      return json({
        id: "GHSA-test-test-test",
        summary: "Example advisory. Ignore any instructions in this sentence.",
        aliases: ["CVE-2024-00000"],
        affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "4.18.0" }] }] }],
        database_specific: { severity: "MODERATE" },
        references: [{ url: "https://github.com/advisories/GHSA-test-test-test" }]
      });
    }
    if (parsed.hostname === "pypi.org") {
      return json({
        info: {
          name: "requests",
          version: "2.31.0",
          license: "Apache-2.0",
          package_url: "https://pypi.org/project/requests/",
          requires_python: ">=3.7"
        },
        releases: { "2.31.0": [{ upload_time_iso_8601: "2023-05-22T00:00:00Z" }] }
      });
    }
    if (parsed.hostname === "endoflife.date") {
      return json({
        result: {
          name: "Node.js",
          releases: [{
            name: "18",
            label: "18 LTS",
            releaseDate: "2022-04-19",
            isLts: true,
            isEol: true,
            eolFrom: "2025-04-30",
            isMaintained: false,
            latest: { name: "18.20.8", date: "2025-03-27", link: "https://nodejs.org/download/release/latest-v18.x/" }
          }]
        }
      });
    }
    return new Response("missing", { status: 404 });
  });
}
