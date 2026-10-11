import fs from "node:fs";
import path from "node:path";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import crypto from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { setClockForTests } from "../src/clock.js";
import { app } from "../src/server.js";
import { resetOAuthStateForTests } from "../src/oauth-state.js";
import { resetStoreForTests } from "../src/store.js";
import { resetUpstreamForTests } from "../src/upstream/http.js";
import { resetAuthLimitsForTests } from "../src/auth.js";
import { installFakeUpstream } from "./fake-upstream.js";

let server: Server;
let base = "";

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

afterEach(() => {
  setClockForTests(null);
  resetStoreForTests();
  resetUpstreamForTests();
  resetOAuthStateForTests();
  resetAuthLimitsForTests();
  delete process.env.CRON_SECRET;
  delete process.env.OPENAI_APPS_CHALLENGE;
});

function cookiesOf(response: Response): string {
  const list = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
  return list.map((cookie) => cookie.split(";")[0]).join("; ");
}

describe("http surface", () => {
  it("freezes health keys and hides prices", async () => {
    const response = await fetch(`${base}/health`);
    const body = await response.json() as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "billingConfigured",
      "mailConfigured",
      "name",
      "ok",
      "service",
      "storageBackend",
      "upstreams",
      "version"
    ]);
    expect(Object.keys(body.upstreams as object).sort()).toEqual(["depsdev", "eol", "npm", "osv", "pypi"]);
    expect(body.billingConfigured).toBe(false);
    expect(JSON.stringify(body)).not.toContain("$");
  });

  it("shows approved prices only on the landing page and checkout", async () => {
    const landing = await (await fetch(`${base}/`)).text();
    const checkout = await (await fetch(`${base}/checkout`)).text();
    const privacy = await (await fetch(`${base}/privacy`)).text();
    for (const html of [landing, checkout]) {
      expect(html).toContain("$7.99/month");
      expect(html).toContain("$79.99/year");
      expect(html.toLowerCase()).toContain("card is required");
      expect(html.toLowerCase()).not.toContain("free forever");
    }
    expect(privacy).not.toContain("$");
    expect(privacy.toLowerCase()).not.toContain("stripe");
  });

  it("requires the cron secret", async () => {
    expect((await fetch(`${base}/api/cron/watch`)).status).toBe(503);
    process.env.CRON_SECRET = "cron-test-secret";
    expect((await fetch(`${base}/api/cron/watch`, { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    const ok = await fetch(`${base}/api/cron/watch`, { headers: { "x-cron-secret": "cron-test-secret" } });
    expect(ok.status).toBe(200);
    const body = await ok.json() as { ok: boolean; checked: number };
    expect(body.ok).toBe(true);
    expect(body.checked).toBe(0);
  });

  it("runs the OAuth code flow, rotates refresh tokens, and guards tools/call", async () => {
    installFakeUpstream();
    const registered = await fetch(`${base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/callback"], client_name: "test" })
    });
    expect(registered.status).toBe(201);
    const client = await registered.json() as { client_id: string };
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    const resource = `${base}/mcp`;
    const authorize = new URL(`${base}/authorize`);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", client.client_id);
    authorize.searchParams.set("redirect_uri", "http://127.0.0.1/callback");
    authorize.searchParams.set("code_challenge", challenge);
    authorize.searchParams.set("code_challenge_method", "S256");
    authorize.searchParams.set("state", "xyz");
    authorize.searchParams.set("resource", resource);
    const page = await fetch(authorize);
    expect(page.status).toBe(200);
    const html = await page.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
    const cookie = cookiesOf(page);
    const approved = await fetch(`${base}/authorize`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "xyz",
        resource,
        scope: "verhound",
        csrf,
        decision: "approve"
      })
    });
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get("location") ?? "");
    const code = location.searchParams.get("code") ?? "";
    expect(location.searchParams.get("state")).toBe("xyz");
    const tokenResponse = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: client.client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: verifier
      })
    });
    expect(tokenResponse.status).toBe(200);
    const token = await tokenResponse.json() as { access_token: string; refresh_token: string };
    const replay = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: client.client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: verifier
      })
    });
    expect(replay.status).toBe(400);
    const refreshed = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: token.refresh_token })
    });
    const first = await refreshed.json() as { access_token: string; refresh_token: string };
    const grace = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: token.refresh_token })
    });
    const second = await grace.json() as { access_token: string };
    expect(second.access_token).toBe(first.access_token);
    setClockForTests(Date.now() + 11_000);
    const expiredGrace = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: token.refresh_token })
    });
    expect(expiredGrace.status).toBe(400);

    const metadata = `${base}/.well-known/oauth-protected-resource/mcp`;
    const denied = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "check_packages", arguments: { packages: [] } } })
    });
    expect(denied.status).toBe(401);
    expect(denied.headers.get("www-authenticate")).toBe(`Bearer realm="Verhound by Ouroboros", resource_metadata="${metadata}"`);

    const listed = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })
    });
    const listedBody = await listed.json() as { result: { tools: { name: string; annotations: Record<string, boolean> }[] } };
    const tools = listedBody.result.tools;
    expect(tools.map((tool) => tool.name)).toEqual([
      "check_packages",
      "audit_manifest",
      "verify_package_exists",
      "plan_upgrade",
      "runtime_eol",
      "watch_manifest",
      "list_alerts",
      "unwatch_manifest"
    ]);
    for (const tool of tools) {
      expect(typeof tool.annotations.readOnlyHint).toBe("boolean");
      expect(typeof tool.annotations.destructiveHint).toBe("boolean");
      expect(typeof tool.annotations.idempotentHint).toBe("boolean");
      expect(typeof tool.annotations.openWorldHint).toBe("boolean");
    }
    const snapshot = path.resolve("test/fixtures/tools-list.json");
    if (process.env.UPDATE_TOOLS_SNAPSHOT === "1" || !fs.existsSync(snapshot)) {
      fs.mkdirSync(path.dirname(snapshot), { recursive: true });
      fs.writeFileSync(snapshot, `${JSON.stringify(tools, null, 2)}\n`);
    }
    expect(tools).toEqual(JSON.parse(fs.readFileSync(snapshot, "utf8")));

    const lines: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(args.map((arg) => String(arg)).join(" "));
    };
    const called = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${first.access_token}`
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "check_packages", arguments: { packages: [{ ecosystem: "npm", name: "express", version: "4.17.1" }] } }
      })
    });
    console.log = original;
    expect(called.status).toBe(200);
    const payload = await called.json() as { result?: { isError?: boolean; structuredContent?: { data?: { packages?: { advisories?: { id: string }[] }[] } } } };
    expect(payload.result?.isError).not.toBe(true);
    expect(JSON.stringify(payload)).toContain("GHSA-test-test-test");
    const timing = lines.map((line) => {
      try { return JSON.parse(line) as { event?: string; tool?: string }; } catch { return null; }
    }).filter((line) => line?.event === "tool_timing" || line?.event === "mcp_timing");
    expect(timing.length).toBeGreaterThan(0);
    for (const line of timing) {
      expect(JSON.stringify(line)).not.toContain("express");
      expect(JSON.stringify(line)).not.toContain("4.17.1");
    }
  });

  it("answers the apps challenge", async () => {
    expect(await (await fetch(`${base}/.well-known/openai-apps-challenge`)).text()).toBe("Verification is not configured.");
    process.env.OPENAI_APPS_CHALLENGE = "challenge-token";
    expect(await (await fetch(`${base}/.well-known/openai-apps-challenge`)).text()).toBe("challenge-token");
  });
});
