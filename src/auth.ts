import crypto from "node:crypto";
import type { Express, Request, Response } from "express";
import { z } from "zod";
import { PUBLIC_BRAND, SCOPE, publicBase, resourceUrl } from "./config.js";
import { escapeHtml, page } from "./html.js";
import { identityConfigured, sendEmailOtp, verifyEmailOtp } from "./identity.js";
import { consumeAuthorizationCode, rememberRefresh, reuseRefresh } from "./oauth-state.js";
import { configuredReviewerEmail, reviewerAccountId, reviewerCredentialsMatch, reviewerLoginConfigured } from "./reviewer.js";
import { getStore } from "./store.js";
import { signToken, verifyToken, type TokenPayload } from "./tokens.js";

const ACCESS_TTL = 60 * 60;
const REFRESH_TTL = 30 * 24 * 60 * 60;
const CODE_TTL = 5 * 60;
const CLIENT_TTL = 365 * 24 * 60 * 60;
const ACCOUNT_TTL = 90 * 24 * 60 * 60;
const CSRF_COOKIE = "verhound_csrf";
const ACCOUNT_COOKIE = "verhound_account";

function sha(value: string): string {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

export function redirectAllowed(uri: string): boolean {
  let url: URL;
  try { url = new URL(uri); } catch { return false; }
  if (url.protocol === "https:") return true;
  if (url.protocol === "http:") return url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol === "javascript:" || url.protocol === "data:" || url.protocol === "file:" || url.protocol === "vbscript:") return false;
  return /^[a-z][a-z0-9+.-]*:$/.test(url.protocol);
}

function cookieHeader(name: string, value: string, maxAge: number, secure: boolean): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function readCookie(req: Request, name: string): string | null {
  const header = req.header("cookie") ?? "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

export function bearerAccess(req: Request): { sub: string; aud: string } | null {
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  try {
    const payload = verifyToken<TokenPayload & { sub?: unknown; aud?: unknown }>(token, "access");
    if (typeof payload.sub !== "string" || typeof payload.aud !== "string") return null;
    if (payload.aud !== resourceUrl(publicBase(req))) return null;
    return { sub: payload.sub, aud: payload.aud };
  } catch {
    return null;
  }
}

export function accountIdFromRequest(req: Request): string | null {
  const access = bearerAccess(req);
  if (access) return access.sub;
  const raw = readCookie(req, ACCOUNT_COOKIE);
  if (!raw) return null;
  try {
    const payload = verifyToken<TokenPayload & { sub?: unknown }>(raw, "account");
    return typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    return null;
  }
}

function clientRecord(clientId: string): { redirect_uris: string[]; client_name: string } | null {
  try {
    const payload = verifyToken<TokenPayload & { redirect_uris?: unknown; client_name?: unknown }>(clientId, "client");
    if (!Array.isArray(payload.redirect_uris) || typeof payload.client_name !== "string") return null;
    const redirectUris = payload.redirect_uris.filter((item): item is string => typeof item === "string");
    if (!redirectUris.length) return null;
    return { redirect_uris: redirectUris, client_name: payload.client_name };
  } catch {
    return null;
  }
}

function oauthError(res: Response, status: number, error: string, description: string): void {
  res.status(status).json({ error, error_description: description });
}

function metadata(base: string) {
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [SCOPE]
  };
}

function protectedResource(base: string) {
  return {
    resource: resourceUrl(base),
    resource_name: PUBLIC_BRAND,
    authorization_servers: [base],
    scopes_supported: [SCOPE],
    bearer_methods_supported: ["header"]
  };
}

function cors(_req: Request, res: Response): void {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "600"
  });
}

const hits = new Map<string, { count: number; end: number }>();

export function resetAuthLimitsForTests(): void {
  hits.clear();
}

function allow(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  for (const [name, value] of hits) if (value.end <= now) hits.delete(name);
  const current = hits.get(key);
  if (current) {
    current.count += 1;
    return current.count <= limit;
  }
  if (hits.size >= 10000) return false;
  hits.set(key, { count: 1, end: now + windowMs });
  return true;
}

const registerBody = z.object({
  redirect_uris: z.array(z.string().min(1).max(500)).min(1).max(10),
  client_name: z.string().trim().min(1).max(120).optional(),
  token_endpoint_auth_method: z.string().optional(),
  grant_types: z.array(z.string()).max(5).optional(),
  response_types: z.array(z.string()).max(5).optional()
});

function issueTokens(sub: string, aud: string) {
  const accessToken = signToken({ typ: "access", sub, aud }, ACCESS_TTL);
  const refreshToken = signToken({ typ: "refresh", sub, aud, jti: crypto.randomUUID() }, REFRESH_TTL);
  return {
    access_token: accessToken,
    token_type: "Bearer" as const,
    expires_in: ACCESS_TTL,
    refresh_token: refreshToken,
    scope: SCOPE
  };
}

function consentPage(base: string, fields: Record<string, string>, clientName: string, csrf: string, error = ""): string {
  const hidden = Object.entries({ ...fields, csrf }).map(([key, value]) =>
    `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`).join("");
  const reviewer = reviewerLoginConfigured() ? `<section class="card" style="margin-top:14px">
      <h2>Reviewer sign-in</h2>
      <p>Reviewers sign in on this page. The review account does not expire.</p>
      <form method="post" action="/authorize">${hidden}
        <label>Email <input name="reviewer_email" type="email" autocomplete="username" maxlength="254" required></label>
        <label>Password <input name="reviewer_password" type="password" autocomplete="current-password" maxlength="128" required></label>
        <button class="btn secondary" name="decision" value="reviewer">Reviewer sign-in</button>
      </form>
    </section>` : "";
  const email = identityConfigured() ? `<section class="card" style="margin-top:14px">
      <h2>Email code</h2>
      <p>Optional. A verified email is used for advisory alerts. Plan details are on the checkout page. This form does not collect a card.</p>
      <form method="post" action="/authorize">${hidden}
        <label>Email <input name="email" type="email" maxlength="254"></label>
        <label>Code <input name="otp" inputmode="numeric" maxlength="12" autocomplete="one-time-code"></label>
        <button class="btn secondary" name="decision" value="email">Email code</button>
      </form>
    </section>` : "";
  const banner = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  const body = `<p class="eyebrow">Connect an assistant</p>
    <h1>Allow ${escapeHtml(clientName)} to use ${escapeHtml(PUBLIC_BRAND)}?</h1>
    <p class="lede">This connection can look up package versions, known advisories, and runtime end-of-life dates. It can also see whether this browser session is on a trial or Pro.</p>
    ${banner}
    <section class="card">
      <p>Return address: ${escapeHtml(fields.redirect_uri)}</p>
      <p>Requested scope: ${escapeHtml(SCOPE)}</p>
      <form method="post" action="/authorize">${hidden}
        <div class="actions">
          <button class="btn primary" name="decision" value="approve">Continue</button>
          <button class="btn secondary" name="decision" value="deny">Cancel</button>
        </div>
      </form>
    </section>
    ${email}
    ${reviewer}`;
  return page(PUBLIC_BRAND, body, `${base}/logo.jpg`);
}

function redirectError(redirectUri: string, error: string, state: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

async function finishCode(res: Response, base: string, fields: Record<string, string>, sub: string, email: string | null, plan?: "pro"): Promise<void> {
  await getStore().ensureAccount(sub, email, plan);
  const secure = base.startsWith("https://");
  const code = signToken({
    typ: "code",
    sub,
    aud: fields.resource,
    client_hash: sha(fields.client_id),
    redirect_uri: fields.redirect_uri,
    code_challenge: fields.code_challenge,
    jti: crypto.randomUUID()
  }, CODE_TTL);
  const account = signToken({ typ: "account", sub }, ACCOUNT_TTL);
  res.append("Set-Cookie", cookieHeader(ACCOUNT_COOKIE, account, ACCOUNT_TTL, secure));
  res.append("Set-Cookie", cookieHeader(CSRF_COOKIE, "", 0, secure));
  const target = new URL(fields.redirect_uri);
  target.searchParams.set("code", code);
  if (fields.state) target.searchParams.set("state", fields.state);
  res.redirect(target.toString());
}

export function installOAuth(app: Express): void {
  const open = (req: Request, res: Response, next: () => void) => {
    cors(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  };

  app.options(["/register", "/token", "/authorize", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], (req, res) => {
    cors(req, res);
    res.status(204).end();
  });

  app.get(["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"], open, (req, res) => {
    res.json(metadata(publicBase(req)));
  });
  app.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], open, (req, res) => {
    res.json(protectedResource(publicBase(req)));
  });

  app.post("/register", open, (req, res) => {
    if (!allow(`register:${req.ip}`, 30, 10 * 60 * 1000)) return res.status(429).json({ error: "Too many registration requests." });
    const parsed = registerBody.safeParse(req.body);
    if (!parsed.success) return oauthError(res, 400, "invalid_client_metadata", "redirect_uris are required.");
    if (parsed.data.token_endpoint_auth_method && parsed.data.token_endpoint_auth_method !== "none") {
      return oauthError(res, 400, "invalid_client_metadata", "Only token_endpoint_auth_method none is supported.");
    }
    const grants = parsed.data.grant_types ?? ["authorization_code", "refresh_token"];
    if (grants.some((grant) => grant !== "authorization_code" && grant !== "refresh_token")) {
      return oauthError(res, 400, "invalid_client_metadata", "Supported grants are authorization_code and refresh_token.");
    }
    if (parsed.data.redirect_uris.some((uri) => !redirectAllowed(uri))) {
      return oauthError(res, 400, "invalid_redirect_uri", "Use an https redirect or a loopback http redirect.");
    }
    const clientName = parsed.data.client_name ?? "MCP client";
    const clientId = signToken({ typ: "client", redirect_uris: parsed.data.redirect_uris, client_name: clientName }, CLIENT_TTL);
    res.status(201).json({
      client_id: clientId,
      client_name: clientName,
      redirect_uris: parsed.data.redirect_uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    });
  });

  app.get("/authorize", (req, res) => {
    const base = publicBase(req);
    const fields = {
      response_type: String(req.query.response_type ?? ""),
      client_id: String(req.query.client_id ?? ""),
      redirect_uri: String(req.query.redirect_uri ?? ""),
      code_challenge: String(req.query.code_challenge ?? ""),
      code_challenge_method: String(req.query.code_challenge_method ?? ""),
      state: String(req.query.state ?? ""),
      resource: String(req.query.resource ?? resourceUrl(base)),
      scope: String(req.query.scope ?? SCOPE)
    };
    const client = clientRecord(fields.client_id);
    if (!client || !client.redirect_uris.includes(fields.redirect_uri) || !redirectAllowed(fields.redirect_uri)) {
      return res.status(400).type("html").send(page(PUBLIC_BRAND, "<h1>This connection request is not valid.</h1>", `${base}/logo.jpg`));
    }
    if (fields.response_type !== "code" || fields.code_challenge_method !== "S256" || fields.code_challenge.length < 43) {
      return res.redirect(redirectError(fields.redirect_uri, "invalid_request", fields.state));
    }
    if (fields.resource !== resourceUrl(base)) {
      return res.redirect(redirectError(fields.redirect_uri, "invalid_target", fields.state));
    }
    const csrf = crypto.randomBytes(24).toString("base64url");
    res.setHeader("Set-Cookie", cookieHeader(CSRF_COOKIE, csrf, 30 * 60, base.startsWith("https://")));
    res.set("Cache-Control", "no-store");
    res.type("html").send(consentPage(base, fields, client.client_name, csrf));
  });

  app.post("/authorize", async (req, res) => {
    const base = publicBase(req);
    const body = req.body ?? {};
    const fields = {
      response_type: String(body.response_type ?? ""),
      client_id: String(body.client_id ?? ""),
      redirect_uri: String(body.redirect_uri ?? ""),
      code_challenge: String(body.code_challenge ?? ""),
      code_challenge_method: String(body.code_challenge_method ?? ""),
      state: String(body.state ?? ""),
      resource: String(body.resource ?? ""),
      scope: String(body.scope ?? SCOPE)
    };
    const csrf = String(body.csrf ?? "");
    const decision = String(body.decision ?? "");
    const client = clientRecord(fields.client_id);
    if (!client || !client.redirect_uris.includes(fields.redirect_uri) || !redirectAllowed(fields.redirect_uri)) {
      return res.status(400).type("html").send(page(PUBLIC_BRAND, "<h1>This connection request is not valid.</h1>", `${base}/logo.jpg`));
    }
    if (!csrf || csrf !== readCookie(req, CSRF_COOKIE)) {
      return res.status(400).type("html").send(page(PUBLIC_BRAND, "<h1>The connection form expired.</h1><p>Start the connection again.</p>", `${base}/logo.jpg`));
    }
    if (fields.resource !== resourceUrl(base) || fields.code_challenge_method !== "S256" || fields.code_challenge.length < 43 || fields.code_challenge.length > 128) {
      return res.redirect(redirectError(fields.redirect_uri, "invalid_request", fields.state));
    }
    const secure = base.startsWith("https://");
    if (decision === "deny") return res.redirect(redirectError(fields.redirect_uri, "access_denied", fields.state));
    if (decision === "reviewer") {
      if (!allow(`reviewer:${req.ip}`, 8, 10 * 60 * 1000)) {
        return res.status(429).type("html").send(page(PUBLIC_BRAND, "<h1>Too many reviewer sign-in attempts.</h1>", `${base}/logo.jpg`));
      }
      const email = String(body.reviewer_email ?? "").slice(0, 254);
      const password = String(body.reviewer_password ?? "").slice(0, 200);
      if (!reviewerCredentialsMatch(email, password)) {
        const nextCsrf = crypto.randomBytes(24).toString("base64url");
        res.setHeader("Set-Cookie", cookieHeader(CSRF_COOKIE, nextCsrf, 30 * 60, secure));
        return res.status(401).type("html").send(consentPage(base, fields, client.client_name, nextCsrf, "Reviewer sign-in was rejected."));
      }
      const reviewerEmail = configuredReviewerEmail();
      return finishCode(res, base, fields, reviewerAccountId(reviewerEmail), reviewerEmail, "pro");
    }
    if (decision === "email") {
      const email = String(body.email ?? "").trim().toLowerCase().slice(0, 254);
      const otp = String(body.otp ?? "").trim();
      const nextCsrf = crypto.randomBytes(24).toString("base64url");
      res.setHeader("Set-Cookie", cookieHeader(CSRF_COOKIE, nextCsrf, 30 * 60, secure));
      if (!identityConfigured()) {
        return res.status(400).type("html").send(consentPage(base, fields, client.client_name, nextCsrf, "Email sign-in is not configured on this server."));
      }
      if (!otp) {
        const sent = await sendEmailOtp(email);
        return res.status(sent.ok ? 200 : 400).type("html").send(consentPage(base, fields, client.client_name, nextCsrf, sent.ok ? "Check your email for a code, then submit it here." : (sent.error ?? "The email code could not be sent.")));
      }
      const verified = await verifyEmailOtp(email, otp);
      if (!verified) return res.status(401).type("html").send(consentPage(base, fields, client.client_name, nextCsrf, "That code was not accepted."));
      return finishCode(res, base, fields, verified.id, verified.email);
    }
    if (decision !== "approve") return res.redirect(redirectError(fields.redirect_uri, "access_denied", fields.state));
    const sub = accountIdFromRequest(req) ?? crypto.randomUUID();
    return finishCode(res, base, fields, sub, null);
  });

  app.post("/token", open, async (req, res) => {
    if (!allow(`token:${req.ip}`, 60, 10 * 60 * 1000)) return res.status(429).json({ error: "Too many token requests." });
    const grant = String(req.body?.grant_type ?? "");
    const base = publicBase(req);
    const audience = resourceUrl(base);
    try {
      if (grant === "authorization_code") {
        const code = String(req.body?.code ?? "");
        const clientId = String(req.body?.client_id ?? "");
        const redirectUri = String(req.body?.redirect_uri ?? "");
        const verifier = String(req.body?.code_verifier ?? "");
        const payload = verifyToken<TokenPayload & {
          sub?: unknown; aud?: unknown; client_hash?: unknown; redirect_uri?: unknown; code_challenge?: unknown; jti?: unknown;
        }>(code, "code");
        if (typeof payload.jti !== "string" || !consumeAuthorizationCode(payload.jti, payload.exp)) {
          return oauthError(res, 400, "invalid_grant", "This authorization code was already used.");
        }
        if (payload.client_hash !== sha(clientId) || payload.redirect_uri !== redirectUri) {
          return oauthError(res, 400, "invalid_grant", "The client or redirect URI does not match the authorization request.");
        }
        if (payload.aud !== audience) return oauthError(res, 400, "invalid_grant", "The resource does not match this server.");
        const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
        if (!verifier || verifier.length < 43 || verifier.length > 128 || challenge !== payload.code_challenge) {
          return oauthError(res, 400, "invalid_grant", "PKCE verification failed.");
        }
        if (typeof payload.sub !== "string") return oauthError(res, 400, "invalid_grant", "The authorization code is not valid.");
        await getStore().ensureAccount(payload.sub);
        res.set("Cache-Control", "no-store").json(issueTokens(payload.sub, audience));
        return;
      }
      if (grant === "refresh_token") {
        const refresh = String(req.body?.refresh_token ?? "");
        const payload = verifyToken<TokenPayload & { sub?: unknown; aud?: unknown; jti?: unknown }>(refresh, "refresh");
        if (typeof payload.sub !== "string" || typeof payload.jti !== "string" || payload.aud !== audience) {
          return oauthError(res, 400, "invalid_grant", "The refresh token is not valid for this server.");
        }
        const reuse = reuseRefresh(payload.jti);
        if (!reuse.fresh) {
          if (reuse.tokens) return res.set("Cache-Control", "no-store").json(reuse.tokens);
          return oauthError(res, 400, "invalid_grant", "This refresh token was already used.");
        }
        const tokens = issueTokens(payload.sub, audience);
        rememberRefresh(payload.jti, tokens);
        res.set("Cache-Control", "no-store").json(tokens);
        return;
      }
      return oauthError(res, 400, "unsupported_grant_type", "Use authorization_code or refresh_token.");
    } catch {
      return oauthError(res, 400, "invalid_grant", "The token request could not be verified.");
    }
  });
}

export function accountCookieName(): string {
  return ACCOUNT_COOKIE;
}
