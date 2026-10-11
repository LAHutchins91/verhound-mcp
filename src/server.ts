import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { bearerAccess, installOAuth } from "./auth.js";
import { accessFor, isBillingConfigured, type Access } from "./billing.js";
import { PRODUCT, publicBase, SERVICE, VERSION } from "./config.js";
import { MCP_CORS_HEADERS, mcpBrowserOriginAllowed } from "./mcp-clients.js";
import { mailConfigured } from "./mailer.js";
import { installPages } from "./pages.js";
import { getStore, storageBackendName } from "./store.js";
import { createVerhoundServer } from "./tools.js";
import { upstreamHealth } from "./upstream/http.js";
import { installCron } from "./watch-job.js";

export const app = express();
export default app;

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((_req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store"
  });
  next();
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));

export function logoFile(): string {
  const candidates = [
    path.resolve(process.cwd(), "logo.jpg"),
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "logo.jpg"),
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "logo.jpg")
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? candidates[0];
}

app.get(["/logo.jpg", "/favicon.ico"], (_req, res) => {
  res.type("image/jpeg");
  res.set("Cache-Control", "public, max-age=86400");
  res.sendFile(logoFile());
});

app.get("/health", (_req, res) => {
  const upstreams = upstreamHealth();
  res.json({
    ok: true,
    service: SERVICE,
    name: PRODUCT,
    version: VERSION,
    storageBackend: storageBackendName(),
    upstreams: {
      osv: upstreams.osv,
      depsdev: upstreams.depsdev,
      npm: upstreams.npm,
      pypi: upstreams.pypi,
      eol: upstreams.eol
    },
    billingConfigured: isBillingConfigured(),
    mailConfigured: mailConfigured()
  });
});

app.get("/.well-known/openai-apps-challenge", (_req, res) => {
  const token = process.env.OPENAI_APPS_CHALLENGE;
  if (!token) return res.status(404).type("text").send("Verification is not configured.");
  res.type("text").send(token);
});

installPages(app);
installOAuth(app);
installCron(app);

const buckets = new Map<string, { count: number; end: number }>();
function allow(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  for (const [name, value] of buckets) if (value.end <= now) buckets.delete(name);
  const current = buckets.get(key);
  if (current) {
    current.count += 1;
    return current.count <= limit;
  }
  if (buckets.size >= 10000) return false;
  buckets.set(key, { count: 1, end: now + windowMs });
  return true;
}

function guardMcpOrigin(req: Request, res: Response): boolean {
  const origin = req.header("origin");
  if (!mcpBrowserOriginAllowed(origin, publicBase(req))) {
    res.status(403).json({ error: "Origin is not allowed." });
    return false;
  }
  if (origin) res.set({ ...MCP_CORS_HEADERS, "Access-Control-Allow-Origin": origin, Vary: "Origin" });
  return true;
}

function unauthorized(req: Request, res: Response): void {
  const metadata = `${publicBase(req)}/.well-known/oauth-protected-resource/mcp`;
  res.set("WWW-Authenticate", `Bearer realm="${PRODUCT}", resource_metadata="${metadata}"`);
  res.status(401).json({ error: `Sign in to ${PRODUCT} to use these tools.` });
}

const publicMethods = new Set(["initialize", "notifications/initialized", "tools/list", "ping"]);

app.options("/mcp", (req, res) => {
  if (!guardMcpOrigin(req, res)) return;
  res.status(204).end();
});

app.get("/mcp", (req, res) => {
  if (!guardMcpOrigin(req, res)) return;
  const metadata = `${publicBase(req)}/.well-known/oauth-protected-resource/mcp`;
  res.set("WWW-Authenticate", `Bearer realm="${PRODUCT}", resource_metadata="${metadata}"`);
  res.status(405).set("Allow", "POST, DELETE, OPTIONS").json({ error: "Use Streamable HTTP POST." });
});

app.delete("/mcp", (req, res) => {
  if (!guardMcpOrigin(req, res)) return;
  res.status(200).json({});
});

app.post("/mcp", async (req, res) => {
  if (!guardMcpOrigin(req, res)) return;
  if (!allow(`mcp:${req.ip}`, 300, 60_000)) {
    res.status(429).set("Retry-After", "60").json({ error: "Too many requests." });
    return;
  }
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body) || typeof req.body.method !== "string") {
    res.status(400).json({ error: "Expected a single JSON-RPC request." });
    return;
  }
  const method = req.body.method as string;
  let access: Access | null = null;
  if (!publicMethods.has(method)) {
    const bearer = bearerAccess(req);
    if (!bearer) return unauthorized(req, res);
    await getStore().ensureAccount(bearer.sub);
    access = await accessFor(bearer.sub);
  }
  const started = Date.now();
  const tool = method === "tools/call" && req.body.params && typeof req.body.params === "object" ? String((req.body.params as { name?: unknown }).name ?? "") : "";
  res.on("finish", () => {
    if (method !== "tools/call") return;
    console.log(JSON.stringify({
      event: "mcp_timing",
      tool: tool.slice(0, 64),
      duration_ms: Date.now() - started,
      status: res.statusCode
    }));
  });
  const server = createVerhoundServer(access);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch {
    console.error(JSON.stringify({ event: "mcp_error", method }));
    if (!res.headersSent) res.status(500).json({ error: "Unable to process the request." });
  }
});

app.use((_req, res) => {
  res.status(404).json({ error: "Not found." });
});

export function handleRouteError(error: unknown, req: Request, res: Response, _next: NextFunction): void {
  const type = typeof error === "object" && error !== null && "type" in error ? (error as { type?: string }).type : undefined;
  const tooLarge = type === "entity.too.large";
  const badBody = typeof type === "string" && type.startsWith("entity.");
  const name = error instanceof Error ? error.name : typeof error;
  const message = error instanceof Error ? error.message.slice(0, 300) : "";
  console.error(JSON.stringify({ event: "route_error", method: req.method, path: req.path, name, message }));
  if (res.headersSent) return;
  if (tooLarge) {
    res.status(413).json({ error: "Request is too large." });
    return;
  }
  if (badBody) {
    res.status(400).json({ error: "Invalid request." });
    return;
  }
  res.status(500).json({ error: "Something went wrong." });
}

app.use(handleRouteError);

const invokedDirectly = process.argv[1] ? path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false;
if (process.env.NODE_ENV !== "test" && !process.env.VERCEL && !process.env.VITEST && invokedDirectly) {
  const port = Number(process.env.PORT ?? 43127);
  app.listen(port, "0.0.0.0", () => {
    console.log(`${PRODUCT} listening on ${port}`);
  });
}
