import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Access } from "./billing.js";
import { nowMs } from "./clock.js";
import { ECOSYSTEMS, INSTRUCTIONS, PRODUCT, VERSION } from "./config.js";
import { toolError } from "./envelope.js";
import {
  auditManifest,
  checkPackages,
  listAlerts,
  planUpgrade,
  runtimeEolTool,
  unwatchManifest,
  verifyPackageExists,
  watchManifest,
  type ToolPayload
} from "./operations.js";
import { logToolTiming, withCallStats } from "./timing.js";

const READ_EXTERNAL = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const READ_INTERNAL = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const WRITE_WATCH = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const DELETE_WATCH = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };

const envelopeSchema = {
  data: z.unknown(),
  sources: z.array(z.object({
    id: z.string(),
    name: z.string(),
    url: z.string(),
    attribution: z.string()
  })),
  checked_at: z.string(),
  cache_age_seconds: z.number(),
  notes: z.array(z.string()),
  stale: z.boolean()
};

const ecosystem = z.enum(ECOSYSTEMS);

type ToolResult = ToolPayload & Record<string, unknown>;

function asResult(value: ToolPayload): ToolResult {
  return value as ToolResult;
}

async function timed(tool: string, items: number, fn: () => Promise<ToolPayload>): Promise<ToolResult> {
  const started = nowMs();
  try {
    const { value, stats } = await withCallStats(fn);
    logToolTiming(tool, nowMs() - started, !value.isError, stats, items);
    return asResult(value);
  } catch {
    logToolTiming(tool, nowMs() - started, false, { cacheHits: 0, upstreamFetches: 0, upstreamMs: 0 }, items);
    return asResult(toolError("The request could not be completed. Nothing was filled in instead of a guess."));
  }
}

export function createVerhoundServer(access: Access | null): McpServer {
  const server = new McpServer({ name: PRODUCT, version: VERSION }, { instructions: INSTRUCTIONS });

  server.registerTool("check_packages", {
    title: "Check packages",
    description: "Look up one or more packages and report the latest stable version, publish dates, whether the requested version is deprecated, its declared license, and known advisory IDs from OSV.dev with the first fixed version. Facts come from deps.dev, the npm registry, PyPI, and OSV.dev at the time shown. 'No known advisories' means none were found in OSV.dev. It is not a promise that no advisory exists. This tool does not install or change anything.",
    inputSchema: {
      packages: z.array(z.object({
        ecosystem,
        name: z.string().trim().min(1).max(214),
        version: z.string().trim().max(80).optional()
      })).min(1).max(100),
      include_prerelease: z.boolean().optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_EXTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("check_packages", args.packages.length, () => checkPackages(access, args.packages, args.include_prerelease));
  });

  server.registerTool("audit_manifest", {
    title: "Audit manifest",
    description: "Read pasted manifest or lockfile text (package.json, package-lock.json, requirements.txt, pyproject.toml, poetry.lock, go.mod) and list dependencies with known OSV.dev advisories, the first fixed version for each, and deprecated or end-of-life runtimes declared in the file. Only direct pins are resolved unless a lockfile is given. The text is processed in memory and not stored. Results reflect OSV.dev at the time shown and are not a complete security review. Nothing is installed or changed.",
    inputSchema: {
      filename: z.string().trim().min(1).max(120),
      content: z.string().max(200_000),
      include_dev: z.boolean().optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_EXTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("audit_manifest", 1, () => auditManifest(access, args));
  });

  server.registerTool("verify_package_exists", {
    title: "Verify package exists",
    description: "Check whether a package name is published in its registry (npm or PyPI; other ecosystems via deps.dev), with first-publish date, latest version, recent download count where the registry provides one, and similar popular names. Use it before adding a dependency an assistant suggested, to catch names that do not exist. Existing in the registry does not mean a package is maintained, or that it is the one you intended. Very new, rarely downloaded, or look-alike names are flagged for a human to review.",
    inputSchema: {
      ecosystem,
      name: z.string().trim().min(1).max(214).optional(),
      names: z.array(z.string().trim().min(1).max(214)).max(100).optional(),
      max_similar: z.number().int().min(1).max(5).optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_EXTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    const names = args.names?.length ? args.names : args.name ? [args.name] : [];
    if (!names.length) return asResult(toolError("Provide a package name."));
    return timed("verify_package_exists", names.length, () => verifyPackageExists(access, {
      ecosystem: args.ecosystem,
      names,
      maxSimilar: args.max_similar ?? 3
    }));
  });

  server.registerTool("plan_upgrade", {
    title: "Plan upgrade",
    description: "Compare a pinned package version with a newer version and describe the version jump, advisories that the newer version addresses, advisories that remain, engine and peer dependency changes, and commands for you to run after reviewing. Verhound does not install or upgrade anything.",
    inputSchema: {
      ecosystem,
      name: z.string().trim().min(1).max(214),
      from_version: z.string().trim().min(1).max(80),
      to_version: z.string().trim().min(1).max(80).optional(),
      project_runtime: z.object({
        node: z.string().max(40).optional(),
        python: z.string().max(40).optional()
      }).optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_EXTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("plan_upgrade", 1, () => planUpgrade(access, {
      ecosystem: args.ecosystem,
      name: args.name,
      fromVersion: args.from_version,
      toVersion: args.to_version,
      projectRuntime: args.project_runtime
    }));
  });

  server.registerTool("runtime_eol", {
    title: "Runtime end of life",
    description: "Look up end-of-life dates and maintenance flags for a language runtime or product from endoflife.date. Returns dates and flags only. It does not change the runtime.",
    inputSchema: {
      product: z.string().trim().min(1).max(60),
      version: z.string().trim().max(30).optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_EXTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("runtime_eol", 1, () => runtimeEolTool(access, args.product, args.version));
  });

  server.registerTool("watch_manifest", {
    title: "Watch manifest",
    description: "Pro: save a manifest so Verhound re-checks it against OSV.dev once a day and emails you when a new advisory affects a listed version. A trial can save one watched project. Only call this when the user explicitly asks to watch a project. Saving the same label again replaces that watch's manifest. Verhound never installs or upgrades anything; alerts describe what changed and link to the advisory.",
    inputSchema: {
      label: z.string().trim().min(1).max(60),
      filename: z.string().trim().min(1).max(120),
      content: z.string().max(200_000),
      min_severity: z.enum(["low", "moderate", "high", "critical"]).optional(),
      alert_email: z.literal("account").optional()
    },
    outputSchema: envelopeSchema,
    annotations: WRITE_WATCH
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("watch_manifest", 1, () => watchManifest(access, {
      label: args.label,
      filename: args.filename,
      content: args.content,
      minSeverity: args.min_severity,
      alertEmail: args.alert_email
    }));
  });

  server.registerTool("list_alerts", {
    title: "List alerts",
    description: "Pro: list your watched manifests and the advisory alerts raised for them, newest first. A trial with a watched project can list alerts for that project.",
    inputSchema: {
      label: z.string().trim().min(1).max(60).optional(),
      since: z.string().trim().max(40).optional(),
      limit: z.number().int().min(1).max(50).optional()
    },
    outputSchema: envelopeSchema,
    annotations: READ_INTERNAL
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("list_alerts", 0, () => listAlerts(access, { label: args.label, since: args.since, limit: args.limit ?? 20 }));
  });

  server.registerTool("unwatch_manifest", {
    title: "Unwatch manifest",
    description: "Pro: stop watching a manifest and delete its stored dependency list and alerts. A trial can delete its watched project the same way.",
    inputSchema: {
      label: z.string().trim().min(1).max(60)
    },
    outputSchema: envelopeSchema,
    annotations: DELETE_WATCH
  }, async (args) => {
    if (!access) return asResult(toolError("Sign in to use this tool."));
    return timed("unwatch_manifest", 0, () => unwatchManifest(access, args.label));
  });

  return server;
}
