import { USER_AGENT } from "./config.js";
import { dispatchFetch } from "./upstream/http.js";

export type WebhookKind = "slack" | "discord";

/** Incoming-webhook hosts only. Any other host, scheme, or path is refused. */
export function webhookKind(raw: string): WebhookKind | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  // Only the default https port. A custom port would reach a different service on that host.
  if (url.port) return null;
  if (raw.length > 512) return null;
  if (url.hostname === "hooks.slack.com" && url.pathname.startsWith("/services/")) return "slack";
  if (url.hostname === "discord.com" && url.pathname.startsWith("/api/webhooks/")) return "discord";
  return null;
}

export function webhookHostLabel(raw: string | null | undefined): string | null {
  const kind = raw ? webhookKind(raw) : null;
  if (kind === "slack") return "hooks.slack.com";
  if (kind === "discord") return "discord.com";
  return null;
}

export function slackEscape(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * POST an alert text. Redirects are refused and not followed.
 * The URL is not written to logs.
 */
/**
 * "gone" means Slack or Discord says the webhook no longer exists or the token is wrong
 * (401, 403, 404, 410). Retrying will not help, so the caller stops retrying.
 */
export async function postWebhook(raw: string, text: string): Promise<"ok" | "rejected" | "gone" | "failed"> {
  const kind = webhookKind(raw);
  if (!kind) return "rejected";
  // Package names such as @everyone/x must not ping a Discord server, and Slack control
  // sequences like <!channel> must not be formed from alert text.
  const payload = kind === "slack"
    ? { text: slackEscape(text).slice(0, 3500) }
    : { content: text.slice(0, 1900), allowed_mentions: { parse: [] } };
  let response: Response;
  try {
    response = await dispatchFetch(raw, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8_000)
    });
  } catch {
    return "failed";
  }
  if (response.status >= 300 && response.status < 400) return "rejected";
  if ([401, 403, 404, 410].includes(response.status)) return "gone";
  if (!response.ok) return "failed";
  return "ok";
}
