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

/**
 * POST an alert text. Redirects are refused and not followed.
 * The URL is not written to logs.
 */
export async function postWebhook(raw: string, text: string): Promise<"ok" | "rejected" | "failed"> {
  const kind = webhookKind(raw);
  if (!kind) return "rejected";
  const payload = kind === "slack" ? { text } : { content: text.slice(0, 1900) };
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
  if (!response.ok) return "failed";
  return "ok";
}
