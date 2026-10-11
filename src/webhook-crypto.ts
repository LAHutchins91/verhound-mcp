import crypto from "node:crypto";

/** Versioned AES-256-GCM payload. Plaintext rows from before this prefix are migrated on read. */
export const WEBHOOK_SEAL_PREFIX = "vh1.";

export class WebhookKeyError extends Error {
  constructor() {
    super("WEBHOOK_ENC_KEY is required to store a webhook.");
    this.name = "WebhookKeyError";
  }
}

export interface WebhookRead {
  url: string | null;
  /** Ciphertext to write back when a legacy plaintext URL can be sealed. */
  rewrite: string | null;
  /** Production has a webhook and no usable key, so the URL must not be used. */
  blocked: boolean;
}

function decodeKey(raw: string): Buffer | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const buf = Buffer.from(trimmed, "base64");
    if (buf.length === 32) return buf;
  } catch {
    return null;
  }
  return null;
}

/** 32-byte key from WEBHOOK_ENC_KEY (standard base64). Missing or wrong length is treated as unset. */
export function webhookKeyBytes(): Buffer | null {
  return decodeKey(process.env.WEBHOOK_ENC_KEY ?? "");
}

export function sealWebhookUrl(url: string): string {
  const key = webhookKeyBytes();
  if (!key) {
    if (process.env.VERCEL_ENV === "production") throw new WebhookKeyError();
    return url;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(url, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return WEBHOOK_SEAL_PREFIX + Buffer.concat([iv, tag, ciphertext]).toString("base64url");
}

export function readWebhookUrl(stored: string | null | undefined): WebhookRead {
  if (!stored) return { url: null, rewrite: null, blocked: false };
  const key = webhookKeyBytes();
  const production = process.env.VERCEL_ENV === "production";
  if (!stored.startsWith(WEBHOOK_SEAL_PREFIX)) {
    if (!key) {
      if (production) return { url: null, rewrite: null, blocked: true };
      return { url: stored, rewrite: null, blocked: false };
    }
    return { url: stored, rewrite: sealWebhookUrl(stored), blocked: false };
  }
  if (!key) return { url: null, rewrite: null, blocked: production };
  try {
    const raw = Buffer.from(stored.slice(WEBHOOK_SEAL_PREFIX.length), "base64url");
    if (raw.length < 12 + 16 + 1) return { url: null, rewrite: null, blocked: production };
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const url = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return { url, rewrite: null, blocked: false };
  } catch {
    return { url: null, rewrite: null, blocked: production };
  }
}

export function sealForStorage(url: string | null | undefined): string | null {
  if (!url) return null;
  if (url.startsWith(WEBHOOK_SEAL_PREFIX)) return url;
  return sealWebhookUrl(url);
}

const NEEDS_KEY = Symbol.for("verhound.webhookNeedsKey");

/** Non-enumerable, so it is not written to the database or to logs. */
export function flagWebhookNeedsKey(watch: object): void {
  Object.defineProperty(watch, NEEDS_KEY, { value: true, enumerable: false, configurable: true });
}

export function webhookNeedsKey(watch: object): boolean {
  return (watch as Record<symbol, unknown>)[NEEDS_KEY] === true;
}
