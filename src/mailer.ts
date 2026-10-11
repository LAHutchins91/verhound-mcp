import { DATA_SOURCES_TEXT } from "./sources.js";

export interface DigestAlert {
  label: string;
  package: string;
  version: string;
  advisory_id: string;
  severity: string | null;
  first_fixed_version: string | null;
  url: string;
  malicious?: boolean;
}

export interface AlertDigest {
  alerts: DigestAlert[];
  accountUrl: string;
}

export interface Mailer {
  sendAlert(to: string, digest: AlertDigest): Promise<void>;
}

export class NoopMailer implements Mailer {
  async sendAlert(): Promise<void> {
    return undefined;
  }
}

export function mailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY?.trim() && process.env.ALERT_FROM?.trim() && process.env.MAIL_PROVIDER === "resend");
}

export function renderDigest(digest: AlertDigest): { subject: string; text: string } {
  const labels = [...new Set(digest.alerts.map((alert) => alert.label))];
  const label = labels.length === 1 ? labels[0] : `${labels.length} watched manifests`;
  const subject = `Verhound: ${digest.alerts.length} new advisories in ${label}`;
  const ordered = [...digest.alerts].sort((a, b) => Number(Boolean(b.malicious)) - Number(Boolean(a.malicious)));
  const blocks = ordered.map((alert) => [
    alert.malicious ? "Known malware record." : "",
    `${alert.package}@${alert.version} (${alert.label})`,
    `Advisory: ${alert.advisory_id}`,
    alert.severity ? `Severity: ${alert.severity}` : "",
    alert.first_fixed_version ? `First fixed version: ${alert.first_fixed_version}` : "",
    `Link: ${alert.url}`
  ].filter(Boolean).join("\n"));
  const text = [
    "Verhound found new advisories.",
    "",
    ...blocks.flatMap((block) => [block, ""]),
    "Verhound has not changed your project. Review the advisory and upgrade if appropriate.",
    "",
    "To stop watching a manifest, call unwatch_manifest with its label.",
    `Account and deletion: ${digest.accountUrl}`,
    "",
    DATA_SOURCES_TEXT
  ].join("\n");
  return { subject, text };
}

export class ResendMailer implements Mailer {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async sendAlert(to: string, digest: AlertDigest): Promise<void> {
    const key = process.env.RESEND_API_KEY?.trim();
    const from = process.env.ALERT_FROM?.trim();
    if (!key || !from) return;
    const { subject, text } = renderDigest(digest);
    const response = await this.fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ from, to: [to], subject, text })
    });
    if (!response.ok) throw new Error("The alert email was not accepted.");
  }
}

export function getMailer(): Mailer {
  if (!mailConfigured()) return new NoopMailer();
  return new ResendMailer();
}
