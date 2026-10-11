# Verhound by Ouroboros

Verhound reports dependency facts to coding agents over MCP: whether a name is published, the latest version, declared licenses, known advisories from OSV.dev, a per-package verdict (`no_known_issues`, `review`, or `avoid`), and runtime end-of-life dates. It covers npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems, and Composer. It does not install packages or change a project.

Connect a client to `https://verhound-mcp.vercel.app/mcp`.

## Install

ChatGPT, Claude, Cursor, and Grok use the same remote URL.

```json
{
  "mcpServers": {
    "verhound": {
      "url": "https://verhound-mcp.vercel.app/mcp"
    }
  }
}
```

The assistant opens a browser page so you can approve the connection.

## Pricing

<!-- price-allowed:start -->
Pro is $7.99/month or $79.99/year. The trial is 7 days and includes 100 tool calls a day and 1 watched project. Pro includes 300 tool calls a day and up to 10 watched projects, plus advisory alerts. A card is collected only after billing is connected on that deployment.
<!-- price-allowed:end -->

Free plan: an account with a verified email gets 15 one-off checks a day (`check_packages`, `verify_package_exists`, `runtime_eol`, and `audit_manifest` up to 20 KB), with up to 10 packages per call. `watch_manifest`, `list_alerts`, and `plan_upgrade` are part of Pro and the Pro trial. Every account needs a verified email, and each person gets one Pro trial. When a trial ends without Pro, the account moves to the free plan.

Card checkout is shown on the site and is not collected until billing is connected on that deployment.

## Permissions, data, and limits

- Tool calls read public package registries. `watch_manifest` stores the parsed dependency list (ecosystem, name, version), the filename, and the label. It does not store the raw file.
- Logs keep the tool name, counts, timing, and a SHA-256 hash of pasted manifest text. They do not keep package contents or account identifiers in the timing line. Retention for those logs is 7 days.
- Upstream calls are batched and cached. npm requests stop well under the registry's monthly ceiling.
- Daily caps are enforced in US Eastern time. The published numbers are in Pricing. A trial ends and the account moves to the free plan. Pro raises limits.
- `plan_upgrade` returns commands for you to run after reviewing, including Maven, Cargo, and NuGet. When you omit a target version, it picks the newest version with no known advisories. Verhound does not run the commands.
- Release-notes links are shown only after a GitHub check succeeds.
- Known malware records are listed first and alerted even below the watch severity minimum.
- Each watch can optionally post alerts to a Slack or Discord incoming webhook. Other hosts are refused, and redirects are not followed.
- `verify_package_exists` means the name is published in the registry. It does not mean the package is maintained or the one you intended.
- "No known advisories" means none were found in OSV.dev at the time shown.

## Data sources

Vulnerability data from OSV.dev, which aggregates the GitHub Advisory Database, PyPA Advisory Database, Go Vulnerability Database (CC-BY 4.0) and others. Known malware records may also be read from the GitHub Advisory Database and are attributed to that source. Package metadata from deps.dev (Google; derived data CC-BY 4.0), the npm registry, PyPI, RubyGems, and Packagist. Lifecycle data from endoflife.date (MIT). Verhound is not affiliated with or endorsed by Google, npm, PyPI, the Python Software Foundation, RubyGems, Packagist, GitHub, OSV, or endoflife.date.

## Operators

Ouroboros Apps, operated by Lawrence Hutchins as a sole proprietor. Support: ouroborosplugins@gmail.com. Docs: https://ouroborosapps.com/docs/verhound.

## Environment

Set these in the host. Do not commit secret values.

| Name | Purpose |
| --- | --- |
| `APP_BASE_URL` | Public origin, no trailing slash |
| `AUTH_SECRET` | HMAC key for OAuth tokens |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side key. Never exposed to the browser |
| `SUPABASE_ANON_KEY` | Email-code sign-in, when used |
| `REVIEWER_EMAIL` | Reviewer account email |
| `REVIEWER_PASSWORD_HASH` | scrypt hash: parameters 16384, 8, 1, then the salt and hash |
| `OPENAI_APPS_CHALLENGE` | Optional apps verification token |
| `CRON_SECRET` | Required for the hourly watch job |
| `GITHUB_TOKEN` | Optional. Raises the GitHub API limit for release-note checks and malware advisories. Omit it to use the unauthenticated API |
| `MAIL_PROVIDER` | `resend` to send mail, otherwise no mail is sent |
| `RESEND_API_KEY` | Used only when mail is enabled |
| `ALERT_FROM` | From address for alert mail |
| `TRIAL_DAYS` | Optional override, integer 1 through 3650. Default 7 |

The Supabase project for this product is ref `frkulsspyctwntbrihty` in `us-east-1`. Set `SUPABASE_URL` to `https://frkulsspyctwntbrihty.supabase.co`. The service-role key stays in the host environment. Apply `supabase/migrations/001_init.sql` through `004_free_plan_and_webhooks.sql` in numeric order in the SQL editor at deploy time. This repository does not apply those files.

There is no billing secret in this version. `billingConfigured` stays false until checkout is connected.

## Develop

```bash
npm ci
npm run typecheck
npm run lint
npm test
```

`npm test` does not call live registries. `VERHOUND_LIVE_SMOKE=1 npm run smoke` does, and it is not part of `npm test`.

The Vercel functions use 1 GB of memory. The web function limit is 20 seconds and the watch cron limit is 30 seconds. Upstream reads stay batched and cached so a warm call finishes inside that window.

## License

MIT. Copyright 2026 Lawrence Hutchins.
