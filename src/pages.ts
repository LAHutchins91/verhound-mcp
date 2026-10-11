import crypto from "node:crypto";
import type { Express, Request } from "express";
import { accountIdFromRequest, readCookie } from "./auth.js";
import { accessFor, isBillingConfigured, trialEndsAt } from "./billing.js";
import { DOCS_URL, HOST, LIMITS, PRODUCT, PUBLIC_BRAND, PUBLIC_CONTACT_EMAIL, TRIAL_DAYS, publicBase } from "./config.js";
import { escapeHtml, page } from "./html.js";
import { DATA_SOURCES_TEXT } from "./sources.js";
import { getStore } from "./store.js";
import { signToken, verifyToken, type TokenPayload } from "./tokens.js";

/** Empty until billing is connected. The sentence is not shown while checkout cannot collect a card. */
export function trialCardPhrase(): string {
  return isBillingConfigured() ? "A card is required." : "";
}

function priceCopy(): string {
  const card = trialCardPhrase();
  return `<!-- price-allowed:start -->
<p>Pro is $7.99/month or $79.99/year.</p>
<p>The trial is ${TRIAL_DAYS} days.${card ? ` ${card}` : ""} It includes ${LIMITS.trial.callsPerDay} tool calls a day and ${LIMITS.trial.watches} watched project. Pro includes ${LIMITS.pro.callsPerDay} tool calls a day and up to ${LIMITS.pro.watches} watched projects, plus advisory alerts.</p>
<!-- price-allowed:end -->
${freeCopy()}`;
}

function freeCopy(): string {
  const free = LIMITS.free;
  return `<p>Free plan: an account with a verified email gets ${free.callsPerDay} one-off checks a day (package checks, existence checks, runtime end-of-life lookups, and manifest audits up to ${Math.round(free.manifestBytes / 1000)} KB), with up to ${free.packagesPerCall} packages per call. Watched projects, alerts, and upgrade plans are part of Pro and the Pro trial. One Pro trial per person. When a trial ends without Pro, the account moves to the free plan.</p>`;
}

function shell(req: Request, title: string, body: string): string {
  return page(title, body, `${publicBase(req)}/logo.jpg`);
}

export function installPages(app: Express): void {
  app.get("/", (req, res) => {
    const body = `<p class="eyebrow">${escapeHtml(PRODUCT)}</p>
      <div class="hero">
        <div>
          <h1>Dependency facts for coding agents.</h1>
          <p class="lede">Verhound reports registry existence, latest versions, declared licenses, known advisories from OSV.dev, and runtime end-of-life dates. It does not install packages or change your project.</p>
          <div class="actions">
            <a class="btn primary" href="/connect">Connect</a>
            <a class="btn secondary" href="/checkout">Checkout</a>
          </div>
        </div>
        <img class="logo" src="/logo.jpg" alt="">
      </div>
      <section class="section">
        <h2>Pricing</h2>
        ${priceCopy()}
        <p><a href="/checkout">Checkout</a> shows the same prices. Card collection opens when billing is connected on the server.</p>
      </section>
      <section class="section grid">
        <article class="card"><h3>Known advisories</h3><p>Advisory IDs come from OSV.dev, with the first fixed version when OSV publishes one. An empty list means none were found at the time shown.</p></article>
        <article class="card"><h3>Existence</h3><p>A name that exists in the registry is only that: the name is published. It is not a statement about maintenance or intent.</p></article>
        <article class="card"><h3>Watched projects</h3><p>A watched project stores the parsed dependency list and filename. Verhound keeps checking every watched project and can email new advisories, or post them to a Slack or Discord incoming webhook.</p></article>
        <article class="card"><h3>Plans</h3><p>A small free plan for one-off checks, a ${TRIAL_DAYS}-day Pro trial, then Pro. Every account needs a verified email.</p></article>
      </section>
      <section class="section"><h2>Data sources</h2><p>${escapeHtml(DATA_SOURCES_TEXT)}</p></section>`;
    res.type("html").send(shell(req, PUBLIC_BRAND, body));
  });

  app.get("/checkout", (req, res) => {
    const ready = isBillingConfigured();
    const body = `<p class="eyebrow">Checkout</p>
      <h1>Pro</h1>
      ${priceCopy()}
      <section class="card">
        <p>${ready ? "Billing is configured." : "Card checkout is not open on this server yet. No card is collected until billing is connected."}</p>
        <p>${ready ? `A card is required to start the ${TRIAL_DAYS}-day trial.` : "The trial starts when billing is connected."} After the trial, Pro continues at the price above. You can cancel and keep access through the end of the paid period.</p>
        <p>Support: <a href="mailto:${escapeHtml(PUBLIC_CONTACT_EMAIL)}">${escapeHtml(PUBLIC_CONTACT_EMAIL)}</a></p>
      </section>`;
    res.type("html").send(shell(req, `Checkout · ${PUBLIC_BRAND}`, body));
  });

  app.get("/connect", (req, res) => {
    const endpoint = `${HOST}/mcp`;
    const body = `<p class="eyebrow">Connect</p>
      <h1>Add Verhound to an assistant</h1>
      <p class="lede">Point the client at <code>${escapeHtml(endpoint)}</code>. The assistant opens a browser so you can approve the connection.</p>
      <pre>ChatGPT, Claude, Cursor, or Grok
URL ${escapeHtml(endpoint)}</pre>
      <p>Plan details are on <a href="/checkout">checkout</a>. Docs: <a href="${escapeHtml(DOCS_URL)}">${escapeHtml(DOCS_URL)}</a>.</p>`;
    res.type("html").send(shell(req, `Connect · ${PUBLIC_BRAND}`, body));
  });

  app.get("/docs", (req, res) => {
    const body = `<p class="eyebrow">Docs</p>
      <h1>What the tools return</h1>
      <p>Full product notes: <a href="${escapeHtml(DOCS_URL)}">${escapeHtml(DOCS_URL)}</a>.</p>
      <ul>
        <li><code>check_packages</code> reports versions, declared licenses, and known advisories.</li>
        <li><code>verify_package_exists</code> reports whether a name is published. The meaning is exists in the registry only.</li>
        <li><code>audit_manifest</code> reads pasted manifest text in memory and does not store it.</li>
        <li><code>plan_upgrade</code> returns a plan and commands for you to run. Verhound does not run them.</li>
        <li><code>runtime_eol</code> returns end-of-life dates from endoflife.date.</li>
        <li><code>watch_manifest</code>, <code>list_alerts</code>, and <code>unwatch_manifest</code> manage a watched project.</li>
      </ul>`;
    res.type("html").send(shell(req, `Docs · ${PUBLIC_BRAND}`, body));
  });

  app.get("/privacy", (req, res) => {
    const body = `<p class="eyebrow">Privacy</p>
      <h1>Privacy</h1>
      <p>Manifest text is stored only for accounts that watch a project, and only as the parsed dependency list (ecosystem, name, version), the filename, and the label. Package contents beyond names and versions are not stored.</p>
      <p>Logs keep the tool name, counts, timing, and a SHA-256 hash of pasted manifest text. They do not keep the manifest text. Log retention is 7 days.</p>
      <p>Upstream calls send package names and versions to OSV.dev, deps.dev, the npm registry, PyPI, or endoflife.date. Cache rows are stored by package, not by account.</p>
      <p>Processors are Vercel (hosting), Supabase (database, when configured), and email delivery when alert email is enabled.</p>
      <p>You can delete the account and its watches, alerts, and usage from the account page.</p>
      <p>${escapeHtml(DATA_SOURCES_TEXT)}</p>`;
    res.type("html").send(shell(req, `Privacy · ${PUBLIC_BRAND}`, body));
  });

  app.get("/terms", (req, res) => {
    const body = `<p class="eyebrow">Terms</p>
      <h1>Terms</h1>
      <p>${escapeHtml(PRODUCT)} is operated by Ouroboros Apps, operated by Lawrence Hutchins as a sole proprietor.</p>
      <p>The service reports third-party package data. It does not install or change your code. Known-advisory results are limited to what OSV.dev returned at the time shown.</p>
      <p>These terms are governed by the laws of the Commonwealth of Virginia, USA.</p>
      <p>You can cancel a paid plan at any time. Access continues through the end of the paid period. Fees are not refunded, and there is no promise of a refund.</p>
      <p>Support: <a href="mailto:${escapeHtml(PUBLIC_CONTACT_EMAIL)}">${escapeHtml(PUBLIC_CONTACT_EMAIL)}</a>.</p>`;
    res.type("html").send(shell(req, `Terms · ${PUBLIC_BRAND}`, body));
  });

  app.get("/account", async (req, res) => {
    const id = accountIdFromRequest(req);
    if (!id) {
      res.type("html").send(shell(req, `Account · ${PUBLIC_BRAND}`, "<h1>Account</h1><p>Connect an assistant first. Then return here to see the trial or to delete stored data.</p><p><a href=\"/checkout\">Checkout</a></p>"));
      return;
    }
    const access = await accessFor(id);
    const csrf = crypto.randomBytes(18).toString("base64url");
    res.setHeader("Set-Cookie", `verhound_page=${encodeURIComponent(csrf)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800`);
    const trial = access.plan === "pro"
      ? "Pro is active on this account."
      : access.emailRequired
        ? "This account has no verified email. Reconnect and sign in with the email code."
        : access.plan === "trial"
          ? `Pro trial ends ${escapeHtml(access.trialEndsAt ?? trialEndsAt(new Date().toISOString()))}.`
          : `Free plan.${access.trialEndsAt ? ` The Pro trial ended ${escapeHtml(access.trialEndsAt)}.` : ""}`;
    const body = `<h1>Account</h1>
      <p>${trial}</p>
      <p>Email: ${escapeHtml(access.email ?? "none saved")}</p>
      <p><a href="/checkout">Checkout</a></p>
      <form method="post" action="/account/delete">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button class="btn secondary" type="submit">Delete stored data</button>
      </form>`;
    res.type("html").send(shell(req, `Account · ${PUBLIC_BRAND}`, body));
  });

  app.post("/account/delete", async (req, res) => {
    const id = accountIdFromRequest(req);
    const csrf = String(req.body?.csrf ?? "");
    if (!id || !csrf || csrf !== readCookie(req, "verhound_page")) {
      res.status(400).type("html").send(shell(req, PUBLIC_BRAND, "<h1>The form expired.</h1>"));
      return;
    }
    await getStore().deleteAccount(id);
    res.setHeader("Set-Cookie", "verhound_account=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    res.type("html").send(shell(req, PUBLIC_BRAND, "<h1>Stored data for this account was deleted.</h1>"));
  });

  app.get("/unwatch", (req, res) => {
    const token = String(req.query.token ?? "");
    let label = "";
    try {
      const payload = verifyToken<TokenPayload & { label?: unknown }>(token, "unwatch");
      label = typeof payload.label === "string" ? payload.label : "";
    } catch {
      label = "";
    }
    if (!label) {
      res.status(400).type("html").send(shell(req, PUBLIC_BRAND, "<h1>This unwatch link is not valid.</h1>"));
      return;
    }
    const body = `<h1>Stop watching ${escapeHtml(label)}?</h1>
      <p>This deletes the stored dependency list and alerts for that label. Opening this page does not delete anything.</p>
      <form method="post" action="/unwatch">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <button class="btn primary" type="submit">Delete this watch</button>
      </form>`;
    res.type("html").send(shell(req, `Unwatch · ${PUBLIC_BRAND}`, body));
  });

  app.post("/unwatch", async (req, res) => {
    const token = String(req.body?.token ?? "");
    try {
      const payload = verifyToken<TokenPayload & { sub?: unknown; label?: unknown }>(token, "unwatch");
      if (typeof payload.sub !== "string" || typeof payload.label !== "string") throw new Error("bad");
      await getStore().deleteWatch(payload.sub, payload.label);
      res.type("html").send(shell(req, PUBLIC_BRAND, `<h1>Stopped watching ${escapeHtml(payload.label)}.</h1>`));
    } catch {
      res.status(400).type("html").send(shell(req, PUBLIC_BRAND, "<h1>This unwatch link is not valid.</h1>"));
    }
  });
}

export function unwatchToken(accountId: string, label: string): string {
  return signToken({ typ: "unwatch", sub: accountId, label }, 30 * 24 * 60 * 60);
}
