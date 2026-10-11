import { nowDate, nowMs } from "./clock.js";
import { REFRESH_REUSE_GRACE_MS } from "./config.js";
import { getStore } from "./store.js";

/**
 * One-time use for authorization codes and refresh tokens. With Supabase configured this is
 * shared across instances (oauth_used_tokens); otherwise it lives in the in-memory store.
 */
export async function consumeAuthorizationCode(jti: string, expUnixSeconds: number): Promise<boolean> {
  const claim = await getStore().claimOnce("code", jti, new Date(expUnixSeconds * 1000).toISOString(), nowDate().toISOString());
  return claim.fresh;
}

/**
 * fresh: first use. grace: reused within the grace window (a client retry), so a new pair is issued.
 * reused: reused after the grace window, rejected.
 */
export async function claimRefresh(jti: string, expUnixSeconds: number): Promise<"fresh" | "grace" | "reused"> {
  const claim = await getStore().claimOnce("refresh", jti, new Date(expUnixSeconds * 1000).toISOString(), nowDate().toISOString());
  if (claim.fresh) return "fresh";
  if (claim.usedAt && nowMs() - Date.parse(claim.usedAt) <= REFRESH_REUSE_GRACE_MS) return "grace";
  return "reused";
}

/** Kept for tests; state now lives in the store, which resetStoreForTests clears. */
export function resetOAuthStateForTests(): void {
  // no process-local state
}
