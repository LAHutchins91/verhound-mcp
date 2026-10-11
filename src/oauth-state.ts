import { nowMs } from "./clock.js";
import { REFRESH_REUSE_GRACE_MS } from "./config.js";

const usedCodes = new Map<string, number>();

interface RefreshUse {
  at: number;
  tokens: Record<string, unknown> | null;
}

const refreshUses = new Map<string, RefreshUse>();

export function consumeAuthorizationCode(jti: string, expUnixSeconds: number): boolean {
  const now = Math.floor(nowMs() / 1000);
  for (const [id, exp] of usedCodes) {
    if (exp < now) usedCodes.delete(id);
  }
  if (usedCodes.has(jti)) return false;
  usedCodes.set(jti, expUnixSeconds);
  return true;
}

export function reuseRefresh(jti: string): { fresh: boolean; tokens?: Record<string, unknown> } {
  const now = nowMs();
  for (const [id, entry] of refreshUses) {
    if (entry.tokens && now - entry.at > REFRESH_REUSE_GRACE_MS) {
      refreshUses.set(id, { at: entry.at, tokens: null });
    }
    if (now - entry.at > 30 * 24 * 60 * 60 * 1000) refreshUses.delete(id);
  }
  const existing = refreshUses.get(jti);
  if (!existing) return { fresh: true };
  if (existing.tokens && now - existing.at <= REFRESH_REUSE_GRACE_MS) return { fresh: false, tokens: existing.tokens };
  return { fresh: false };
}

export function rememberRefresh(jti: string, tokens: Record<string, unknown>): void {
  refreshUses.set(jti, { at: nowMs(), tokens });
}

export function resetOAuthStateForTests(): void {
  usedCodes.clear();
  refreshUses.clear();
}
