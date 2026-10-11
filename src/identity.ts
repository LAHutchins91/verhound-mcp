interface IdentityOverride {
  send(email: string): Promise<{ ok: boolean; error?: string }>;
  verify(email: string, token: string): Promise<{ id: string; email: string } | null>;
}

let override: IdentityOverride | null = null;

export function setIdentityForTests(value: IdentityOverride | null): void {
  override = value;
}

export function identityConfigured(): boolean {
  if (override) return true;
  return Boolean(process.env.SUPABASE_URL?.trim() && process.env.SUPABASE_ANON_KEY?.trim());
}

function authUrl(path: string): string {
  return `${(process.env.SUPABASE_URL ?? "").replace(/\/$/, "")}/auth/v1/${path}`;
}

function headers(): Headers {
  const key = process.env.SUPABASE_ANON_KEY ?? "";
  return new Headers({
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json"
  });
}

export async function sendEmailOtp(email: string): Promise<{ ok: boolean; error?: string }> {
  if (override) return override.send(email);
  if (!identityConfigured()) return { ok: false, error: "Email sign-in is not configured on this server." };
  const response = await fetch(authUrl("otp"), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ email, create_user: true })
  });
  if (!response.ok) return { ok: false, error: "The email code could not be sent." };
  return { ok: true };
}

export async function verifyEmailOtp(email: string, token: string): Promise<{ id: string; email: string } | null> {
  if (override) return override.verify(email, token);
  if (!identityConfigured()) return null;
  const response = await fetch(authUrl("verify"), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ email, token, type: "email" })
  });
  if (!response.ok) return null;
  const body = await response.json() as { user?: { id?: string; email?: string } };
  if (!body.user?.id) return null;
  return { id: body.user.id, email: body.user.email ?? email };
}
