-- Verhound schema, file 3 of 4.
-- Apply after 002_advisor_fixes.sql in the Supabase SQL editor.
-- This repository does not apply these files.
-- One Pro trial per normalized email, and one-time use for OAuth codes and refresh tokens.

-- trial_markers has no foreign key to accounts on purpose: deleting an account keeps the marker.
-- email_hash is a SHA-256 of the normalized email, so the address itself is not kept here.
create table if not exists public.trial_markers (
  email_hash text primary key,
  account_id uuid not null,
  first_used_at timestamptz not null default now()
);

create table if not exists public.oauth_used_tokens (
  jti text primary key,
  kind text not null check (kind in ('code', 'refresh')),
  used_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists oauth_used_tokens_expires_at_idx on public.oauth_used_tokens (expires_at);

alter table public.trial_markers enable row level security;
alter table public.oauth_used_tokens enable row level security;

revoke all on table public.trial_markers from anon, authenticated;
revoke all on table public.oauth_used_tokens from anon, authenticated;
grant all on table public.trial_markers to service_role;
grant all on table public.oauth_used_tokens to service_role;

drop policy if exists trial_markers_deny_clients on public.trial_markers;
create policy trial_markers_deny_clients on public.trial_markers
  as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists oauth_used_tokens_deny_clients on public.oauth_used_tokens;
create policy oauth_used_tokens_deny_clients on public.oauth_used_tokens
  as restrictive for all to anon, authenticated using (false) with check (false);
