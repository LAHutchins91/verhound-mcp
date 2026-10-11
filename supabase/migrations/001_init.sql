-- Verhound cache, watches, alerts, and per-account caps.
-- Apply this file in the Supabase SQL editor at deploy time.
-- This repository does not apply it.

create extension if not exists pgcrypto;
create extension if not exists citext;

create table if not exists accounts (
  id uuid primary key,
  email citext unique,
  plan text not null default 'trial' check (plan in ('trial', 'pro')),
  trial_started_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists usage_daily (
  account_id uuid not null references accounts(id) on delete cascade,
  day date not null,
  calls int not null default 0,
  packages int not null default 0,
  plan_upgrade_calls int not null default 0,
  primary key (account_id, day)
);

create table if not exists cache_entries (
  key text primary key,
  source text not null,
  body jsonb not null,
  etag text,
  last_modified text,
  fetched_at timestamptz not null,
  expires_at timestamptz not null
);
create index if not exists cache_entries_expires_at_idx on cache_entries (expires_at);

create table if not exists upstream_usage (
  source text not null,
  month date not null,
  requests int not null default 0,
  primary key (source, month)
);

create table if not exists watches (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  label text not null,
  filename text not null,
  ecosystem_summary jsonb not null default '{}'::jsonb,
  deps jsonb not null,
  min_severity text not null default 'low',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_checked_at timestamptz,
  baseline_complete boolean not null default false,
  email text,
  unique (account_id, label)
);
create index if not exists watches_due_idx on watches (last_checked_at);

create table if not exists watch_seen (
  watch_id uuid not null references watches(id) on delete cascade,
  advisory_id text not null,
  package text not null,
  version text not null,
  first_seen_at timestamptz not null default now(),
  primary key (watch_id, advisory_id, package, version)
);

create table if not exists alerts (
  id uuid primary key,
  watch_id uuid not null references watches(id) on delete cascade,
  account_id uuid not null references accounts(id) on delete cascade,
  label text not null default '',
  advisory_id text not null,
  package text not null,
  version text not null,
  severity text,
  first_fixed_version text,
  url text not null,
  detected_at timestamptz not null default now(),
  emailed_at timestamptz
);
create index if not exists alerts_account_detected_idx on alerts (account_id, detected_at desc);

alter table accounts enable row level security;
alter table usage_daily enable row level security;
alter table cache_entries enable row level security;
alter table upstream_usage enable row level security;
alter table watches enable row level security;
alter table watch_seen enable row level security;
alter table alerts enable row level security;

revoke all on table accounts from anon, authenticated;
revoke all on table usage_daily from anon, authenticated;
revoke all on table cache_entries from anon, authenticated;
revoke all on table upstream_usage from anon, authenticated;
revoke all on table watches from anon, authenticated;
revoke all on table watch_seen from anon, authenticated;
revoke all on table alerts from anon, authenticated;

grant all on table accounts to service_role;
grant all on table usage_daily to service_role;
grant all on table cache_entries to service_role;
grant all on table upstream_usage to service_role;
grant all on table watches to service_role;
grant all on table watch_seen to service_role;
grant all on table alerts to service_role;

create or replace function consume_usage(
  p_account_id uuid,
  p_day date,
  p_calls int,
  p_packages int,
  p_plan int,
  p_call_limit int,
  p_plan_limit int
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  current_row usage_daily%rowtype;
begin
  insert into usage_daily (account_id, day, calls, packages, plan_upgrade_calls)
  values (p_account_id, p_day, 0, 0, 0)
  on conflict (account_id, day) do nothing;

  select * into current_row
  from usage_daily
  where account_id = p_account_id and day = p_day
  for update;

  if current_row.calls + p_calls > p_call_limit or current_row.plan_upgrade_calls + p_plan > p_plan_limit then
    return jsonb_build_object(
      'allowed', false,
      'calls', current_row.calls,
      'packages', current_row.packages,
      'plan_upgrade_calls', current_row.plan_upgrade_calls
    );
  end if;

  update usage_daily
  set calls = calls + p_calls,
      packages = packages + p_packages,
      plan_upgrade_calls = plan_upgrade_calls + p_plan
  where account_id = p_account_id and day = p_day
  returning * into current_row;

  return jsonb_build_object(
    'allowed', true,
    'calls', current_row.calls,
    'packages', current_row.packages,
    'plan_upgrade_calls', current_row.plan_upgrade_calls
  );
end;
$$;

create or replace function add_upstream_usage(p_source text, p_month date, p_delta int) returns int
language plpgsql
security definer
set search_path = public
as $$
declare
  next_count int;
begin
  insert into upstream_usage (source, month, requests)
  values (p_source, p_month, p_delta)
  on conflict (source, month) do update
  set requests = upstream_usage.requests + excluded.requests
  returning requests into next_count;
  return next_count;
end;
$$;

create or replace function purge_expired_cache(p_before timestamptz) returns int
language plpgsql
security definer
set search_path = public
as $$
declare
  removed int;
begin
  delete from cache_entries where expires_at < p_before;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function consume_usage(uuid, date, int, int, int, int, int) from public, anon, authenticated;
revoke all on function add_upstream_usage(text, date, int) from public, anon, authenticated;
revoke all on function purge_expired_cache(timestamptz) from public, anon, authenticated;
grant execute on function consume_usage(uuid, date, int, int, int, int, int) to service_role;
grant execute on function add_upstream_usage(text, date, int) to service_role;
grant execute on function purge_expired_cache(timestamptz) to service_role;
