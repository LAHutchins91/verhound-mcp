-- Verhound schema, file 4 of 5.
-- Apply after 003_trials_and_token_use.sql in the Supabase SQL editor.
-- This repository does not apply these files.
-- Allows the free plan, stores an optional Slack or Discord webhook on a watch,
-- and marks alerts that are known malware records.

alter table public.accounts drop constraint if exists accounts_plan_check;
alter table public.accounts add constraint accounts_plan_check check (plan in ('free', 'trial', 'pro'));

alter table public.watches add column if not exists webhook_url text;
alter table public.watches add column if not exists license_allow jsonb not null default '[]'::jsonb;
alter table public.watches add column if not exists license_deny jsonb not null default '[]'::jsonb;

alter table public.alerts add column if not exists malicious boolean not null default false;
