-- Verhound schema, file 5 of 5.
-- Apply after 004_free_plan_and_webhooks.sql in the Supabase SQL editor.
-- This repository does not apply these files.
-- The app encrypts webhook URLs before writing them. A plaintext URL already in
-- webhook_url is rewritten to ciphertext on the next read, when WEBHOOK_ENC_KEY is set.
-- Alert rows stay pending until email or the webhook is sent, so a cron run that
-- runs out of time can finish them on the next run.
-- stripe_customer_id is filled from Stripe webhooks. This file does not call Stripe.

alter table public.alerts add column if not exists webhook_sent_at timestamptz;
alter table public.alerts add column if not exists email_claim_at timestamptz;
alter table public.alerts add column if not exists webhook_claim_at timestamptz;

alter table public.accounts add column if not exists stripe_customer_id text;
