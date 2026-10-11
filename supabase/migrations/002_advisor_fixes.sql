-- Fixes from the Supabase security and performance advisors (2026-10-10).
-- The app uses only the service role, which bypasses RLS. These policies make
-- the deny-all intent for anon and authenticated explicit.

create schema if not exists extensions;
alter extension citext set schema extensions;

do $$
declare
  t text;
begin
  foreach t in array array['accounts', 'usage_daily', 'cache_entries', 'upstream_usage', 'watches', 'watch_seen', 'alerts'] loop
    execute format('drop policy if exists %I on public.%I', t || '_deny_clients', t);
    execute format(
      'create policy %I on public.%I as restrictive for all to anon, authenticated using (false) with check (false)',
      t || '_deny_clients', t
    );
  end loop;
end
$$;

create index if not exists alerts_watch_id_idx on public.alerts (watch_id);
