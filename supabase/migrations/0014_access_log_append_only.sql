-- Finding 6 (MED): make the access log genuinely append-only until the daily
-- on-chain anchor lands.
--
-- The log's tamper-evidence rests on the daily Merkle anchor (now built:
-- access_log.anchor_day + /api/anchor-access-log). Between writes and the anchor,
-- integrity rested on Postgres alone — and the service-role key (held by the web
-- process and the Fargate worker) bypasses RLS and could UPDATE/DELETE any row.
--
-- Fix: revoke UPDATE/DELETE on access_log at the PRIVILEGE level (separate from
-- RLS, so it binds even the service-role). The app only ever INSERTs here. The
-- anchors table stays writable (the anchor job updates tx_hash on it).

revoke update, delete on public.access_log from anon, authenticated;

-- service_role bypasses RLS but not table privileges — revoke there too so history
-- can't be silently rewritten. Wrapped so it's a no-op if the role/grant differs
-- across environments.
do $$
begin
    execute 'revoke update, delete on public.access_log from service_role';
exception when others then
    raise notice 'could not revoke update/delete from service_role on access_log: %', sqlerrm;
end $$;
