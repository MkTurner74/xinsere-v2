-- 2026-07-15 prod incident: migration 0011 (share_batches) was never applied to
-- the production database, so every interactive share anchored since the batch
-- cutover (2026-07-13) recorded NO (node, grantee) -> root mapping — the insert
-- is best-effort and failed silently — and every unshare 500'd on the mapping
-- lookup (fail-closed: no share row was deleted, no grant left dangling).
--
-- This migration is self-contained and idempotent:
--   1. creates share_batches if missing (verbatim from 0011);
--   2. backfills the mapping from the proof cache: permission_batches.scope holds
--      the share node and batch_grants.grantee_id the grantee for every
--      interactive-source batch, and interactive roots are single-grantee +
--      node-scoped, so the reconstruction is exact;
--   3. reports any OTHER expected table that is still missing, so a second
--      skipped migration can't hide the same way.
--
-- (The app also gained a runtime fallback that derives roots from the proof
-- cache, so revokes work even before this runs — this backfill restores the
-- fast exact path and the audit mapping.)

-- 1. Table (verbatim from 0011, safe if 0011 was already applied) -------------
create table if not exists public.share_batches (
    id           uuid primary key default gen_random_uuid(),
    node_id      text not null references public.nodes(id) on delete cascade,
    grantee      uuid not null references public.profiles(id) on delete cascade,
    merkle_root  text not null,
    created_at   timestamptz not null default now(),
    unique (node_id, grantee, merkle_root)
);
create index if not exists share_batches_lookup_idx
    on public.share_batches(node_id, grantee);
alter table public.share_batches enable row level security;
-- Deny-by-default: no policies (service-role only), consistent with the other
-- batch/permission tables.

-- 2. Backfill from the proof cache -------------------------------------------
-- Sources must match supa.INTERACTIVE_SHARE_SOURCES. Joins on nodes/profiles
-- keep FK integrity (a batch whose node was since erased is skipped — its files
-- are gone, there is nothing left to revoke).
insert into public.share_batches (node_id, grantee, merkle_root, created_at)
select distinct pb.scope, bg.grantee_id, pb.merkle_root, pb.created_at
from public.permission_batches pb
join public.batch_grants bg on bg.batch_id = pb.id
join public.nodes n on n.id = pb.scope
join public.profiles p on p.id = bg.grantee_id
where pb.source in ('share', 'grant-on-add', 'reconcile-invite', 'move', 'reanchor')
  and pb.status <> 'revoked'
on conflict (node_id, grantee, merkle_root) do nothing;

-- 3. Schema completeness check — should return ZERO rows. Any row named here is
-- a table from migrations 0001–0018 that is still missing in this database.
select missing_table from unnest(array[
    'profiles', 'nodes', 'shares',                     -- 0001
    'organizations', 'org_members', 'api_keys',        -- 0003
    'api_key_usage',                                   -- 0004
    'access_log', 'access_log_anchors',                -- 0005
    'pending_shares',                                  -- 0006
    'permission_batches', 'batch_grants',              -- 0007
    'migration_runs',                                  -- 0008
    'platform_admins',                                 -- 0009
    'share_batches',                                   -- 0011
    'share_rate_usage',                                -- 0012
    'account_security',                                -- 0013
    'org_usage',                                       -- 0015
    'access_log_anchor_periods', 'access_log_org_roots' -- 0018
]) as t(missing_table)
where not exists (
    select 1 from information_schema.tables
    where table_schema = 'public' and table_name = t.missing_table);
