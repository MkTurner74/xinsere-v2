-- Finding 2 (HIGH): denial-of-wallet via per-file interactive grants.
--
-- Interactive folder-shares looped one on-chain grant tx PER FILE. Sharing a
-- 10,000-file folder = 10,000 signed txs from the single shared gas wallet in one
-- action; an attacker with any account could upload N tiny files, share the
-- folder, and drain the wallet -> every tenant's grants then fail closed
-- (platform-wide outage).
--
-- Fix: route interactive shares through the SAME capped Merkle batch path the
-- migration already uses (batch_grant.preserve / grantBatch) -- <= 1 flat-gas tx
-- per 1,000 files instead of one per file. The download gate already reads batch
-- grants (verify_batch), so no read-side change is needed.
--
-- This table records which batch root(s) an interactive share of (node_id ->
-- grantee) anchored, so a later unshare can revoke EXACTLY those roots. Interactive
-- roots are single-grantee and node-scoped, so a root-level revoke
-- (revokeBatchRoot) revokes precisely that share and affects no one else.
--
-- Service-role only (RLS deny-by-default). Written/read by the backend after the
-- owner authorization check in app.py.

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
-- batch/permission tables (permission_batches, batch_grants).
