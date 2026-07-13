-- Merkle aggregate batch-grant: proof cache for bulk permission preservation.
-- ADR-2026-07-13. Built for the Dropbox migration's permission-preservation pass,
-- reusable by every future connector (OneDrive/Google/Box).
--
-- WHY THIS IS A CACHE, NOT SOURCE OF TRUTH (Mark's corruption concern):
--   The on-chain Merkle root is the source of truth (immutable once mined). These
--   rows are a convenience index over data that is otherwise deterministically
--   REBUILDABLE: every leaf = keccak256(fileHash(file_id) ++ granteeHash(grantee_id)),
--   and file_id/grantee_id already live in nodes/shares. If a proof here is ever
--   wrong, verifyBatch fails CLOSED (download denied) — corruption can only block a
--   legitimate user, never expose a file — and the tree/proofs can be regenerated
--   from the manifest. So a corrupt cache is a recoverable annoyance, not data loss.
--
-- BLAST-RADIUS CAP: each batch anchors <= XINSERE_BATCH_MAX leaves (default 1,000),
-- so a single bad root affects at most that chunk. status gates trust: a batch is
-- only 'live' after the connector reads its root back on-chain and re-checks a
-- sample of proofs via verifyBatch.
--
-- Trust model matches 0003/0004/0005/0006: service-role only, RLS deny-by-default.

-- One row per anchored Merkle root (one on-chain grantBatch tx).
create table if not exists public.permission_batches (
    id           uuid primary key default gen_random_uuid(),
    merkle_root  text not null unique,                 -- 0x + 64 hex; the on-chain key
    leaf_count   bigint not null,                      -- leaves under this root (<= cap)
    tx_hash      text,                                 -- Amoy grantBatch tx (null until sent)
    source       text not null default 'dropbox',      -- connector that produced it
    scope        text,                                 -- human note, e.g. '/Founders' folder path
    status       text not null default 'pending'
                 check (status in ('pending','live','revoked','failed')),
    anchored_at  timestamptz,                          -- set when read-back confirms the root
    created_at   timestamptz not null default now()
);
create index if not exists permission_batches_status_idx on public.permission_batches(status);

-- One row per (file, grantee) grant carried in a batch — the proof cache.
-- The proof is the sibling-hash array (0x-hex strings) from leaf to root; the app's
-- download gate replays it through the contract's verifyBatch on the batch fallback.
create table if not exists public.batch_grants (
    id           uuid primary key default gen_random_uuid(),
    batch_id     uuid not null references public.permission_batches(id) on delete cascade,
    merkle_root  text not null,                        -- denormalized for the hot lookup
    file_id      text not null,                        -- pipeline file id (not a node id)
    grantee_id   uuid not null,                        -- profile uuid the grant is for
    leaf         text not null,                        -- 0x keccak(fileHash ++ granteeHash)
    leaf_index   integer not null,                     -- position in the tree (order = commitment)
    proof        jsonb not null,                       -- ["0x..", ...] sibling hashes leaf->root
    created_at   timestamptz not null default now(),
    unique (file_id, grantee_id, merkle_root)          -- idempotent re-runs
);
-- Hot path: "does this grantee have a batch grant to this file?" at download time.
create index if not exists batch_grants_lookup_idx on public.batch_grants(file_id, grantee_id);
create index if not exists batch_grants_batch_idx  on public.batch_grants(batch_id);

alter table public.permission_batches enable row level security;
alter table public.batch_grants       enable row level security;
-- deny-by-default: no policies (service-role only).
