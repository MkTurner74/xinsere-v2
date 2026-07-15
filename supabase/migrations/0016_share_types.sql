-- Share types: view-only vs download (vs future co-owner).
--
-- 2026-07-14 (next-session backlog item c): a share can now carry a permission
-- LEVEL. `view` = render in the browser via the server-mediated preview path
-- only — no /api/download, no /api/download-plan (which hands the client the
-- per-fragment data keys). `download` = today's behavior (view + download).
-- `co-owner` is reserved in the CHECK for the future re-share tier but is not
-- yet accepted by the API.
--
-- On-chain binding: a typed grant's Merkle leaf commits to the type —
--   leaf = keccak(fileHash ++ granteeHash ++ keccak(type))   (type != download)
-- while download grants keep the legacy 2-part leaf (backwards compatible with
-- every root already anchored). The download gate recomputes the expected leaf
-- from the CLAIMED type before replaying the proof, so flipping grant_type in
-- the DB breaks the proof and fails closed — the type is chain-anchored without
-- a contract change.
--
-- All three tables are additive with a 'download' default: every existing row
-- keeps exactly its current meaning.

alter table public.shares
    add column if not exists share_type text not null default 'download'
    check (share_type in ('view', 'download', 'co-owner'));

alter table public.pending_shares
    add column if not exists share_type text not null default 'download'
    check (share_type in ('view', 'download', 'co-owner'));

alter table public.batch_grants
    add column if not exists grant_type text not null default 'download'
    check (grant_type in ('view', 'download', 'co-owner'));
