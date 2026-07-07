-- Soft-delete (Trash) support.
--
-- A node with deleted_at set is "in the Trash": hidden from normal listings,
-- shown in the Trash view, restorable by clearing deleted_at, and eligible for
-- permanent cryptographic erasure once it is >30 days old (auto-purge) or when
-- the owner chooses "Erase". Only the target node gets deleted_at set; its
-- descendants stay untouched and are hidden implicitly (their trashed parent
-- no longer appears in navigation), so restore brings the whole subtree back.
--
-- RLS is unchanged: the existing owner-scoped policies on public.nodes already
-- cover select/update/delete of these columns. Trashed items are hidden from
-- recipients at the application query layer (deleted_at IS NULL filters).

alter table public.nodes add column if not exists deleted_at timestamptz;

-- Fast "my trash" and "expired items to purge" lookups.
create index if not exists nodes_deleted_idx on public.nodes(owner, deleted_at);
