-- Grant windows for PENDING shares (closes the 0020 gap): an external-email
-- invite (recipient has no account yet) now carries the share's validity window
-- through to materialization.
--
-- Before this, pending_shares had no window columns, so _reconcile_pending
-- materialized every invite as a PERPETUAL grant — silently discarding any
-- start/expiry the owner set in the share dialog. With these columns the stub
-- stores the window and first-login materialization anchors it on-chain via
-- grantBatchWindowed, exactly like a direct share. An invite whose window has
-- already expired by the time the invitee joins is dropped without any grant.
--
-- Same conventions as 0020: unix seconds, 0 = unbounded on that end, additive
-- with a 0 default, deploy-order-safe (supa.insert_pending_share strips the
-- columns and retries once if this migration hasn't been applied yet, so the
-- invite still lands — perpetual — rather than erroring).

alter table public.pending_shares
    add column if not exists not_before bigint not null default 0,
    add column if not exists not_after  bigint not null default 0;
