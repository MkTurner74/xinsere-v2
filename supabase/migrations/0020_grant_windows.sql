-- Grant validity windows (0016-expiry): per-share start + expiry, enforced on-chain.
--
-- 2026-07-20 (next-session backlog item 1, "optional demo add"): a share can now
-- carry a validity WINDOW — a start time (default: now/immediately) and an expiry
-- (default: perpetual). The window is anchored ON-CHAIN per Merkle batch root via
-- XinserePermissions.grantBatchWindowed(root, size, notBefore, notAfter); the
-- contract's verifyBatch fails closed outside [notBefore, notAfter], so a time-boxed
-- share ends with NO revoke tx — the chain simply stops verifying at expiry.
--
-- These columns are the off-chain MIRROR of that on-chain window (unix seconds,
-- 0 = unbounded on that end): permission_batches for audit, shares for the owner
-- UI ("expires Aug 1"). The chain remains the authority — these are display/audit
-- only and are rebuildable from the on-chain grantBatchWindowed events.
--
-- Additive with a 0 (unbounded) default: every existing row keeps its current
-- meaning (perpetual, immediate), and code deployed before this migration simply
-- omits the columns (supa.insert_permission_batch / insert_share degrade to a
-- windowless insert), so the deploy is safe in either order.

alter table public.permission_batches
    add column if not exists not_before bigint not null default 0,
    add column if not exists not_after  bigint not null default 0;

alter table public.shares
    add column if not exists not_before bigint not null default 0,
    add column if not exists not_after  bigint not null default 0;
