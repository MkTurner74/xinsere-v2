-- 0018: hourly, per-org access-log anchoring (replaces the daily commingled root
-- as the primary seal; access_log_anchors stays for historical daily records).
--
-- Two-level Merkle: each period (UTC hour) gets one root PER ORG over that org's
-- entry_hashes, and one GLOBAL root over the org roots — a single on-chain tx
-- seals every tenant, and each tenant can verify its own audit trail without
-- other tenants' entries (only opaque sibling org-roots appear in a proof).
--
-- `seq` pre-wires dynamic anchoring (Mark, 2026-07-15): today every period is
-- sealed once as seq=0 covering the whole hour [from_ts, to_ts). A future
-- volume trigger ("anchor early when an org crosses N unanchored entries") adds
-- seq=1.. rows covering sub-ranges of the hour — the (period, seq) row records
-- its own ts range so an auditor can always recompute which entries it commits to.
--
-- Orgs with no entries in a period get NO row at all; a fully empty period gets
-- no rows and no tx (nothing to seal, nothing spent).

create table if not exists access_log_anchor_periods (
  period      text not null,               -- UTC hour, e.g. '2026-07-15T14'
  seq         int  not null default 0,
  from_ts     timestamptz not null,
  to_ts       timestamptz not null,
  merkle_root text not null,               -- global root over org-root leaves
  entry_count int  not null,
  org_count   int  not null,
  tx_hash     text,
  anchored_at timestamptz,
  created_at  timestamptz not null default now(),
  primary key (period, seq)
);

create table if not exists access_log_org_roots (
  period      text not null,
  seq         int  not null default 0,
  org_id      text not null,               -- access_log.org_id, or 'platform' for null
  merkle_root text not null,
  entry_count int  not null,
  primary key (period, seq, org_id)
);

-- Backend-only tables (service role): RLS on, no policies = deny-all to clients.
alter table access_log_anchor_periods enable row level security;
alter table access_log_org_roots enable row level security;
