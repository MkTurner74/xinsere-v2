-- Tamper-evident, per-user access log + daily on-chain Merkle anchor.
--
-- 2026-07-12 API security audit + Mark's requirement: every data access (by an
-- API key OR an interactive user) must be recorded against the INDIVIDUAL acting
-- identity, so a breach or anomaly scopes back to *whose* credentials were used —
-- and the record must be impossible to quietly erase.
--
-- Design: each access writes one append-only row carrying a content hash
-- (entry_hash = sha256 of the canonical event). A daily job builds a Merkle root
-- over that day's entry_hashes and anchors the root on-chain (Polygon). Integrity
-- then rests on the anchored root: you cannot alter or delete any entry from an
-- anchored day without changing the root, which is immutable on-chain — while the
-- per-row content hash stays cheap and race-free at write time (no write-time
-- chaining, so concurrent serverless writes never contend).
--
-- The log is ALSO the export source: rows map to OCSF File Activity so a customer's
-- existing SIEM/UEBA (Purview, Splunk, Sentinel, ...) can consume it as ground
-- truth (build-vs-buy research 2026-07-12: integrate, don't rebuild the analytics).
--
-- Trust model matches 0003/0004: service-role only, RLS deny-by-default. The app
-- only ever INSERTs here — never UPDATE/DELETE (append-only by discipline; the
-- on-chain anchor is the external guarantee).

create table if not exists public.access_log (
    id          uuid primary key default gen_random_uuid(),
    ts          timestamptz not null default now(),
    day         date not null default (now() at time zone 'utc')::date,  -- anchor bucket
    org_id      uuid references public.organizations(id) on delete set null,
    actor_id    uuid not null,                       -- the individual principal (profile uuid)
    actor_type  text not null check (actor_type in ('api_key','user','service')),
    key_id      uuid references public.api_keys(id) on delete set null,   -- which key, if api_key
    action      text not null,                       -- e.g. file.read, file.download_plan, grant, revoke, delete
    file_id     text,                                -- pipeline file id (not a node id)
    node_id     text,
    bytes       bigint not null default 0,
    entry_hash  text not null,                       -- sha256(canonical(event)) hex
    meta        jsonb not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);
create index if not exists access_log_day_idx    on public.access_log(day);
create index if not exists access_log_actor_idx  on public.access_log(actor_id, ts desc);
create index if not exists access_log_key_idx     on public.access_log(key_id, ts desc);

-- One anchored Merkle root per day.
create table if not exists public.access_log_anchors (
    day          date primary key,
    merkle_root  text not null,
    entry_count  bigint not null,
    tx_hash      text,                               -- Polygon anchor tx (null until anchored)
    anchored_at  timestamptz
);

alter table public.access_log         enable row level security;
alter table public.access_log_anchors enable row level security;
-- deny-by-default: no policies (service-role only).
