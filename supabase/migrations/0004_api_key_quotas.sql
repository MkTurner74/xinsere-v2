-- Per-API-key usage quotas — anti-exfiltration rate + egress limits.
--
-- 2026-07-12 API security audit: a leaked key could enumerate + stream an org's
-- whole tree with no rate or volume ceiling. This adds durable per-key counters so
-- the /v1 edge can throttle request bursts (per-minute) and bulk egress (per-day).
--
-- Counters live in Postgres (already our metadata plane — no new infra). Increment
-- is a single atomic upsert via xinsere_bump_usage() so concurrent serverless
-- invocations can't race a read-modify-write. Buckets are coarse fixed windows
-- (UTC minute for rate, UTC day for egress); a row per (key, window, bucket).
--
-- Trust model matches 0003: service-role only. RLS deny-by-default; the RPC runs
-- SECURITY INVOKER so a non-service caller hits deny-all and cannot write counters.

create table if not exists public.api_key_usage (
    key_id     uuid   not null references public.api_keys(id) on delete cascade,
    win        text   not null check (win in ('minute','day')),  -- 'window' is a reserved word
    bucket     text   not null,                 -- 'YYYY-MM-DD HH:MM' (minute) or 'YYYY-MM-DD' (day)
    requests   bigint not null default 0,
    bytes      bigint not null default 0,
    files      bigint not null default 0,
    updated_at timestamptz not null default now(),
    primary key (key_id, win, bucket)
);
create index if not exists api_key_usage_bucket_idx on public.api_key_usage(win, bucket);

alter table public.api_key_usage enable row level security;
-- deny-by-default: no policies (service-role only, like api_keys).

-- Atomic increment-and-return. One statement, so concurrent callers serialize on
-- the PK and each sees a consistent post-increment total to compare to the limit.
create or replace function public.xinsere_bump_usage(
    p_key_id   uuid,
    p_window   text,
    p_bucket   text,
    p_requests bigint default 0,
    p_bytes    bigint default 0,
    p_files    bigint default 0
) returns table (requests bigint, bytes bigint, files bigint)
language plpgsql
as $$
begin
    return query
    insert into public.api_key_usage as u (key_id, win, bucket, requests, bytes, files, updated_at)
    values (p_key_id, p_window, p_bucket, p_requests, p_bytes, p_files, now())
    on conflict (key_id, win, bucket) do update
        set requests = u.requests + excluded.requests,
            bytes    = u.bytes    + excluded.bytes,
            files    = u.files    + excluded.files,
            updated_at = now()
    returning u.requests, u.bytes, u.files;
end;
$$;

-- Only the backend (service-role) may meter usage.
revoke all on function public.xinsere_bump_usage(uuid, text, text, bigint, bigint, bigint)
    from anon, authenticated;

-- Defense-in-depth: align the DB-level default scopes with the code's new
-- least-privilege default (orgs.DEFAULT_SCOPES). New keys always pass explicit
-- scopes, so this only matters if a key is ever inserted without them.
alter table public.api_keys alter column scopes set default '{files:read,verify:read}';
