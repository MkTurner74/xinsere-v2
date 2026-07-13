-- Finding 2 completion (HIGH): grant-rate cap for interactive shares.
--
-- The batch path (migration 0011) already collapsed a folder share from one
-- on-chain tx PER FILE to <=1 flat-gas tx per 1,000 files, which closes the
-- headline denial-of-wallet vector. This adds the audit's SECONDARY control — a
-- per-USER share-action rate cap — so a compromised/abusive interactive account
-- cannot drain the shared gas wallet by firing many share actions in a loop.
-- (The complementary low-balance pre-flight guard lives in the app, and the
-- per-tenant wallet is the longer-term item in the tenancy memo.)
--
-- Mirrors the api_key_usage design (migration 0004) but keyed by user_id, since
-- interactive callers are session-authenticated users, not API keys. Same atomic
-- upsert-and-return so concurrent serverless invocations can't race the counter.
-- Service-role only (RLS deny-by-default); the RPC is revoked from anon/authenticated.

create table if not exists public.share_rate_usage (
    user_id    uuid   not null references public.profiles(id) on delete cascade,
    win        text   not null check (win in ('minute','day')),
    bucket     text   not null,                 -- 'YYYY-MM-DD HH:MM' (minute) or 'YYYY-MM-DD' (day)
    count      bigint not null default 0,
    updated_at timestamptz not null default now(),
    primary key (user_id, win, bucket)
);
create index if not exists share_rate_usage_bucket_idx on public.share_rate_usage(win, bucket);

alter table public.share_rate_usage enable row level security;
-- deny-by-default: no policies (service-role only).

create or replace function public.xinsere_bump_share_rate(
    p_user_id uuid,
    p_window  text,
    p_bucket  text,
    p_count   bigint default 1
) returns table (count bigint)
language plpgsql
as $$
begin
    return query
    insert into public.share_rate_usage as u (user_id, win, bucket, count, updated_at)
    values (p_user_id, p_window, p_bucket, p_count, now())
    on conflict (user_id, win, bucket) do update
        set count = u.count + excluded.count,
            updated_at = now()
    returning u.count;
end;
$$;

-- Only the backend (service-role) may meter share rate.
revoke all on function public.xinsere_bump_share_rate(uuid, text, text, bigint)
    from anon, authenticated;
