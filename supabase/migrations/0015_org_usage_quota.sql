-- Finding 8 (MED): per-tenant (per-ORG) ingest/egress ceilings.
--
-- The 2026-07-12 audit added per-KEY egress quotas (0004). This adds per-ORG
-- ceilings so (a) egress can't be multiplied by minting many keys in one org, and
-- (b) a customer pointing a multi-TB source at a self-serve connector can't run up
-- unbounded S3/KMS/compute cost — there's now a daily ingest ceiling per org.
--
-- Same atomic upsert-and-return as api_key_usage/share_rate. Service-role only.

create table if not exists public.org_usage (
    org_id       uuid   not null references public.organizations(id) on delete cascade,
    win          text   not null check (win in ('day')),
    bucket       text   not null,                 -- 'YYYY-MM-DD' (UTC)
    egress_bytes bigint not null default 0,
    egress_files bigint not null default 0,
    ingest_bytes bigint not null default 0,
    ingest_files bigint not null default 0,
    updated_at   timestamptz not null default now(),
    primary key (org_id, win, bucket)
);
create index if not exists org_usage_bucket_idx on public.org_usage(win, bucket);

alter table public.org_usage enable row level security;
-- deny-by-default: no policies (service-role only).

create or replace function public.xinsere_bump_org_usage(
    p_org_id       uuid,
    p_bucket       text,
    p_egress_bytes bigint default 0,
    p_egress_files bigint default 0,
    p_ingest_bytes bigint default 0,
    p_ingest_files bigint default 0
) returns table (egress_bytes bigint, egress_files bigint, ingest_bytes bigint, ingest_files bigint)
language plpgsql
as $$
begin
    return query
    insert into public.org_usage as u
        (org_id, win, bucket, egress_bytes, egress_files, ingest_bytes, ingest_files, updated_at)
    values (p_org_id, 'day', p_bucket, p_egress_bytes, p_egress_files,
            p_ingest_bytes, p_ingest_files, now())
    on conflict (org_id, win, bucket) do update
        set egress_bytes = u.egress_bytes + excluded.egress_bytes,
            egress_files = u.egress_files + excluded.egress_files,
            ingest_bytes = u.ingest_bytes + excluded.ingest_bytes,
            ingest_files = u.ingest_files + excluded.ingest_files,
            updated_at = now()
    returning u.egress_bytes, u.egress_files, u.ingest_bytes, u.ingest_files;
end;
$$;

revoke all on function public.xinsere_bump_org_usage(uuid, text, bigint, bigint, bigint, bigint)
    from anon, authenticated;
