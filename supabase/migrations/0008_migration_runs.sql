-- Migration run telemetry — powers the Admin import dashboard.
-- One row per connector run (Dropbox now; Box/Google/OneDrive later). The connector
-- heartbeats counters + throughput into this row so the admin UI can show live import
-- progress, per-run integrity (verified/failed), and the cloud-to-cloud performance
-- metrics we quote to clients. The on-chain 1,000-file permission batches render from
-- permission_batches (migration 0007), joined by run.
--
-- Trust model matches the other service-plane tables: service-role only, RLS
-- deny-by-default. The connector writes with the service-role key; the admin API
-- reads with it after the platform-admin gate.

create table if not exists public.migration_runs (
    id            uuid primary key default gen_random_uuid(),
    source        text not null default 'dropbox',   -- connector
    folder        text,                                -- source path migrated
    owner         uuid,                                -- target Xinsere account
    target_root   text,                                -- import root node id
    workers       int  default 1,                      -- concurrency used
    status        text not null default 'running'
                  check (status in ('running','complete','failed')),
    manifest_files int  default 0,
    sourced       int  default 0,
    stored        int  default 0,
    verified      int  default 0,
    skipped       int  default 0,
    failed        int  default 0,
    failures      jsonb not null default '[]'::jsonb,  -- [[path, reason], ...] (capped)
    bytes_in      bigint default 0,
    wall_seconds  numeric default 0,
    mb_per_s      numeric default 0,
    files_per_min numeric default 0,
    started_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now()
);
create index if not exists migration_runs_started_idx on public.migration_runs(started_at desc);
create index if not exists migration_runs_status_idx  on public.migration_runs(status);

alter table public.migration_runs enable row level security;
-- deny-by-default: no policies (service-role only).
