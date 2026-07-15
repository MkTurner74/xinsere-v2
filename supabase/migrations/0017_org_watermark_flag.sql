-- Org-level forensic-watermarking override (2026-07-15).
-- Default ON: every non-owner download/preview is marked unless the file
-- owner's organization has explicitly opted out (speed-sensitive tenants).
alter table public.organizations
    add column if not exists watermark_downloads boolean not null default true;
