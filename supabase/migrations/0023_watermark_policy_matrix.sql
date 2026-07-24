-- Marking-policy matrix (2026-07-23): extends the 0017/0022 org-wide flags
-- into a per-format-class x per-serve-context matrix, plus a per-share
-- "serve unmarked" override.
--
-- watermark_downloads (0017) remains the master kill switch: an org that sets
-- it false still gets NO marking at all, matrix or no matrix. When it's true
-- (the default), watermark_policy governs per format class (video/image/audio
-- master vs distribution, document, other) x per context (preview/download).
-- An org's watermark_policy only needs to list the class/context pairs it
-- wants to DEVIATE from the built-in default (see format_policy.DEFAULT_POLICY
-- in demo/format_policy.py) — an empty/missing entry falls through to that
-- default, so existing orgs need no backfill.
alter table public.organizations
    add column if not exists watermark_policy jsonb not null default '{}'::jsonb;

-- Per-share override: force an unmarked serve regardless of the org matrix —
-- e.g. a legal hold or an internal transfer that must stay bit-perfect.
-- Default false so every existing share keeps today's behavior.
alter table public.shares
    add column if not exists serve_unmarked boolean not null default false;

alter table public.pending_shares
    add column if not exists serve_unmarked boolean not null default false;
