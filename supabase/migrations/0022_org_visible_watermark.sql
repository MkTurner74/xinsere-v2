-- Separate the VISIBLE (pixel-domain) image watermark from the invisible marks.
--
-- 0017's watermark_downloads gates ALL forensic marking (the invisible
-- metadata/content marks that survive file copying — no quality cost). The
-- pixel-domain image mark (Phase 2) is different: it perturbs the picture, so a
-- pro imaging org may reject even a near-invisible change, AND it does not yet
-- survive a real cropped screen grab. So it gets its OWN switch, default OFF —
-- invisible marking stays on; the visible layer is opt-in per organization
-- (2026-07-21, after Mark saw minor artifacts on a flat-background image).
alter table public.organizations
    add column if not exists watermark_pixel_images boolean not null default false;
