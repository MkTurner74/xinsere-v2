-- Security hardening: close the CRITICAL admin-takeover and formalize the
-- Super-Admin tier of the account structure.
--
-- Audit context: research/2026-07-13-signup-migrate-security-audit.md, Finding 1
-- (CRITICAL). Platform-admin status was decided purely by matching a mutable,
-- user-writable column (profiles.email) against XINSERE_ADMIN_EMAILS. The
-- profiles UPDATE RLS policy guarded the row id but NOT which columns change, so
-- any authenticated user could `PATCH profiles.email` to an admin address and
-- self-promote to platform admin. This migration removes that path three ways:
--
--   1. platform_admins  — a durable, service-role-only registry that is the real
--      source of truth for the Super-Admin tier (not a mutable string match).
--   2. email/id immutability trigger — the authenticated role can no longer
--      change profiles.email or profiles.id; only the service-role plane can.
--   3. unique index on lower(email) — two profiles can never collide on email,
--      closing the "claim someone else's admin email" variant.
--
-- Account-structure note: the 3-tier model is
--   Super-Admin (platform_admins)  →  Tenant Admin (org_members.role='org_admin')
--   →  User (org_members.role='member' / node owner). No control-plane role
--   confers file-read; only an owner's on-chain grant does. See the design doc
--   projects/Xinsere/identity-admin-architecture-design.md.

-- ---------------------------------------------------------------------------
-- 1. Super-Admin registry (platform operator = Xinsere staff)
-- ---------------------------------------------------------------------------
create table if not exists public.platform_admins (
    user_id     uuid primary key references public.profiles(id) on delete cascade,
    added_by    uuid references public.profiles(id),
    created_at  timestamptz not null default now()
);

alter table public.platform_admins enable row level security;

-- Deny-by-default: the registry is written and read on the service-role plane
-- (backend admin gate). The ONLY authenticated-user policy lets a signed-in user
-- check whether THEY themselves are an admin — never enumerate the admin set.
drop policy if exists platform_admins_select_self on public.platform_admins;
create policy platform_admins_select_self on public.platform_admins
    for select to authenticated using (user_id = auth.uid());

-- Bootstrap: seed any existing profile whose email is in the historical admin
-- list. Robust across environments — if the profile doesn't exist yet, the
-- backend env-var fallback (XINSERE_ADMIN_EMAILS) still bootstraps the first
-- admin, and that fallback is now SAFE because email became user-immutable below.
insert into public.platform_admins (user_id)
select id from public.profiles
where lower(email) in (
    'mark.turner@entertainmenttechnologists.com',
    'mark.turner@xinsere.com'
)
on conflict (user_id) do nothing;

-- ---------------------------------------------------------------------------
-- 2. Make profiles.email / profiles.id immutable to the authenticated role
--    (email changes must go through a service-role verified flow only)
-- ---------------------------------------------------------------------------
-- NOTE: intentionally NOT security definer — the function must observe the
-- caller's JWT role. PostgREST/GoTrue set the JWT claims GUC regardless, so the
-- role check is reliable. Service-role callers (backend) are exempt so admin
-- flows and verified email changes remain possible.
create or replace function public.enforce_profile_immutable_fields()
returns trigger
language plpgsql
as $$
declare
    jwt_role text := coalesce(
        (nullif(current_setting('request.jwt.claims', true), '')::json ->> 'role'),
        ''
    );
begin
    if jwt_role is distinct from 'service_role' then
        if new.email is distinct from old.email then
            raise exception
                'profiles.email is immutable for role %',
                coalesce(nullif(jwt_role, ''), 'authenticated')
                using errcode = 'insufficient_privilege';
        end if;
        if new.id is distinct from old.id then
            raise exception 'profiles.id is immutable'
                using errcode = 'insufficient_privilege';
        end if;
    end if;
    return new;
end;
$$;

drop trigger if exists trg_profiles_immutable on public.profiles;
create trigger trg_profiles_immutable
    before update on public.profiles
    for each row execute function public.enforce_profile_immutable_fields();

-- ---------------------------------------------------------------------------
-- 3. Email uniqueness (case-insensitive). Emails are already stored lowercased
--    by the app; the functional unique index enforces it at the DB level.
-- ---------------------------------------------------------------------------
create unique index if not exists profiles_email_lower_uidx
    on public.profiles (lower(email));
