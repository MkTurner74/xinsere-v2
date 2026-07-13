-- Account-security state for the roles/UX build: forced password change, an MFA
-- mirror for admin visibility, and password-rotation tracking.
--
-- Source-of-truth notes:
--   * Email verification lives on auth.users.email_confirmed_at (Supabase) and is
--     enforced at login in code — no column here.
--   * MFA factors live in Supabase Auth (GoTrue /factors). `mfa_enabled` here is a
--     MIRROR the backend maintains on enroll/disable so the admin console can show
--     "2FA on/off" without an admin-API call per user.
--   * must_change_password is app-owned: an admin sets it (force a rotation), the
--     change-password flow clears it.
--
-- Service-role writes; a user may READ their own row (to drive the security UI).

create table if not exists public.account_security (
    user_id               uuid primary key references public.profiles(id) on delete cascade,
    must_change_password  boolean not null default false,
    mfa_enabled           boolean not null default false,
    password_changed_at   timestamptz,
    updated_at            timestamptz not null default now()
);

alter table public.account_security enable row level security;

drop policy if exists account_security_select_self on public.account_security;
create policy account_security_select_self on public.account_security
    for select to authenticated using (user_id = auth.uid());
-- writes are service-role only (deny-by-default: no insert/update/delete policy).
