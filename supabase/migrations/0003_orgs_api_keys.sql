-- Organizations + machine API access (Samsyn integration).
--
-- Model:
--   organizations  — a tenant (Xinsere itself, Samsyn, future customers).
--   org_members    — user membership + role within an org.
--   api_keys       — machine credentials. Each key belongs to an org and acts AS
--                    the org's service identity (a real auth user whose profile
--                    uuid is the on-chain owner/grantee for API-stored assets).
--                    Only a SHA-256 hash of the key is stored — never the key.
--
-- Trust model: these tables are written/read exclusively by the backend using
-- the service-role key after it has authenticated the caller (platform-admin
-- session for admin ops; hashed API key for /v1 ops). RLS is therefore
-- deny-by-default (project rule: every table has RLS enabled); the only
-- authenticated-user policy is "a member can see their own memberships".

create table if not exists public.organizations (
    id            uuid primary key default gen_random_uuid(),
    name          text not null,
    slug          text not null unique,
    status        text not null default 'active' check (status in ('active','suspended')),
    -- the org's service identity: owns all nodes stored via the org's API keys
    service_user  uuid references public.profiles(id) on delete restrict,
    created_by    uuid references public.profiles(id),
    created_at    timestamptz not null default now()
);

create table if not exists public.org_members (
    org_id      uuid not null references public.organizations(id) on delete cascade,
    user_id     uuid not null references public.profiles(id) on delete cascade,
    role        text not null default 'member' check (role in ('org_admin','member')),
    created_at  timestamptz not null default now(),
    primary key (org_id, user_id)
);
create index if not exists org_members_user_idx on public.org_members(user_id);

create table if not exists public.api_keys (
    id            uuid primary key default gen_random_uuid(),
    org_id        uuid not null references public.organizations(id) on delete cascade,
    name          text not null,
    prefix        text not null,               -- first chars of the key, for display
    key_hash      text not null unique,        -- sha256 hex of the full key
    scopes        text[] not null default '{files:read,files:write,grants:manage,verify:read}',
    created_by    uuid references public.profiles(id),
    created_at    timestamptz not null default now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
create index if not exists api_keys_org_idx on public.api_keys(org_id);

alter table public.organizations enable row level security;
alter table public.org_members   enable row level security;
alter table public.api_keys      enable row level security;

-- deny-by-default: no policies for organizations / api_keys (service-role only).
-- org_members: a signed-in user may read their own memberships (lets the app
-- show "your organization" without a backend round-trip through service-role).
create policy org_members_select_self on public.org_members
    for select to authenticated using (user_id = auth.uid());
