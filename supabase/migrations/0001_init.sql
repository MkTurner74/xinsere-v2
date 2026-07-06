-- Xinsere app metadata schema (Supabase / Postgres).
-- Auth is owned by Supabase Auth (auth.users). This schema holds the app layer:
-- user profiles, the folder/file tree, and shares. The pipeline file/fragment
-- index lives in DynamoDB; `nodes.file_id` is an opaque reference to it.
--
-- Authoritative download permission remains the on-chain contract verify() — RLS
-- here governs metadata listing (defense in depth + UI), never the file bytes.
--
-- Every table has RLS enabled (project rule: no table without RLS).

-- ---------------------------------------------------------------------------
-- profiles: one row per auth user. id == auth.uid() == on-chain grantee_id.
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
    id          uuid primary key references auth.users(id) on delete cascade,
    email       text not null,
    name        text not null,
    username    text unique,
    created_at  timestamptz not null default now()
);

-- Auto-create a profile whenever a Supabase Auth user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, email, name, username)
    values (
        new.id,
        new.email,
        coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
        new.raw_user_meta_data->>'username'
    )
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- nodes: folder tree + file nodes. File nodes reference the DynamoDB pipeline
-- record via file_id (+ mirrored sha/size/frags for display).
-- ---------------------------------------------------------------------------
create table if not exists public.nodes (
    id            text primary key,                    -- 'fld_...' / 'fil_...'
    type          text not null check (type in ('folder','file')),
    name          text not null,
    parent        text references public.nodes(id) on delete cascade,
    owner         uuid not null references public.profiles(id) on delete cascade,
    created_at    timestamptz not null default now(),
    -- file-only columns (null for folders)
    file_id       text,            -- DynamoDB pipeline file id
    sha256        text,
    size          bigint,
    frags         integer,
    content_type  text
);
create index if not exists nodes_parent_idx on public.nodes(parent);
create index if not exists nodes_owner_idx  on public.nodes(owner);

-- ---------------------------------------------------------------------------
-- shares: an owner grants a grantee read access to a node (file or folder).
-- tx = the on-chain grant transaction hash (PolygonScan proof).
-- ---------------------------------------------------------------------------
create table if not exists public.shares (
    id          uuid primary key default gen_random_uuid(),
    node_id     text not null references public.nodes(id) on delete cascade,
    grantee     uuid not null references public.profiles(id) on delete cascade,
    tx          text,
    created_at  timestamptz not null default now(),
    unique (node_id, grantee)
);
create index if not exists shares_grantee_idx on public.shares(grantee);
create index if not exists shares_node_idx    on public.shares(node_id);

-- ---------------------------------------------------------------------------
-- has_node_access: does p_uid own, or hold a share on, this node or any ancestor?
-- security definer so it reads nodes/shares WITHOUT triggering the nodes RLS
-- policy that calls it (prevents infinite recursion). Walks parent chain upward.
-- ---------------------------------------------------------------------------
create or replace function public.has_node_access(p_node text, p_uid uuid)
returns boolean
language sql
stable
security definer set search_path = public
as $$
    with recursive chain as (
        select id, parent, owner from public.nodes where id = p_node
        union all
        select n.id, n.parent, n.owner
        from public.nodes n join chain c on n.id = c.parent
    )
    select
        exists (select 1 from chain where owner = p_uid)
        or exists (
            select 1 from public.shares s
            join chain c on s.node_id = c.id
            where s.grantee = p_uid
        );
$$;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.nodes    enable row level security;
alter table public.shares   enable row level security;

-- profiles: any authenticated user can read the directory (needed to pick share
-- recipients); you may only write your own row.
create policy profiles_select_authenticated on public.profiles
    for select to authenticated using (true);
create policy profiles_insert_self on public.profiles
    for insert to authenticated with check (id = auth.uid());
create policy profiles_update_self on public.profiles
    for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- nodes: readable if you own it or have access to it/an ancestor; writable only
-- by the owner. The direct `owner = auth.uid()` disjunct is essential: it lets
-- INSERT ... RETURNING (PostgREST return=representation) succeed for the owner
-- without calling has_node_access(), which re-queries the table and cannot see
-- the row still inside the insert's data-modifying CTE.
create policy nodes_select_access on public.nodes
    for select to authenticated
    using (owner = auth.uid() or public.has_node_access(id, auth.uid()));
create policy nodes_insert_owner on public.nodes
    for insert to authenticated with check (owner = auth.uid());
create policy nodes_update_owner on public.nodes
    for update to authenticated using (owner = auth.uid()) with check (owner = auth.uid());
create policy nodes_delete_owner on public.nodes
    for delete to authenticated using (owner = auth.uid());

-- shares: the grantee can see their grants; the node owner can create/see/revoke.
create policy shares_select_party on public.shares
    for select to authenticated using (
        grantee = auth.uid()
        or exists (select 1 from public.nodes n where n.id = node_id and n.owner = auth.uid())
    );
create policy shares_insert_owner on public.shares
    for insert to authenticated with check (
        exists (select 1 from public.nodes n where n.id = node_id and n.owner = auth.uid())
    );
create policy shares_delete_owner on public.shares
    for delete to authenticated using (
        exists (select 1 from public.nodes n where n.id = node_id and n.owner = auth.uid())
    );
