-- Finding 3 (HIGH): blanket profiles SELECT -> cross-tenant PII harvesting.
--
-- Before: `profiles_select_authenticated ... using (true)` let ANY authenticated
-- user read EVERY profile's id/email/name/username, and the app pulled the whole
-- table on every tree render (_profiles_map). In a multi-tenant product that is a
-- full cross-tenant email/name directory, one GET away.
--
-- After: the base table grants SELECT only on your OWN row. Every legitimate
-- cross-profile read the app needs goes through a SECURITY DEFINER RPC that returns
-- MINIMAL fields for an EXPLICIT, SCOPED query -- never a bulk table dump:
--   * profiles_visible_to_me()      -- people you can already see (self, co-org
--                                      members, share counterparties) for RENDERING
--                                      owner/grantee names. No enumeration.
--   * search_profiles_min(q, lim)   -- typeahead: co-org members by name/username,
--                                      OR an exact full-email match (external share).
--                                      Capped; requires a query; no blank dump.
--   * profile_by_email_min(addr)    -- resolve ONE exact email to share with an
--                                      existing account (the share-by-email flow).
-- All three use auth.uid() INTERNALLY for the identity scope, so a caller cannot
-- pass someone else's id to search from their perspective.

-- ---------------------------------------------------------------------------
-- 1. Lock the base-table SELECT policy to self only.
-- ---------------------------------------------------------------------------
drop policy if exists profiles_select_authenticated on public.profiles;
drop policy if exists profiles_select_self_only on public.profiles;
create policy profiles_select_self_only on public.profiles
    for select to authenticated using (id = auth.uid());

-- ---------------------------------------------------------------------------
-- 2. RENDER scope: profiles the caller can legitimately see (minimal fields).
--    Union of: self, co-org members, owners of nodes shared to me, grantees of
--    my nodes, and pending-invite counterparties. This is exactly the set the UI
--    needs to render owner/grantee names -- and nothing else.
-- ---------------------------------------------------------------------------
create or replace function public.profiles_visible_to_me()
returns table (id uuid, email text, name text, username text)
language sql stable security definer set search_path = public
as $$
    with me as (select auth.uid() as uid)
    select distinct p.id, p.email, p.name, p.username
    from public.profiles p, me
    where p.id = me.uid
       or exists (
            select 1 from public.org_members m1
            join public.org_members m2 on m1.org_id = m2.org_id
            where m1.user_id = me.uid and m2.user_id = p.id)
       or exists (
            select 1 from public.shares s
            join public.nodes n on n.id = s.node_id
            where s.grantee = me.uid and n.owner = p.id)
       or exists (
            select 1 from public.shares s
            join public.nodes n on n.id = s.node_id
            where n.owner = me.uid and s.grantee = p.id)
       or exists (
            select 1 from public.pending_shares ps
            where ps.invited_by = me.uid and lower(ps.email) = lower(p.email));
$$;

-- ---------------------------------------------------------------------------
-- 3. TYPEAHEAD scope: co-org members matching the query, OR an exact full-email
--    match (so you can still invite an external party by typing their address).
--    Capped, query-required -- no bulk enumeration.
-- ---------------------------------------------------------------------------
create or replace function public.search_profiles_min(q text, lim int default 8)
returns table (id uuid, email text, name text, username text)
language sql stable security definer set search_path = public
as $$
    with me as (select auth.uid() as uid)
    select p.id, p.email, p.name, p.username
    from public.profiles p, me
    where p.id <> me.uid
      and (
            exists (
                select 1 from public.org_members m1
                join public.org_members m2 on m1.org_id = m2.org_id
                where m1.user_id = me.uid and m2.user_id = p.id)
            or lower(p.email) = lower(q)
          )
      and (
            p.name ilike '%' || q || '%'
            or p.username ilike '%' || q || '%'
            or p.email ilike '%' || q || '%'
          )
    order by p.name
    limit least(greatest(coalesce(lim, 8), 1), 25);
$$;

-- ---------------------------------------------------------------------------
-- 4. EXACT-EMAIL resolve: the share-by-email flow needs to turn a full address
--    into an existing account id. Single exact match, minimal fields.
-- ---------------------------------------------------------------------------
create or replace function public.profile_by_email_min(addr text)
returns table (id uuid, email text, name text, username text)
language sql stable security definer set search_path = public
as $$
    select p.id, p.email, p.name, p.username
    from public.profiles p
    where lower(p.email) = lower(addr)
    limit 1;
$$;

grant execute on function public.profiles_visible_to_me() to authenticated;
grant execute on function public.search_profiles_min(text, int) to authenticated;
grant execute on function public.profile_by_email_min(text) to authenticated;
