-- Pending share invitations — external-email sharing + viral onboarding.
--
-- Sharing to an email that has no Xinsere account yet creates a PENDING stub here
-- instead of an on-chain grant. When that person signs up (first login), the
-- reconciliation step materializes the real shares + on-chain grants, so the files
-- "appear" for them. Executing the grant at signup (not at invite) means no gas is
-- spent on invites that never convert, and there's no on-chain identity to rebind.
--
-- Trust model: service-role only (RLS deny-by-default). Reconciliation runs
-- server-side at login with the service-role key.

create table if not exists public.pending_shares (
    id          uuid primary key default gen_random_uuid(),
    node_id     text not null references public.nodes(id) on delete cascade,  -- nodes.id is text
    email       text not null,                       -- lowercased at write time
    invited_by  uuid not null references public.profiles(id) on delete cascade,
    created_at  timestamptz not null default now(),
    unique (node_id, email)                          -- one pending invite per (item, email)
);
create index if not exists pending_shares_email_idx on public.pending_shares(email);

alter table public.pending_shares enable row level security;
-- deny-by-default: no policies (service-role only).
