-- Per-tenant contract factory (SaaS tenant isolation).
--
-- Each organization can have its OWN XinserePermissions contract instance, so a
-- tenant's grant/revoke activity lives at its own contract address rather than
-- co-mingled with every other tenant on one shared contract (security audit
-- finding 14; architecture: docs/blockchain-tenancy-architecture.md).
--
-- Backward-compatible + dormant: contract_address is NULL for every existing org,
-- and the chain layer falls back to the shared contract when it is NULL. Turning
-- the feature on is gated by XINSERE_PER_TENANT_CONTRACTS and requires deploying a
-- per-org contract (scripts/deploy_org_contract.py) and backfilling this column.

alter table public.organizations
    add column if not exists contract_address text;   -- 0x… per-org XinserePermissions; NULL = use the shared contract

comment on column public.organizations.contract_address is
    'Per-tenant XinserePermissions contract address (Polygon). NULL = shared platform contract. See docs/per-tenant-contracts.md.';
