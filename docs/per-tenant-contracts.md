# Per-tenant contract factory — status & activation checklist

*Branch `feature/per-tenant-contract-factory`. Addresses security audit finding 14
(on-chain metadata co-mingling). Architecture + rationale:
`docs/blockchain-tenancy-architecture.md`.*

## The idea

Give each organization its **own** `XinserePermissions` contract instance, so a
tenant's grant/revoke activity lives at its own contract address instead of
co-mingled with every other tenant on one shared public page. The rule that keeps
this correct everywhere is: **operate on the file OWNER's contract** — a grantee
verifying or downloading resolves the *owner's* contract, not its own.

## Built in this branch (foundation — safe, dormant)

- **Migration `0004_org_contract_address.sql`** — `organizations.contract_address`
  (nullable; NULL = shared contract).
- **`chain.py` plumbing** — `Chain._contract_for(address)` caches per-tenant contract
  objects; `grant/verify/revoke` take an optional `contract_address` (default = shared
  contract). Fully backward-compatible.
- **`orgs.contract_for_owner(owner)`** — the resolver. Returns the per-org contract for
  a file's owner, or `None`. **Gated by `XINSERE_PER_TENANT_CONTRACTS`** (default off) —
  when off it returns `None` with *no DB hit*, so the hot path is unchanged.
- **`orgs.set_org_contract` / `org_by_service_user`** — read/write helpers.
- **`scripts/deploy_org_contract.py`** — deploys a fresh `XinserePermissions` from the
  platform signer (signer becomes admin, as with the shared contract), records the
  address on the org. Dry-run by default; `--confirm` to deploy. **Spends gas.**

Nothing above changes behaviour: no org has a `contract_address`, the flag is off, and
every call site still passes no address → shared contract. It is a **dormant seam**.

## NOT done — the atomic "turn it on" step (do all of these together)

Threading the resolver through the call sites was deliberately left out so the live
grant path is never half-wired. To activate, in ONE reviewed change:

1. **Thread `orgs.contract_for_owner(node["owner"])` into every chain call**, passing the
   result as `contract_address`:
   - `demo/v1.py`: `grant`, `revoke`, `verify`, and the `_readable_file` on-chain check.
   - `demo/app.py`: `share`, `unshare`, `move` (grant/revoke reconciliation),
     `_grant_inherited`, `_erase_subtree`, `verify_access`, `download`, `download_plan`.
   - Owner resolution is uniform: the file's `owner` uuid → `contract_for_owner`.
2. **Deploy per-org contracts** for the orgs you're migrating
   (`deploy_org_contract.py --confirm`) and confirm `contract_address` is set.
3. **Backfill / re-grant** any *existing* grants that were written to the shared
   contract — they do NOT move automatically. Either re-issue them against the new
   per-org contract, or keep reading the shared contract for pre-migration files (a
   per-file "which contract" marker is the robust version if you need both).
4. **Flip `XINSERE_PER_TENANT_CONTRACTS=true`.**
5. Verify with `scripts/verify_grant.py` against the new contract address.

## Gotchas

- **Existing grants don't migrate.** A file protected + shared before its org had a
  contract has its grant on the *shared* contract; after enabling, lookups target the
  *new* contract and won't find it. Plan the backfill (step 3) before flipping the flag
  for an org with live shares.
- **The signer must be admin of each per-org contract.** `deploy_org_contract.py`
  deploys from the signer, so the signer is the constructor admin — correct. Don't
  deploy these from a different key.
- **Per-org contracts still share one signer address** (all grants come from the
  platform wallet). That removes the shared-*contract* page but not the shared-*sender*.
  Full sender-isolation is the later ERC-4337 paymaster + per-tenant smart-account step
  (see the architecture memo).
