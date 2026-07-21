# Session 2026-07-20 — On-chain grant windows + file-management polish

Handoff for running the **deploy + SQL on the Sedona dev PC**. Everything in this
session is committed to `main`; on the dev PC just `git pull --ff-only` first.

This session delivered the PRD "Next in dev" item 1 optional add (**on-chain grant
expiry**, extended to also carry a **start** time) plus four file-manager items
(inline F2 rename, drag-to-move, duplicate-name conflict dialog, deep-nesting
verification). See the code sections at the bottom for the full change list.

---

## ⚠️ Read first — the redeploy is a reset

The contract changed, so this deploys a **new** `XinserePermissions` instance with a
**new address**. Grants anchored on the *old* contract (address
`0xec2aFB351e45568D0B0A7af606e69Bab4db8ee85`) will **stop verifying** until re-shared.
On Amoy testnet for the demo this is acceptable, but it means existing demo shares
need re-sharing after cutover. Nothing auto-migrates.

`grantBatch` (perpetual, immediate) is untouched, so the change is backward
compatible *within* the new contract — only the address change forces the re-share.

---

## Steps to run on the dev PC (in order)

### 0. Pull
```powershell
cd C:\...\xinsere-v2
git pull --ff-only
```

### 1. Recompile the contract
`contracts/bytecode.txt` and `contracts/abi.json` are **stale** — they predate
`grantBatchWindowed`. Regenerate them or the deployed contract won't have the new
function:
```powershell
cd demo
py -m venv .venv                                  # if not already present
.\.venv\Scripts\pip install -r requirements.txt
cd ..\contracts
..\demo\.venv\Scripts\python compile_contract.py  # rewrites bytecode.txt + abi.json
```

### 2. Run the test suite
```powershell
cd ..\demo
.\.venv\Scripts\python -m pytest -q
```
New tests: `tests/test_grant_window.py` (windowed anchor + expiry fail-closed +
future-start activation + `_parse_window`), `tests/test_name_conflict.py`
(`_suffix_name` / `_resolve_name` / `ensure_path` deep-nesting). Two existing fakes
(`test_batch_grant.py`, `test_view_permission.py`) were updated for the new
`insert_permission_batch(..., not_before, not_after)` signature.

### 3. Deploy the new contract to Amoy
Needs AWS creds (the signer key in Secrets Manager) + POL for gas on the signer
wallet. This mints a fresh instance and proves the batch path live:
```powershell
cd ..\contracts
..\demo\.venv\Scripts\python deploy_to_amoy.py    # prints the NEW contract address
```
Then point the app at it — set the env var wherever the app reads config
(Vercel/Render dashboard for prod, or local shell for a local run):
```
XINSERE_CONTRACT_ADDRESS = <new address printed above>
```

### 4. Apply the Supabase migration
Run `supabase/migrations/0020_grant_windows.sql` against the project (Supabase SQL
editor or the migration runner). It's additive with a `0` (unbounded) default and
deploy-order-safe — the app degrades to perpetual shares if it hasn't been applied
yet, so applying it before OR after the code deploy is fine.

```sql
-- 0020_grant_windows.sql (full text in supabase/migrations/)
alter table public.permission_batches
    add column if not exists not_before bigint not null default 0,
    add column if not exists not_after  bigint not null default 0;
alter table public.shares
    add column if not exists not_before bigint not null default 0,
    add column if not exists not_after  bigint not null default 0;
```

### 5. End-to-end smoke test (the fun part)
1. Share a file with a test recipient, open **Access window**, set **Expires** ~2
   minutes out. Confirm the recipient can download.
2. Wait past the expiry. The recipient's download now fails closed — **no revoke tx
   was sent**; `verifyBatch` simply returns false past `notAfter`. That's the whole
   feature.
3. Optionally set a **Starts** a couple minutes in the future and confirm the grant
   is denied until it opens, then works.

---

## Deploy-order safety (no coordination required)

Both the code and the DB migration are written to tolerate either order:
- **Code before SQL:** `supa.insert_permission_batch` / `insert_share` send the
  window columns only when a bound is set, and strip-and-retry once if the columns
  are absent — so shares still work, just perpetual, until 0020 lands.
- **Contract before env cutover:** the app keeps using the old address until
  `XINSERE_CONTRACT_ADDRESS` is updated; windowed shares only exist once both the
  new contract is live AND the env points at it.

---

## Change list (all committed to `main`)

**On-chain grant window (start + expiry, enforced on-chain):**
- `contracts/XinserePermissions.sol` — `rootNotBefore`/`rootNotAfter`,
  `grantBatchWindowed()`, `BatchPermissionWindowed` event, window checks in
  `verifyBatch`; `grantBatch` unchanged (perpetual).
- `demo/chain.py` — ABI + `grant_batch_windowed()` + `root_window()`.
- `demo/batch_grant.py` — window threaded through `preserve()`; window-aware
  read-back gate (future start validates the proof off-chain, still goes `live`).
- `demo/share_grants.py` — `grant_share(..., not_before, not_after)`.
- `demo/supa.py` — `insert_permission_batch` / `insert_share` store the window
  (deploy-order-safe fallbacks); `ensure_path` depth guard + `.`/`..` stripping.
- `demo/app.py` — `/api/share` `starts_at`/`expires_at` params + `_parse_window()`.
- `demo/frontend/index.html` — Share dialog "Access window" (start/expiry inputs,
  posts epoch seconds).
- `supabase/migrations/0020_grant_windows.sql`.

**File-management polish:**
- Inline F2 rename (edit-in-place; kebab "Rename" and F2 key; extension lock kept).
- Drag-to-move (draggable owned items → folder tiles/rows + breadcrumb ancestors;
  multi-select drags together; OS-file upload drop still works).
- Duplicate-name conflict, **Keep both / Cancel** (no destructive Replace):
  `_resolve_name` backend check + 409 on `/api/rename` `/api/move` `/api/folder`;
  move-into-a-folder-with-a-name-clash covered.
- Deep-nesting: `ensure_path` idempotent folder reuse + depth cap (`MAX_PATH_DEPTH`)
  → 400; tests.

**Known follow-up:** a *pending* email invite (recipient has no account yet)
materializes **perpetual** — `pending_shares` has no window column. Typeahead
grantees and existing-account emails are fully windowed. Add a window column to
`pending_shares` + thread it through `_reconcile_pending` when this matters.
