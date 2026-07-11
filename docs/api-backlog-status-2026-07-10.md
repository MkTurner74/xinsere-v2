# Xinsere API backlog — status after the overnight build (2026-07-10/11)

Maps the first-integration feedback (`feedback-first-integration-2026-07-10.md`)
and the security audit (`security-audit-2026-07-10.md`) to what shipped on branch
`feature/security-audit-and-api-backlog`. Nothing here spends on-chain gas — the
grant/verify/revoke demo beat still waits on wallet funding (morning task).

## Integrator feedback — friction items

| # | Item | Status | Where |
|---|------|--------|-------|
| 1 | Inline-size ambiguity | **Done** | Split `MAX_INLINE_BYTES` (8 MB) vs `MAX_STAGED_BYTES` (500 MB); `max_inline_bytes` now in `GET /v1/ping` and the 413 body |
| 2 | No visibility into chain capacity | **Done** | New `GET /v1/chain/status` — wallet, balance, gas price, `est_grants_remaining`, `wallet_ok` (read-only, no gas) |
| 3 | Grantee `party_id` discovery is human-only | **Done** | New `GET /v1/parties?slug=` → `{slug,name,party_id}` for active orgs (grants:manage) |
| 4 | Error body shape `{detail}` vs `{error}` | **Done** | `RequestValidationError` handler → `{error,errors}`; every status now one shape |
| 5 | Store has no on-chain anchor (`anchor=true`) | **Deferred** | Needs a contract method + gas — design below |
| 6 | Docs behind invite-only sign-in | **Done (flagged off)** | `XINSERE_PUBLIC_DOCS=true` makes the guide public; Swagger/openapi stay gated. Default off preserves current posture until you flip it |
| 7 | No webhooks | **Deferred** | Needs event infra + the grant/revoke path exercised — design below |
| 8 | Reference client isn't packaged | **Done (unpublished)** | `clients/js/` — typed `xinsere-client`, builds clean; publishing is your call |

## What worked well (per the integrator) — unchanged, keep

Small honest surface, `/ping` as identity check, `sha256` at store time, plan-based
retrieval, hash-only keys, clean metadata boundary, the error-contract table. No
regressions to any of these.

## Deferred items — designs (need gas and/or a contract change)

### 5 — `anchor=true` on store (provenance anchor)
Write `sha256 → on-chain event at time T` so integrators can claim "existence +
integrity anchored on-chain", not just "access controlled on-chain" — strengthens
the EU AI Act provenance pitch. **Why deferred:** the current
`XinserePermissions` contract has no anchor method; adding one (e.g.
`anchorFile(bytes32 fileHash)` emitting `FileAnchored(fileHash, timestamp)`) needs
a redeploy (immutable) **and** each anchor spends gas. Ship it as a **priced,
opt-in** flag once the contract is next revised. Keep the store response's
`sha256` as the off-chain claim until then.

### 7 — Webhooks (`grant.confirmed` / `grant.failed`)
Chain writes take seconds; today Samsyn does async fail-closed polling of its own
call. A callback would remove the pending-state UI. **Why deferred:** needs a
delivery mechanism (signed callback + retry/backoff + a dead-letter), and it can't
be exercised end-to-end until the grant/revoke path runs against a funded wallet.
**Design:** register a per-org `webhook_url` + secret; on grant/revoke completion
POST `{event, file_id, party_id, tx, status}` with an HMAC signature header; retry
with backoff; expose delivery status in `/admin`. Build alongside the first real
async-grant customer.

## Infra TODOs from the security audit (not code)

- **Staging lifecycle rule (finding 7):** S3 lifecycle on the `staging/` prefix,
  expire objects after 24–48 h, so an abandoned presigned upload can't linger.
- **Rate limiting (finding 8):** Vercel WAF / gateway throttle on `/api/login` and
  `/v1`. A per-instance in-process limiter is unreliable on serverless.
- **Confirm prod env (findings 1, 2, 9):** `XINSERE_SESSION_SECRET`,
  `XINSERE_TENANT_SALT` (or salt in the tenant secret), `XINSERE_HTTPS_ONLY=true`.
  The new startup validator now refuses to boot without the first two, so this is
  self-enforcing on the next production deploy — **verify these are set before
  merging to the deploy branch.**

## Publishing the client (your decision)

`clients/js` is ready to `npm publish` but intentionally `private: true` and
`UNLICENSED` pending: (a) the npm name (`xinsere-client` vs `@xinsere/client` vs a
Botverse-Secure name), (b) which entity/npm org owns it (Xinsere is a separate
entity from ETI), (c) license choice. Flip `private`, set the name + license, add
`@types/node` only if you want the Node base64 path type-checked, then `npm
publish`.
