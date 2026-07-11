# Xinsere Security Audit — machine API (`/v1`) + hosted app

*2026-07-10. Scope: the pre-condition set in the machine-API build note before any
org beyond Samsyn gets a production key — v1 owner-scoping (no RLS backstop), API
key lifecycle, staged uploads, retrieval-plan key exposure, admin CSRF — plus a
full OWASP-style sweep of the FastAPI backend, Supabase RLS, and the on-chain
layer. Auditor: overnight review against commit `79cf279`
(`feature/dpd-backend-and-tests`).*

**Threat model.** The `/v1` plane authenticates an *organization* (Samsyn today,
more later) by a bearer API key and acts as that org's Supabase **service
identity**. Because `/v1` runs on the Supabase **service-role** key, Postgres RLS
is bypassed on this plane — so every `/v1` query must be scoped to the caller's
identity **in Python**. RLS still protects the interactive app plane (user JWT).
The on-chain contract `verify()` is the authoritative download gate; Postgres is
defense-in-depth + listing.

The overriding question for multi-tenant readiness: **can org A ever read, list,
mutate, grant, or infer the existence of org B's assets?**

---

## Findings summary

| # | Severity | Area | Finding | Status |
|---|----------|------|---------|--------|
| 1 | HIGH | Config | Default session-signing secret ships if `XINSERE_SESSION_SECRET` unset | **Fixed** (fail-closed) |
| 2 | HIGH | Crypto/privacy | Default HMAC tenant salt (`dev-tenant-salt-change-me`) can silently back on-chain grantee hashing | **Fixed** (fail-closed) |
| 3 | HIGH | DoS/correctness | Inline `POST /v1/files` accepts up to 500 MB into a 1 GB function (OOM); contradicts "~4 MB" docs | **Fixed** (split caps) |
| 4 | MED | Info leak | On-chain / internal exception text returned to clients; `XINSERE_DEBUG_ERRORS` returns stack traces | **Fixed** (sanitized) |
| 5 | MED | API contract | 422 validation errors return `{detail:[…]}` while all else returns `{error}` | **Fixed** (unified) |
| 6 | MED | Multi-tenant | `/v1` isolation rests entirely on code-level owner checks; no DB backstop, no regression test | **Fixed** (hardened + tests) |
| 7 | MED | Cost/DoS | Orphaned staging objects never cleaned; no lifecycle rule | **Documented** (infra TODO) |
| 8 | MED | Brute-force | No rate limiting on `/v1` auth or `/api/login` | **Documented** (edge/WAF TODO) |
| 9 | MED | CSRF/cookie | `SameSite`/`Secure` cookie attributes implicit; not pinned | **Fixed** (explicit) |
| 10 | LOW | Cost | `/api/warm` unauthenticated (forces heavy client init) | Accepted (no user data) |
| 11 | LOW | Hygiene | Generated one-time passwords returned in JSON bodies | Documented |
| 12 | LOW | Hygiene | `XINSERE_SECRET_ID` default names decommissioned `polygon-mumbai` path | **Fixed** (renamed default) |
| 13 | INFO | Contract | `checkFileExists()` is a hardcoded `true` placeholder | Noted (unused by app) |

No **critical** finding survived review: every `/v1` endpoint was confirmed to
enforce an owner-or-on-chain-grant check before returning or mutating a node
(detail below). The gaps are hardening, fail-closed configuration, and
operability — consistent with the integrator's own read that the design is sound.

---

## Per-endpoint isolation review (`/v1`)

Each `/v1` endpoint verified for cross-tenant safety. `svc` = service-role key
(RLS bypassed); the check column is the Python scoping that substitutes for RLS.

| Endpoint | Scoping check | Verdict |
|----------|---------------|---------|
| `GET /ping` | returns only the caller's own org context | safe |
| `GET /files` | roots at `ensure_root(service_user)`; result filtered `owner == service_user` | safe |
| `POST /files` | writes under caller root, `owner = service_user` | safe |
| `POST /uploads` | staging key namespaced `staging/{service_user}/…` | safe |
| `POST /files/finalize` | rejects key not prefixed with caller's `staging/{uid}/` | safe |
| `GET /files/{id}` | `_readable_file`: owner **or** on-chain `verify()` | safe |
| `GET /files/{id}/content` | `_readable_file` | safe |
| `GET /files/{id}/plan` | `_readable_file`; returns per-fragment data keys (by design) | safe* |
| `DELETE /files/{id}` | `_own_node` (owner only) | safe |
| `POST /files/{id}/grants` | `_own_node`; grantee must be a known profile | safe |
| `DELETE …/grants/{party}` | `_own_node` | safe |
| `GET …/grants` | `_own_node` | safe |
| `GET …/verify` | owner **or** self-grant before revealing; 404 otherwise | safe |

*`/plan` deliberately hands the caller per-fragment AES-GCM data keys after the
permission check — this is the client-side-reassembly contract (plaintext never
transits Xinsere). Keys are the per-fragment data keys only (never the KMS CMK),
returned over TLS, short-TTL URLs, and are **not** logged (`/api/client-log`
truncates and strips signed URLs). Acceptable and by design.

**The residual risk (finding 6) is fragility, not a present hole:** a *future*
endpoint that forgets `_own_node`/`_readable_file` would leak across orgs with no
second line of defense. Remediation below.

---

## Detailed findings & remediation

### 1 — Default session-signing secret (HIGH) — Fixed
`app.py` set `SESSION_SECRET = os.environ.get("XINSERE_SESSION_SECRET",
"xinsere-demo-dev-secret")`. If the env var is ever unset in production, session
cookies are signed with a publicly-known key — an attacker can forge/tamper the
session envelope. (Blast radius is bounded because data calls still carry a real
Supabase JWT that RLS validates, but the integrity of the admin gate and any
future session-trusted field must not depend on an unset env var.)
**Fix:** `config.py::validate_production_config()` raises at startup when
`XINSERE_BACKEND=aws` and the secret is missing/default. Fail-closed: the function
refuses to boot rather than serve with a known secret.

### 2 — Default HMAC tenant salt (HIGH) — Fixed
`chain.py::_tenant_salt()` falls back to the literal `dev-tenant-salt-change-me`
when neither `XINSERE_TENANT_SALT` nor the tenant secret provides one. That salt
is the HMAC key protecting on-chain **grantee identity** (patent Emb. 3 privacy
model) and must match the Node blockchain service for cross-service `verify()`. A
public salt makes grantee hashes computable/enumerable and breaks the privacy
claim. **Fix:** the startup validator refuses to boot in the AWS backend unless a
non-default salt is resolvable (env or tenant secret); the in-function fallback
remains only for local/offline dev.

### 3 — Inline store size (HIGH) — Fixed
`MAX_INLINE_BYTES` (default **500 MB**) governed both the in-memory `POST
/v1/files` body path *and* the staged-finalize path. A 500 MB inline upload is
read wholesale into a 1024 MB Vercel function → OOM; and the docs advertise
"~4 MB", so integrators had to guess (integrator feedback #1). **Fix:** split into
`MAX_INLINE_BYTES` (default **8 MB**, the direct-body path) and
`MAX_STAGED_BYTES` (default 500 MB, the finalize path). The effective inline cap
is now advertised machine-readably in `GET /v1/ping` (`max_inline_bytes`) and in
the `413` body, so clients switch to staged uploads without hardcoding a guess.

### 4 — Exception-text leakage (MED) — Fixed
Grant/revoke/share returned `f"On-chain grant failed: {exc}"` straight to the
client (can expose RPC endpoints, contract internals, Secrets Manager errors), and
`XINSERE_DEBUG_ERRORS=1` returns a stack-trace tail. **Fix:** on-chain failures now
log the full exception server-side and return a stable, generic message + short
code (`chain_grant_failed` / `chain_revoke_failed`). The debug handler is left in
place (it is off unless the env flag is set) but the audit records it **must be
unset in production** and it is now additionally suppressed when
`XINSERE_BACKEND=aws` unless `XINSERE_DEBUG_ERRORS_FORCE=1` is also set.

### 5 — Inconsistent error shape (MED) — Fixed
The app's `HTTPException` handler already normalizes to `{ "error": … }`, but
FastAPI's built-in `RequestValidationError` (422) still emitted `{ "detail":
[…] }` — the shape mismatch the integrator hit (feedback #4). **Fix:** added a
`RequestValidationError` handler returning `{ "error": <first message>, "errors":
[…] }`. One shape across every status now, documented in the guide.

### 6 — `/v1` isolation hardening (MED) — Fixed
Owner scoping is correct today but has no backstop. **Fix (defense-in-depth):**
- `supa.get_owned_node(svc, node_id, owner)` — a PostgREST query that filters
  `owner=eq.{owner}` server-side, so even a logic slip cannot return a foreign
  row. `_own_node` now uses it.
- `tests/test_v1_isolation.py` — TestClient regression tests asserting org A
  cannot read/list/delete/grant on org B's node (all return 404), that scope
  enforcement holds, and that the inline cap is enforced.

### 7 — Orphaned staging objects (MED) — Documented
A presigned PUT that never gets finalized leaves an object under `staging/{uid}/`
forever (cost, and a soft DoS vector). No code fix — the correct control is an
**S3 lifecycle rule** expiring `staging/` after 24–48 h. Captured in
`docs/api-backlog-status-2026-07-10.md` as an infra task; the finalize path
already deletes on success and on over-size.

### 8 — No rate limiting (MED) — Documented
Neither `/v1` (bearer auth) nor `/api/login` (password) is rate-limited. API keys
are 256-bit random so online brute force is infeasible, but login and general
request flooding want an edge control (Vercel WAF / a gateway throttle). A
per-instance in-process limiter is unreliable on serverless, so this is recorded
as an edge/WAF task rather than fragile app code.

### 9 — Cookie attributes (MED) — Fixed
`SessionMiddleware` relied on Starlette defaults (`same_site="lax"`, and `Secure`
only when `XINSERE_HTTPS_ONLY=true`). **Fix:** `same_site="lax"` is now explicit
(admin/app POSTs are same-site `fetch`, so lax is correct and blocks cross-site
form CSRF), and `https_only` defaults to **on** in the AWS backend. No separate
CSRF token is required given SameSite=lax + same-origin fetch + no state-changing
GET.

### 12 — Stale secret-id default (LOW) — Fixed
`XINSERE_SECRET_ID` default renamed from `…/polygon-mumbai/private-key` to
`…/polygon-amoy/private-key` (cosmetic; production overrides it via env).

---

## Gate decision

The three scoped **HIGH** items (session secret, tenant salt, inline cap) are
remediated fail-closed; the multi-tenant isolation concern is hardened with a DB
backstop and regression tests. **Remaining before a third org gets a production
key:**
1. Set the S3 lifecycle rule on `staging/` (finding 7).
2. Add an edge rate-limit on `/api/login` and `/v1` (finding 8).
3. Confirm production env actually sets `XINSERE_SESSION_SECRET`,
   `XINSERE_TENANT_SALT` (or the tenant secret carries the salt), and
   `XINSERE_HTTPS_ONLY=true` — the new validator will refuse to boot otherwise, so
   this is now self-enforcing on the next deploy.

With 1–3 done, the machine API is multi-tenant-ready at demo/early-customer scale.
Load/pen testing and SOC 2 remain separate, later gates (PRD Phase 6).
