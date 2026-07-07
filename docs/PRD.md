# Xinsere — Product Redesign
## Serverless API + MCP Service, Botverse Edition

**Version:** 0.3  
**Date:** 2026-05-14 (implementation status added 2026-07-06)  
**Status:** In build — core DPD pipeline, blockchain permissions, and a working demo are implemented and tested. See Implementation Status below.

---

## Implementation Status — 2026-07-07

The DPD core is built and tested, the hosted demo is **live in production on real
AWS infrastructure** (https://xinsere-v2.vercel.app), and the flagship download
path is now **client-side reassembly** — plaintext never exists on the server.

### Major revision 2026-07-07 — production hardening + client-side reassembly
- **Client-side reassembly SHIPPED (server-as-oracle).** `GET /api/download-plan`
  issues presigned per-fragment URLs + unwrapped data keys post-permission-check;
  the browser fetches fragments straight from S3 in parallel, decrypts with
  WebCrypto AES-256-GCM, joins, and verifies whole-file SHA-256. Reusable module
  `demo/frontend/xinsere-client.js` (seed of the JS SDK / MCP client). Server-side
  retrieve() remains automatic fallback. 176MB file: verified fast, bit-perfect.
- **Resilient transfers.** Per-fragment retry w/ exponential backoff, HTTP Range
  resume from last byte, short-read detection (early EOF ≠ success), partial-byte
  preservation across error retries. Upload PUT retries 3x. Client failures are
  never silent: visible failover + diagnostics POSTed to `/api/client-log`.
- **Fragment pool tripled: 21 → 60 buckets** (12 per region × use1/use2/usw1/
  usw2/cac1), all private + SSE-S3. Every region can now hold a full 7-fragment
  file (region-scoped-write prerequisite). AWS quota 10k — scales to 500+.
- **Regional S3 endpoints pinned everywhere** — the global endpoint 307-redirects
  for <24h-old buckets with no CORS headers (browser-fatal). Also: all presigned
  URLs SigV4 (SigV2 signed Content-Type into PUTs, 403ing document uploads).
- **Retrieve fan-out uncapped** (was min(frags, cpu_count) → 2 workers on
  serverless; now one thread/fragment). 184MB reassembles in ~2.6s server-side.
- **Per-stage timing instrumentation** — index/S3/KMS/AES/join/verify breakdown
  logged per retrieve + `X-Retrieve-Timing` response header.
- **Cold-start work**: lazy boto3/web3 imports, `/api/warm` endpoint, keep-warm
  GitHub Action (activates on merge to main).
- **UX**: per-operation task stack (concurrent transfers each get their own
  status line + progress bar), fixed-width busy buttons, on-chain grant gate on
  shared files' Download button (disabled until verify() reads the grant).

### Built & tested
- **Smart contract** — `XinserePermissions` deployed to **Polygon Amoy** testnet:
  `0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD`. grant / revoke / verify / audit +
  immutable events. (Mumbai was decommissioned; switched to Amoy.)
- **Blockchain permission service** — `lambdas/blockchain` (Node/TS + ethers).
  Wallet from Secrets Manager; Amoy ≥25 gwei gas floor. **Chain test 14/14.**
- **File-fragment pipeline** — `lambdas/pipeline` (Python). Strip metadata →
  SHA-256 → split N → per-fragment **AES-256-GCM** → scatter → index. **Pluggable
  backends** (local for test; S3/KMS/DynamoDB written, untested pending infra).
  **Parallelized** (ThreadPoolExecutor over fragments). **Test matrix 18/18.**
- **End-to-end integrity** — whole-file SHA-256 checked pre-encryption and
  post-reassembly (bit-perfect or fail-closed); per-fragment GCM tamper detection.
- **Working demo** — `demo/` (FastAPI). File-explorer UI, drag-drop upload,
  folders, **real accounts** (signup/login), share → **real on-chain grant**,
  download gated by on-chain **verify()**. Deploy-ready (Dockerfile + render.yaml).
- **Benchmarks** — `demo/benchmark.py`. Pipeline ~360–450 MB/s (to 1 GB); Amoy
  read ~0.7 s, write ~1.2 s. See `projects/Xinsere/benchmark-results.md` (Docs repo).

### Divergences from the target architecture (design intent, not yet built)
- ~~**Storage:** demo uses local pipeline backends~~ **RESOLVED 2026-07-07**: the
  hosted demo runs the real AWS backends in production — S3 (60-bucket scatter),
  KMS envelope keys, DynamoDB index.
- **Network:** Amoy testnet, not Polygon PoS mainnet.
- **Auth:** demo uses email/password (Supabase), not federated OIDC/SAML.
- **Permissions:** demo verifies direct-from-chain; the fail-closed local cache
  (Emb. 4 of the CIP) is not built.
- **Routing randomness:** modular routing places a file's fragments in
  CONSECUTIVE buckets (jitter only shifts the start) — observed in prod
  (video.mp4 → usw2-01..07). Fine for the demo; for the "fragments could be
  anywhere" story the router should draw truly random distinct buckets per file.
- **Upload resume:** staging PUT is whole-file retry; S3 multipart (chunk-level
  resume) not yet built. Download-side resume is done.
- Not built: size-based Lambda/Fargate routing, malware scan, multi-tenant CMK
  isolation, MCP server, forensic watermarking, region-scoped write.

### Next in dev (priority order)
1. **Finish security cleanup (Phase 0).** `AKIAQ3EGU6BLQUWCCQGV` (Mark's acct
   058264449111) deactivated 2026-07-05. The other two (`AKIARX7FHY4OVVELQM4Z`,
   `AKIARX7FHY4OQKZ2FLDY`) belong to **Max's account 120202970909** (0 events in
   Mark's acct) — **Max must** deactivate/delete + scrub the POC repo/history.
   *Optional demo add:* wire on-chain permission **expiry** (contract already
   supports `expiryTime`; demo hardcodes 0) — end-dated grants, no revoke needed.
2. ~~Deploy the hosted demo (v2)~~ **DONE 2026-07-06/07** — live at
   xinsere-v2.vercel.app on real AWS backends, invite-only auth.
3. ~~Revoke + delete (paired)~~ **DONE 2026-07-07** — on-chain revoke (unshare,
   fails closed, verify-first so retries never brick) + delete (revoke grants →
   pipeline cryptographic erasure → metadata cascade). Chain-consistency review
   applied: receipt-status checking (reverted tx ≠ success), no-existence-oracle
   on all endpoints.
4. **File-manager basics** — move/rename/grant-on-add **DONE 2026-07-07**
   (move reconciles inherited shares on-chain both directions; rename is
   display-only by design; late-added files in shared folders now get grants).
   Remaining: **download-folder-as-zip** (client-side reassemble + zip),
   deep-nesting verification on upload, and the UX upgrades from the research
   doc (`projects/Xinsere/research/2026-07-07-file-explorer-ux-best-practices.md`
   in the Docs repo): trash/soft-delete with undo-toast instead of confirm
   dialogs, inline F2 rename, multi-select, list/grid toggle, conflict dialog.
5. **Proper authentication.** Move the demo off invite-only email/password:
   Supabase Auth with email verification + password reset (Resend), OAuth
   (Google/Microsoft) sign-in, session hardening. Enterprise SSO (OIDC/SAML)
   stays a Phase 3+ item.
6. **Host on xinsere.com.** Move the demo SaaS off xinsere-v2.vercel.app to
   xinsere.com (or app.xinsere.com) — custom domain on Vercel, TLS, update S3
   CORS origins + Supabase auth redirect URLs. Makes it pitchable as the product.
7. **True-random fragment routing.** Modular routing yields consecutive buckets
   (see Divergences) — draw N distinct random buckets per file so the scatter
   pattern is genuinely unpredictable. Small change, big story value.
8. **Upload resume via S3 multipart** (chunk-level, matches the download-side
   resilience already shipped); then client-side fragment+encrypt on upload
   (MediaShippers pattern) so plaintext never touches the server on upload either.
9. **Multi-cloud research (Google dev budget available).** Scope adding GCS as a
   second fragment store: the ObjectStore interface is already pluggable, GCS has
   S3-interoperability mode (HMAC keys + S3-compatible XML API) that may work with
   the existing boto3 path, and V4 signed URLs + CORS support the client-side
   reassembly model. Cross-CLOUD scatter (some fragments AWS, some GCS) means a
   breach of one cloud provider yields only partial fragments — strongest version
   of the hybrid story, and the "fragments could be anywhere" haystack spans
   providers. Deliverable: a research memo + a spike (store/retrieve a file with
   fragments split across AWS+GCS using Google's dev credits).
10. **MCP server** (`@xinsere/mcp`) — the AI-agent product surface (see mcp-spec);
   reuses the retrieval-plan API + xinsere-client logic.
11. **Region-scoped write (data residency).** API-selectable write region; default
   scatters wide. Region-locked *and* randomized — the EU/Germany play. Bucket
   prerequisite met 2026-07-07. See *Planned capability: region-scoped write*.
12. **Deeper patent differentiators:** fail-closed revocation cache, federated
   identity (OIDC/SAML), size-based large-file routing, forensic watermarking —
   and once watermarking lands, the **forensic file-history tool** (admin-only
   "what happened to this file" — decode + verify + provenance timeline; see
   *Planned capability: forensic file-history tool*). We ship the reference
   reader ourselves; it's the proof point of the whole forensic story.
13. **Housekeeping:** fund Amoy signer wallet (grants ~0.015 POL each; Google
   Cloud Web3 faucet); ~~merge branch to main~~ done 2026-07-07 (keep-warm cron
   active); revert XINSERE_DEBUG_ERRORS handler when demo phase ends.

### Planned capability: temporal access windows (timed shares & embargo release)

Permissions carry a time window `[active_from, expiry]`, enforced on-chain against
the block timestamp:

- **Expiry / end date — already in the contract.** `verify()` returns false once
  `block.timestamp > expiryTime` (0 = no expiry); an expired grant self-denies with
  no revoke transaction. (Demo currently passes 0; wiring a date picker is small.)
- **Activation / start time (`not_before`) — to add.** Requires an `active_from`
  field on the `PermissionRecord` struct and a `block.timestamp >= active_from`
  check in `verify()`, then a contract redeploy (immutable).

**Why it matters — synchronized embargo release.** Pre-stage N encrypted documents
and pre-grant access to M recipients, every grant carrying the same `active_from =
T_release`. The fragments sit fully distributed but cryptographically inaccessible;
at `T_release` all M recipients gain access to all N documents **simultaneously**,
with no action at release time and no possibility of early access — enforced by the
ledger, not by the operator withholding data. Target use cases: film/media releases,
press embargoes, financial/regulatory disclosures, simultaneous multi-party reveals.
(Covered by CIP patent Embodiment 10 / Claims 60–64.)

### Planned capability: region-scoped write (data residency + randomized scatter)

Data residency as a **first-class API feature**, not a deployment mode. The caller
chooses where a file's fragments are written; the security model (per-fragment keys,
opaque `{uuid}_{sequence}` object names, no file linkage, N-of-M scatter) is
unchanged — the fragments are still randomized, just within a chosen geography.

- **API-selectable region on write.** `POST /v1/files` takes an optional `region`
  (or `residency`) parameter. Specify `eu-central-1` and every fragment for that
  file is scattered across buckets **in that region only**.
- **Default = scatter wide.** Omit the parameter and fragments spread across the
  full North America pool (current behavior) — maximum dispersion for users who
  don't have a residency constraint.
- **Region-locked *and* randomized — the differentiator.** Jurisdictions like
  Germany/the EU require data to stay in-region, but still want the randomized,
  fragment-level security. Competing "keep it in-region" offerings just pin a
  single bucket; Xinsere keeps the file scattered across many in-region buckets, so
  residency compliance costs nothing in security. (Also gives a latency win — a
  single-region file avoids cross-region fragment reads.)

**What it needs (not yet built — capturing intent):**
- A **region-pinned routing mode** in the fragmenter: given a target region, pick
  `N` buckets from that region's pool (`route()` already handles arbitrary bucket
  lists; add region filtering).
- A **per-file region field** on the file index record so `retrieve()`/audit know
  the residency (retrieve already resolves per-fragment buckets, so no read-path
  change is strictly required — the field is for policy/reporting/enforcement).
- **Prerequisite met (2026-07-07):** every region now has ≥ `N` buckets (pool
  expanded to 12/region × 5 regions), so any region can hold a full 7-fragment
  file without spilling cross-region. Scaling to more regions/clouds = create
  buckets + register them; the AWS bucket quota is 10,000.
- API schema, validation (region allow-list per account/plan), and enforcement
  (reject a residency-locked account writing out-of-region) to be designed in the
  Phase 3 REST API work.

Ties directly to **Market B — data sovereignty** (below) and Deployment Mode 3
(BYOB), but works even in pure SaaS mode.

### Planned capability: forensic file-history tool ("what happened to this file")

An admin-only tool that takes any candidate file and produces a plain-English,
evidence-grade account of its history — the productization of the patent's
forensic extraction endpoint (Emb. 8) and the delivery-digest verifications
(proposed Claims 53A–C). Third parties could build a reader against the API, but
this capability IS the product's proof point — we ship the reference tool
ourselves and make it part of the pitch/demo.

**What it does.** Upload (or point at) a file →
1. **Decode** the watermark across all encoding channels (metadata part, covert
   micro-variation/spread-spectrum channels) and report channel survival.
2. **Verify** — three server-side checks: delivery-digest comparison
   (bit-identical-as-delivered vs modified-after-delivery), watermark
   authenticity by HMAC recomputation with the signing key (genuine vs
   forged/transplanted), and tamper characterisation from the channel-survival
   pattern (metadata stripped / re-encoded / content edited).
3. **Reconstruct provenance** — join the retrieval log entry with the on-chain
   permission trail (grant → verify → retrieval → any revocation) and the file's
   write-time record.
4. **Explain** — render a timeline in plain language: *"Stored by A on date X
   (SHA-256 …). Shared with B on date Y (tx 0x…). Downloaded by B on date Z from
   IP …. This copy is bit-identical to that delivery"* — or *"…was modified
   after delivery; the surviving channels indicate content editing."* Exportable
   as a signed PDF report for legal/HR use.

**Access control (critical):** admin-level users only, per tenant — the tool
reveals retrieval history and party identifiers, so it must sit behind the same
admin gating as user provisioning (and real identity resolution still requires
the tenant secret, per Emb. 3 privacy model). Every forensic query is itself
audit-logged (who investigated what, when).

**Build shape:** an API endpoint (`POST /v1/forensics/examine`) + an admin UI
page in the file explorer; the LLM-friendly "explain" layer also becomes an MCP
tool so an authorized agent can answer "what happened to this file?" directly.

### Planned capability: client-side reassembly (server-as-oracle) — demo v1 SHIPPED 2026-07-07

The server never assembles plaintext. After the permission check, it issues a
**retrieval plan** — per-fragment presigned GET URLs + unwrapped per-fragment data
keys/nonces (never the CMK) — and the client fetches fragments straight from
storage, decrypts locally (WebCrypto AES-256-GCM), joins, and verifies the
whole-file SHA-256. Server-side retrieve() remains the fallback.

- **Security:** plaintext never exists on operator infrastructure — completes the
  "even Xinsere cannot read your files" proposition end-to-end. Client receives
  only its own file's data keys, post-authorization, over TLS, short-TTL URLs.
- **Performance:** removes the double hop (S3→function→client) and the serverless
  memory/time ceiling; fragments land in parallel from their home regions.
- **Resilience (REQUIRED for all client-side transfer code, upload & download):**
  broken transfers must self-heal — per-fragment retry with exponential backoff,
  HTTP Range resume from the last received byte, and seamless continuation after
  network loss. Fragments are independent GCM-authenticated units, so recovery
  re-fetches only what's missing and corruption cannot pass unnoticed.
  - *Download:* shipped in the demo client (`xinsere-client.js`).
  - *Upload (to build):* staging PUT is currently single-shot retry-whole-file;
    move to S3 multipart upload for chunk-level resume, and eventually client-side
    fragment+encrypt on upload (the MediaShippers pattern) so uploads get the same
    fragment-level resume as downloads.
- **Reuse path:** the demo module (`demo/frontend/xinsere-client.js`, framework-
  free) is the seed for the JS SDK; the MCP client and the future desktop/file-
  explorer agent (mount Xinsere as a drive) use the same plan API.
- **Rollout:** web app (shipped, demo) → JS SDK → MCP client → browser extension /
  desktop agent as the premium tier.

---

## Why redesign

The existing codebase (Chrome extension + Python native host) was built to solve a specific problem: large file transport for MediaShippers, where browser upload limits (2GB) and Lambda timeouts made server-side fragmentation impractical. The local client fragments the file, calls the Lambdas for bucket locations, then uploads each fragment directly to S3 in parallel — bypassing both limits and saving AWS compute costs.

That architecture is the right solution for large M&E files. It is the wrong architecture for:
- A hosted API / MCP service
- Files sized for typical AI agent workflows (documents, images, clips — not 50GB film masters)
- Multi-tenant SaaS with API key auth

This design is a clean serverless rebuild for the API/MCP product. The existing Python fragmentation and encryption logic is the source of truth for the core algorithm — it gets extracted, hardened, and ported to Lambda.

---

## The three security propositions

These are not features — they are the product's reason to exist. Every architecture decision should serve at least one of these.

### 1. Quantum resistance through fragment-level AES-256

AES-256 is already considered quantum-resistant (Grover's algorithm reduces its effective security to AES-128, which remains computationally infeasible to break). Xinsere adds a multiplicative layer:

- Each fragment is encrypted with its own independent KMS data key
- An attacker who wants to reconstruct a file must obtain **all N fragments** from **N different storage locations** AND break AES-256 on **each fragment independently**
- Fragment reassembly order is stored only in DynamoDB (encrypted at rest with a separate key)
- Without the fragment index, even possessing all fragments does not allow reconstruction

**The pitch:** "Today's quantum computers can't break AES-256. Tomorrow's might be able to break one. They still can't break N simultaneously."

### 2. No single root authority — even Xinsere cannot read your files

Standard AWS S3 server-side encryption has a fundamental trust problem: AWS holds the root key. A subpoena, a national security letter, a compromised AWS root admin, or a future regulatory change can force decryption of any file on any S3 bucket.

Xinsere's model removes that attack surface:

- Encryption keys are **customer-managed CMKs** in **the customer's own AWS KMS**
- Xinsere's Lambda functions request data keys from the customer's KMS at upload time — they use the plaintext key momentarily in memory to encrypt, then discard it
- Xinsere never stores, logs, or retains plaintext keys
- Even if Xinsere's entire infrastructure is compromised, the attacker gets encrypted fragments they cannot decrypt without the customer's KMS keys

**In hybrid deployment mode** (fragments split across customer's AWS + Xinsere's AWS):
- An attacker must compromise two independent AWS accounts simultaneously
- Subpoena served to Xinsere yields only partial fragments — not enough to reconstruct the file
- Subpoena served to the customer's AWS account yields the other partial fragments — but those are useless without Xinsere's portion

**The pitch:** "AWS can't read your files. Xinsere can't read your files. Even a court order served to one party gives the petitioner nothing usable."

### 3. Blockchain-immutable permission trail

Permissions (who can access what, when granted, when revoked) are written to a blockchain as immutable, timestamped transactions. This creates an audit trail that:

- Cannot be altered retroactively — not by Xinsere, not by the customer, not by AWS
- Can be verified by a third party (regulator, auditor, opposing counsel, rights holder) without file access
- Provides cryptographic proof of chain of custody

**The pitch:** "Prove to a regulator that a file was shared with exactly these parties on exactly these dates — without opening the file. Proof that neither Xinsere nor the customer could have fabricated retroactively."

---

## Target markets

### Market A — AWS customers who want genuine file-level security

The problem with AWS S3 default encryption: customers trust AWS. Xinsere's customer-managed CMK + fragmentation model removes that trust requirement.

**Entry point:** AWS Marketplace listing. Sells to existing AWS users as an add-on security layer — no new cloud account, no infrastructure migration. "Your S3 buckets. Your KMS keys. Xinsere handles the fragmentation and distribution layer."

**Buyers:** DevOps/security teams at companies handling regulated data (healthcare, legal, financial, HR records).

### Market B — Cloud and IT teams needing data sovereignty

Enterprises subject to cross-border data regulations (GDPR, data localisation laws) or operating in jurisdictions where cloud providers cannot guarantee data sovereignty.

**Entry point:** Direct sales or partnership with cloud resellers/MSPs. Hybrid or customer-hosted deployment.

**Buyers:** CISOs, cloud architects, compliance teams at regulated enterprises.

### Market C — AI agent developers (the Botverse market)

AI agents increasingly handle sensitive documents: legal discovery, patient records, financial filings, contracts. These agents need secure storage and provable permission management — not S3 buckets.

**Entry point:** MCP server published to the MCP registry. Developers add Xinsere Secure to their agent config the same way they'd add any tool. Per-operation pricing.

**Buyers:** Developers building agents on Claude, LangChain, CrewAI, n8n — same audience as Botverse Transcode.

---

## Architecture (serverless rebuild)

```
[MCP client / REST API / AWS Marketplace SDK]
            ↓
  [API Gateway (HTTPS)]
            ↓
  [Auth Lambda — API key → account + CMK config]
            ↓
  ┌─────────────────────────────────────────┐
  │          Core Operation Lambdas          │
  │                                          │
  │  store_file_lambda                       │
  │    → strip metadata                      │
  │    → fragment into N chunks              │
  │    → per-fragment: request data key      │
  │      from customer KMS                   │
  │    → per-fragment: AES-256 encrypt       │
  │    → parallel PUT to N S3 buckets        │
  │    → write fragment index to DynamoDB    │
  │    → write store event to blockchain     │
  │                                          │
  │  retrieve_file_lambda                    │
  │    → check permission (blockchain cache) │
  │    → parallel GET from N S3 buckets      │
  │    → per-fragment: KMS decrypt           │
  │    → reassemble in order                 │
  │    → write retrieval event to blockchain │
  │                                          │
  │  permission_lambda                       │
  │    → write grant/revoke to blockchain    │
  │    → update DynamoDB cache               │
  │                                          │
  │  verify_lambda                           │
  │    → read from blockchain (no file I/O)  │
  └─────────────────────────────────────────┘
            ↓                    ↓
  [Storage Layer]        [Permission Layer]
  S3 (multi-bucket)      Blockchain (TBD)
  DynamoDB               DynamoDB cache
  Customer KMS           
```

### Fragment count and routing

- Default: **N=7 fragments** (configurable: 3, 5, 7, 11, 16)
- Fragment routing: modular distribution across registered buckets (same algorithm as existing code, with true random jitter added)
- Hybrid mode: odd-numbered fragments → customer's S3, even-numbered → Xinsere's S3 (50/50 split, independently operated)
- Customer-managed bucket mode: all buckets in customer's own AWS account; Xinsere only manages the API and blockchain layers
- **Region-pinned mode (planned):** scatter a file's fragments across buckets within one caller-specified region for data residency, still randomized — see *Planned capability: region-scoped write*. Default when unspecified is scatter-wide across the region pool.

### Encryption improvements over current code

| Current code | New design |
|---|---|
| One KMS key per file; file encrypted whole, then sliced | Per-fragment KMS data key — each fragment independently encrypted |
| MD5 for file ID | SHA-256 for all hashing |
| Filename preserved in fragment names | Filename stripped; fragment names are `{uuid}_{sequence}` with no connection to original |
| Local temp files | In-memory only (Lambda function memory); nothing written to disk |
| s5cmd subprocess | Native boto3 parallel S3 operations with `asyncio` or `ThreadPoolExecutor` |
| Hardcoded AWS credentials | IAM execution role (Lambda assumes role); no credentials in code |

### Lambda sizing for file operations

| File size | Fragment size (N=7) | Lambda memory | Timeout |
|---|---|---|---|
| ≤10MB | ~1.4MB/fragment | 512MB | 30s |
| 10–100MB | ~14MB/fragment | 1GB | 60s |
| 100MB–500MB | ~70MB/fragment | 3GB | 300s |
| >500MB | Not recommended for API mode | Use local client (MediaShippers pattern) | — |

For large files in MediaShippers/enterprise context: the existing Chrome extension model remains valid. The API/MCP product targets ≤500MB.

---

## Blockchain layer (decision pending research)

See `blockchain-research.md` for full analysis. Design requirements:

| Requirement | Notes |
|---|---|
| Throughput | 1,000–10,000 TPS at scale |
| Cost per transaction | Target <$0.001/tx; L1 Ethereum/Polygon PoS is too expensive at scale |
| Self-hosted option | Enterprise customers should be able to run their own node |
| Public auditability | 3rd parties can verify a tx_hash without trusting Xinsere |
| Immutability | Records cannot be altered or deleted post-write |
| Query capability | Must support querying all events for a given file_id |

**Decision:** See `blockchain-research.md` for full analysis. Summary:

| Phase | Chain | Notes |
|---|---|---|
| MCP launch | **Polygon PoS (public)** | Real blockchain from day one; zero infra; tx_hash verifiable on Polygonscan; $0.001–$0.005/tx negligible at launch volume |
| Enterprise tier | **Hyperledger Fabric** (customer's own AWS account) | Sovereign, high-TPS, on-prem; first enterprise customer triggers this |
| Public audit tier | **Arbitrum Orbit AnyTrust** | Checkpoints Fabric state onto Ethereum; for 3rd-party auditability |
| At scale | **Cosmos SDK app-chain** | Fully sovereign; right choice at 50k+ customers |

Postgres was considered and rejected — "blockchain-immutable permission trail" is a core brand promise and a key differentiator. Shipping with a database, even hardened, breaks that promise and is discoverable in enterprise due diligence.

---

## API surface

```
POST   /v1/files
         body: { content_type, file_base64 OR presigned_upload,
                 region? }                         # planned: residency; omit = scatter-wide
         → { file_id, fragment_count, stored_at, region, tx_hash }

GET    /v1/files/{id}
         → { file_base64, content_type, retrieved_at }

POST   /v1/files/{id}/permissions
         body: { grantee_id, permission_type, expires_at? }
         → { grant_id, tx_hash, granted_at }

DELETE /v1/files/{id}/permissions/{grantee_id}
         → { revoke_id, tx_hash, revoked_at }

GET    /v1/files/{id}/permissions/{party_id}
         → { has_permission, permission_type, granted_at, tx_hash }

GET    /v1/files/{id}/audit
         → { events: [ { type, actor, target, timestamp, tx_hash } ] }

GET    /v1/files/verify?hash={sha256}
         → { exists, first_stored_at, tx_hash }

GET    /v1/account/config
         → { deployment_mode, bucket_count, fragment_count, blockchain_endpoint }
```

All requests: `Authorization: Bearer {api_key}`

For large files: `POST /v1/files` returns a `presigned_upload` URL for direct client-to-S3 upload (avoids routing the file body through API Gateway/Lambda). Fragmentation then triggered asynchronously via SQS.

---

## Deployment modes

### Mode 1: Xinsere SaaS (simplest)
- Xinsere manages all S3 buckets, all KMS keys, blockchain node
- Customer provides nothing except payment
- Lowest security: customer trusts Xinsere

### Mode 2: Customer-managed keys (BYOK)
- Customer creates CMK in their own AWS KMS
- Xinsere's Lambda functions request data keys from customer's KMS
- Customer controls key rotation and revocation
- Xinsere cannot decrypt data without customer's CMK cooperation

### Mode 3: Customer-managed buckets (BYOB)
- Customer owns and operates the S3 buckets
- Xinsere's Lambda functions write to customer's buckets via cross-account IAM role
- Customers in regulated industries can keep data entirely within their AWS account perimeter

### Mode 4: Hybrid (recommended for maximum security)
- Fragments split: half to customer's buckets, half to Xinsere's buckets
- Each portion is independently useless without the other
- Requires two separate subpoenas / breach events to reconstruct any file
- Customer-managed CMK in customer's AWS account

### Mode 5: Fully self-hosted
- Customer deploys Xinsere's Lambda stack into their own AWS account
- Blockchain node deployed in customer's infrastructure
- Xinsere provides the software; customer operates it
- Xinsere earns licence fee + support retainer

---

## Botverse brand positioning

This product goes to market under **Botverse Secure** (alongside Botverse Transcode):

```
botverse.cloud
├── /transcode  — video encoding for agents  (Botverse Transcode)
└── /secure     — encrypted storage + permissioned sharing for agents  (Botverse Secure / Xinsere)
```

**MCP tool names:**
- `secure_store` — store a file with fragment encryption
- `secure_grant` — grant a party permission to a file
- `secure_revoke` — revoke a permission
- `secure_retrieve` — retrieve a file (if caller has permission)
- `secure_verify` — verify a permission (for 3rd-party audit)
- `secure_audit` — pull full audit trail for a file

**Positioning line:** "Botverse Secure — store files your AI agent can't be forced to reveal."

---

## AWS Marketplace path (phase 2)

AWS Marketplace listing positions Xinsere as a security add-on for existing S3 users:
- Listing category: Security → Data Protection
- Delivery method: SaaS subscription + CloudFormation template for self-hosted
- Pricing: per-operation (store, retrieve, permission grant)
- Integration: IAM role-based; customer grants cross-account access; no credentials exchanged

AWS Marketplace gives immediate access to the IT/cloud buyer (Market B) without direct sales. The listing itself is a credibility signal.

**Prerequisite:** SOC 2 Type I certification (or at minimum a vendor security questionnaire response that satisfies enterprise procurement). Budget ~$15–25k and 3–4 months.

---

## Build plan

*Revised v0.2 — based on full review of max-xinsere/xinsere-poc. Max's 5 Lambda .txt files are the complete code base; 8 additional Lambdas in CloudFormation are planned but not yet coded. Build estimate revised from 13 weeks to 5–7 weeks (human) or 1–2 weeks (Claude Code).*

### Phase 0 — Security cleanup (before anything else)
**Scope:** Rotate all exposed credentials. No new code until this is done.
**Tasks:**
- AWS IAM console: deactivate and delete all three exposed access keys (`AKIARX7FHY4OVVELQM4Z`, `AKIAQ3EGU6BLQUWCCQGV`, `AKIARX7FHY4OQKZ2FLDY`)
- Delete `maxcappellari_accessKeys.csv` and `IAM Keys.txt` from repo and git history (git-filter-repo or BFG)
- Rotate EC2 key pair (`EC2_BlockChain_Key.pem`); terminate or isolate the instance
- Deploy fresh smart contract with new wallet managed by AWS KMS asymmetric key
- Delete `save_to_blockchain.txt` old private key reference from repo history
- Configure Lambda IAM execution roles — `fragment_file`, `save_metadata`, `reassemble_file` roles without embedded credentials
- Verify `Distribute_File.txt` uses IAM role (it already does — confirm and leave)

**Est. human time:** 1 day  **Claude Code sessions:** 1–2 hours

---

### Phase 1 — Core Lambda hardening
**Scope:** Get the 5 existing Lambdas to production-quality. No new functionality yet.
**Tasks:**
- Remove hardcoded credentials from Fragment, Save_Metadata, Reassemble Lambdas → IAM execution roles
- Fix Fernet key normalization: `base64.b64encode` → `base64.urlsafe_b64encode` in `reassemble_file`
- MD5 → SHA-256 for all file and fragment ID hashing
- Dynamic slice sizing (port from `fileUploader.py`: `ceil(fileSize / N_FRAGMENTS)` where `N_FRAGMENTS` is configurable)
- Metadata stripping: fragment names become `{uuid}_{sequence}` — no connection to original filename
- Blockchain Lambda: replace hardcoded private key with AWS KMS asymmetric signing; migrate to Polygon PoS mainnet
- Add SQS dead-letter queues to all three SQS queues
- Add error handling and structured logging to all 5 Lambdas

**Est. human time:** 5 days  **Claude Code sessions:** 5–8 hours

---

### Phase 2 — Missing Lambda build (the 8 planned functions)
**Scope:** Build the Lambdas that are in the CloudFormation but have no code yet.
**Tasks:**
- `ListFiles_RDS` — query MySQL RDS by UserID; return file tree
- `CreateFolder_RDS` — create a folder record in MySQL
- `DeleteFile` — mark file deleted in DynamoDB; send SQS message to trigger fragment cleanup
- `Execute_Delete_FileFragments` — SQS-triggered; delete S3 objects for each fragment
- `RDS_Update_FileFragments` — SQS-triggered; sync fragment index to MySQL RDS
- `RDS_Update_Web3_Info` — update web3/blockchain info in RDS after blockchain confirmation
- `UpdatePermissions_RDS` — update permissions in MySQL (mirrors blockchain write)
- `apiauthorizer` — API Gateway Lambda authorizer: validate API key → return IAM policy

All RDS Lambdas deploy into VPC, use pymysql layer, connect to existing MySQL RDS instance.

**Est. human time:** 7 days  **Claude Code sessions:** 8–12 hours

---

### Phase 3 — REST API layer
**Scope:** API Gateway wired to all Lambdas. Full endpoint coverage.
**Tasks:**
- API Gateway configuration: routes, CORS, throttling, logging
- Auth Lambda wired as authorizer; API key → account config lookup
- All 8 API endpoints (see API surface section) returning correct responses
- DynamoDB schema additions: metadata stripping, per-fragment key storage
- Error response standardisation (400, 401, 403, 404, 500 shapes)
- CloudFormation template updated with all new resources

**Est. human time:** 5 days  **Claude Code sessions:** 4–6 hours

---

### Phase 4 — MCP server (TypeScript)
**Scope:** Botverse Secure MCP server. Wrap the REST API as MCP tools.
**Tasks:**
- TypeScript project scaffolded on MCP SDK
- Six tools: `secure_store`, `secure_retrieve`, `secure_grant`, `secure_revoke`, `secure_verify`, `secure_audit`
- Tool schemas: input/output types, error handling
- Authentication: API key via environment variable
- Publish to npm as `@botverse/secure`
- Register on MCP server registry
- Basic README with usage examples for Claude, LangChain, CrewAI

**Est. human time:** 5 days  **Claude Code sessions:** 4–8 hours

---

### Phase 5 — Browser file explorer (human UX)
**Scope:** Web app for human users. Same API backend as MCP.
**Tasks:**
- React app (or Next.js if SSR needed)
- Cognito auth (existing Identity Pool already provisioned)
- File tree view (browse folders, file metadata, icons by type)
- Upload: drag-drop with streaming progress (SSE)
- Download: stream from pre-signed URL with progress
- Share: generate share link backed by blockchain permission grant
- Permissions panel: see who has access, grant/revoke, show tx_hash
- Audit trail view: timeline of all events for a selected file
- Mobile-responsive

**Est. human time:** 10–15 days  **Claude Code sessions:** 10–16 hours

---

### Phase 6 — AWS Marketplace + enterprise packaging
**Scope:** Marketplace listing, BYOB/BYOK deployment modes, SOC 2 prep.
**Tasks:**
- CloudFormation template for customer self-deployment (BYOB/BYOK modes)
- AWS Marketplace SaaS subscription listing
- HIPAA BAA template, SOC 2 vendor questionnaire response
- Enterprise onboarding workflow (cross-account IAM role setup, CMK policy)

**Est. human time:** 10 days  **Claude Code sessions:** 4–6 hours (mostly documentation and config)

---

**Total revised estimate: 5–7 weeks (human) / 1–2 weeks (Claude Code)**
Phases 0–4 = working MCP product. Phases 5–6 = enterprise-ready product.

---

## Testing matrix

### Test file set

All phases use this standard file set. Create once, reuse at each phase.

| File | Size | Format | Purpose |
|---|---|---|---|
| `test-tiny.txt` | 1 KB | Plain text | Edge case: smaller than one fragment |
| `test-small.pdf` | 100 KB | PDF | Typical document |
| `test-medium.jpg` | 1 MB | JPEG image | Common AI agent use case |
| `test-large.pdf` | 10 MB | PDF | Large document / report |
| `test-video-short.mp4` | 50 MB | Video | Mid-size media |
| `test-video-long.mp4` | 200 MB | Video | Near Lambda memory limit |
| `test-unicode.txt` | 50 KB | UTF-8 with emoji, CJK | Encoding edge case |
| `test-binary.bin` | 5 MB | Random binary | Non-text, non-media |

SHA-256 hashes of all test files recorded before any test. Every retrieval must produce identical hash.

---

### Phase 0 — Security cleanup (no functionality testing)

| Check | Who | Pass criteria |
|---|---|---|
| AWS IAM console — confirm old keys inactive | Mark | All 3 keys show "Inactive" status |
| Attempt API call with old key | Claude Code | HTTP 403 from AWS |
| `git log --all -- maxcappellari_accessKeys.csv` | Claude Code | No commits found |
| Old private key search across repo | Claude Code | Zero matches for `7b9be380` |

---

### Phase 1 — Lambda hardening

**Mark tests (manual):**

| Test | File | Pass criteria |
|---|---|---|
| Store via direct Lambda invoke (test payload) | `test-tiny.txt` | Returns `fragment_count`, `file_id`, `tx_hash` |
| Store + retrieve round-trip | `test-small.pdf` | Retrieved SHA-256 = original SHA-256 |
| Store + retrieve round-trip | `test-medium.jpg` | Retrieved SHA-256 = original SHA-256 |
| Store + retrieve round-trip | `test-large.pdf` | Retrieved SHA-256 = original SHA-256 |
| Inspect fragments in S3 | Any | Fragment name contains no original filename |
| Attempt to open fragment raw | Any | Unreadable binary (Fernet-encrypted) |
| Verify tx_hash on Polygonscan | Any | Transaction visible and confirmed on Polygon PoS |

**Claude Code automated checks:**
- Unit test: SHA-256 of stored → retrieved matches for all 8 test files
- Unit test: fragment count = configured N (default 7) for each file
- Unit test: no fragment name contains any substring of original filename
- Check: no hardcoded credentials in any Lambda source file
- Check: all SQS queues have DLQ configured

---

### Phase 2 — Missing Lambda build

**Mark tests (manual):**

| Test | Pass criteria |
|---|---|
| Create folder via `CreateFolder_RDS` invoke | Folder appears in MySQL `files` table |
| List files for test user | Returns correct file list including `test-small.pdf` from Phase 1 |
| Delete file via `DeleteFile` | File removed from DynamoDB; SQS message sent to fragment cleanup |
| Verify fragment deleted from S3 after delete | S3 object for each fragment is gone |

**Claude Code automated checks:**
- Integration test: store file → list files → file appears
- Integration test: store file → delete → list → file absent
- Integration test: store file → delete → attempt retrieve → 404

---

### Phase 3 — REST API

**Mark tests (manual via curl or Postman):**

| Endpoint | File | Pass criteria |
|---|---|---|
| `POST /v1/files` | `test-medium.jpg` | 200 + `file_id`, `tx_hash` |
| `GET /v1/files/{id}` | Same | 200 + decoded file, SHA-256 matches |
| `POST /v1/files/{id}/permissions` | — | 200 + `grant_id`, `tx_hash` |
| `GET /v1/files/{id}/permissions/{user}` | — | `has_permission: true` |
| `DELETE /v1/files/{id}/permissions/{user}` | — | 200 + `revoke_id`, `tx_hash` |
| `GET /v1/files/{id}/audit` | — | Returns store event + grant + revoke events |
| `POST /v1/files` — no auth header | — | 401 |
| `GET /v1/files/{bad-id}` | — | 404 |
| `POST /v1/files` — oversized file (>500MB) | — | 413 with clear error |

**Claude Code automated checks:**
- Full API contract test suite: all 8 endpoints, all file sizes
- Fuzz test: malformed file IDs, special characters in filenames, Unicode
- Auth bypass attempt: expired key, missing header, wrong format

---

### Phase 4 — MCP server (external beta)

This is the first phase where external testers join.

**Internal (Mark + Claude Code):**

| Test | Pass criteria |
|---|---|
| Add MCP server to Claude config | Tool list shows all 6 Botverse Secure tools |
| Claude agent calls `secure_store` with `test-small.pdf` | Returns `file_id`, confirms with tx_hash |
| Claude agent calls `secure_retrieve` with `file_id` | Returns decoded file; SHA-256 matches |
| Claude agent calls `secure_grant` then second agent calls `secure_retrieve` | Second agent retrieves successfully |
| First agent calls `secure_revoke`; second agent retries | 403 / permission denied |
| Agent calls `secure_audit` | Returns full timeline |

**External beta testers (Max, JC, Jeremy, Joshua):**

| Tester | Role | What to test | Feedback format |
|---|---|---|---|
| Max Cappellari | Technical — knows the internals | End-to-end store/retrieve; verify tx_hash on Polygonscan; attempt to reconstruct file from raw S3 fragments | Written notes or voice call |
| Jeremy Katz | Co-founder / business | Store a file → share it with Joshua → Joshua retrieves it; file is bit-perfect | Written notes |
| Joshua Katz | Co-founder / business | Receive shared file via `secure_retrieve`; confirm contents match what Jeremy sent | Written notes |
| JC Curelop | Sales perspective | First-time setup experience; MCP config friction; time-to-first-successful-store | Written notes — specifically: where did you get confused? |

**Feedback gate:** All four external testers must confirm:
1. File stored and retrieved is bit-perfect (SHA-256 match, or visual/manual confirmation)
2. Shared file (Jeremy → Joshua) works correctly
3. No plaintext filenames visible in S3 (Max to verify)
4. Blockchain tx_hash resolves on Polygonscan (Max to verify)

Build does not advance to Phase 5 until feedback gate is passed.

---

### Phase 5 — Browser UI

**Mark tests (browser):**

| Test | File | Pass criteria |
|---|---|---|
| Login via Cognito | — | Redirects to file browser; user ID displayed |
| Drag-drop upload | `test-large.pdf` | Progress bar moves; file appears in tree on completion |
| Click to download | `test-large.pdf` | File downloads; SHA-256 matches original |
| Share file | `test-medium.jpg` | Share link generated; second user can retrieve via link |
| Permissions panel | Any | Shows grantee list, grant/revoke buttons; blockchain tx_hash visible |
| Audit trail view | Any | Timeline shows store, share, and any revoke events with timestamps |
| Mobile layout | Any | Usable on iPhone/Android without horizontal scroll |

**Claude Code automated checks:**
- Playwright end-to-end tests: login → upload → download → verify SHA-256
- Accessibility check: WCAG AA for key flows (upload, download, share)
- Performance: upload of `test-large.pdf` completes in <30 seconds

---

### Phase 6 — Pre-launch security audit

**See full Security Audit section below.**

---

## Security audit

*To be conducted before any public launch. Not a formality — Xinsere's entire value proposition is security. A breach before launch is existential.*

### Audit scope

| Area | What to test |
|---|---|
| **Credential exposure** | Rescan all repos (including git history) for any remaining secrets |
| **IAM permissions** | Verify all Lambda execution roles are least-privilege; no `*` actions; no `*` resources |
| **KMS key policy** | Verify Xinsere Lambdas cannot call `kms:Decrypt` without the caller's CMK authorisation |
| **Fragment name leakage** | Verify no S3 fragment name contains filename, extension, or any metadata from the original |
| **Fragment reconstruction attack** | Attempt to reconstruct a file from S3 fragments without KMS access; must be impossible |
| **Blockchain replay attack** | Verify smart contract rejects duplicate `addFile` calls (same hash); verify only KMS-signed wallet can call `ADMIN_ROLE` functions |
| **API auth bypass** | Penetration test all 8 API endpoints: missing header, malformed JWT, expired key, IDOR on file IDs |
| **Injection** | SQL injection via DynamoDB query parameters; path traversal in file IDs |
| **DynamoDB encryption** | Verify all DynamoDB tables have encryption at rest enabled; verify KMS key is not AWS-owned default |
| **S3 bucket policy** | Verify no Xinsere S3 bucket is publicly listable; verify no `s3:ListBucket` or `s3:GetObject` without auth |
| **Lambda function URL** | Verify no Lambdas have function URLs enabled (all access via API Gateway only) |
| **Cross-account IAM** | In BYOB/BYOK mode, verify customer's cross-account role has minimum permissions (no `s3:*`) |
| **Logging completeness** | Verify all API calls, Lambda invocations, KMS key uses, and blockchain writes are logged to CloudWatch and optionally CloudTrail |
| **Rate limiting** | Verify API Gateway throttling prevents abuse; verify per-account op limits enforced |
| **Data in transit** | Verify all endpoints enforce TLS 1.2+; HSTS on the browser UI |
| **Cognito config** | Verify MFA is available; verify user pool doesn't allow unauthenticated identity access |

### Audit process

1. **Self-audit (Claude Code + Mark):** Run through the checklist above. Mark passes = documented. Mark fails = fix before proceeding.
2. **Penetration test (external):** Engage an external pen tester for a focused one-week engagement on the API and blockchain layers. Budget: $5,000–$15,000 depending on scope.
3. **Dependency audit:** Run `pip-audit` on all Python Lambda dependencies; `npm audit` on the TypeScript MCP server. Resolve all HIGH and CRITICAL CVEs.
4. **Smart contract audit:** If budget allows ($10,000–$30,000), engage a Solidity auditor to review `XinsereFileAccess`. At minimum, self-audit using Slither (static analysis) and Mythril (symbolic execution).
5. **Fix and re-test:** Any finding rated HIGH or CRITICAL blocks launch. MEDIUM findings require a documented remediation plan.
6. **Produce security posture document:** One page summarising what's protected, how, and what the residual risks are. Required for enterprise sales and SOC 2.

### Modern security principles applied to Xinsere

The design should satisfy these principles at every layer:

| Principle | How Xinsere implements it |
|---|---|
| **Zero trust** | No Xinsere component trusts another by default; all cross-service calls are authenticated via IAM roles or API keys |
| **Least privilege** | Every Lambda has the minimum IAM permissions to do its job; no shared roles across functions |
| **Defence in depth** | Encryption at rest (S3 SSE-KMS), encryption in transit (TLS), per-fragment application-layer encryption, blockchain audit — multiple independent layers |
| **Separation of duties** | Customer's KMS key is in the customer's account; Xinsere cannot independently call `kms:Decrypt` |
| **Immutability** | Blockchain permission records cannot be altered; DynamoDB tables have point-in-time recovery enabled |
| **Auditability** | Every operation logs a blockchain tx_hash; CloudTrail captures all AWS API calls; CloudWatch logs all Lambda invocations |
| **Secure by default** | BYOK is the default for paid tiers; SaaS-managed keys only for Developer/free tier |
| **Fail secure** | If KMS is unavailable, store operation fails — not silently stores without encryption |
| **No security through obscurity** | Fragment distribution algorithm is disclosed (patent); security claims are verifiable by inspecting tx_hash on Polygonscan |

---

## AI-era threat landscape — why now

*This section informs marketing messaging and product positioning.*

### The Anthropic Mythos problem

We are entering an era of large-scale AI-generated content — synthetic text, images, audio, and video that is indistinguishable from authentic human-produced content. The risk to organisations is structural:

- **AI-generated contracts and documents** can be fabricated and injected into legal and business workflows
- **AI-synthesised evidence** (audio, video, image) can be used in litigation, regulation, or competitive intelligence
- **AI-impersonated communications** (email, voice, video calls) already drive billion-dollar fraud
- **Regulatory response** (EU AI Act, SEC AI disclosure requirements, emerging content provenance standards) means organisations will be required to prove the authenticity and chain of custody of their documents

The question is no longer "are your files encrypted?" but "can you prove your files haven't been tampered with, who accessed them, and when?"

### Why standard cloud security is no longer enough

S3 encryption protects against external attackers breaking into your storage. It does not protect against:
- An insider at your cloud provider with admin access
- A national security letter or court order served to your cloud provider
- A compromised AWS root account at your organisation
- AI-generated replacement documents injected into your workflow by an attacker who has compromised a user account

Xinsere's architecture addresses all four. The blockchain audit trail means that even if an attacker injects a fake document, they cannot forge the blockchain record showing the original document's chain of custody.

### Messaging for market communications

**For AI agent developers (Botverse Secure):**
> "Your AI agent handles real documents. In a world where AI can generate convincing fakes, the value of your agent depends on it being able to prove what it stored and what it shared. Botverse Secure gives every file a blockchain receipt. If anyone asks — show them the tx_hash."

**For business buyers (Xinsere Business):**
> "In 2025, your biggest document risk wasn't external hackers — it was AI impersonation and synthetic document injection. Xinsere stores your real documents with an immutable proof of authenticity. Your contracts, your filings, your records — with cryptographic proof they haven't been touched."

**For enterprise buyers (Xinsere Enterprise):**
> "As AI-generated content becomes indistinguishable from authentic content, the organisations with proof of custody win. Xinsere's blockchain-immutable permission ledger is the enterprise standard for document sovereignty in the AI era. Not even Xinsere can read or fabricate your records."

**The one-sentence pitch for any context:**
> "Every AI tool can generate a convincing fake document. Xinsere is the only place you can prove yours is real."

---

## Relationship to existing code

### From Max's serverless POC (`max-xinsere/xinsere-poc`)

The .txt files in the `AWS/` folder ARE the complete Lambda code set. The additional Lambda entries in the CloudFormation are planned functions not yet implemented. Max confirmed this.

| Lambda file | Status | What to do |
|---|---|---|
| `Fragment_File_Lambda.txt` | Working — **has hardcoded credentials** | Remove `Access_Key`/`Secret_Key` → IAM execution role. Fix per-fragment KMS (confirmed correct). Add SHA-256, metadata stripping, dynamic slice sizing. |
| `Distribute_File.txt` | Working — **already uses IAM role** (no credentials in code) | Minor: add dead-letter queue, improve error handling. |
| `Save_Metadata.txt` | Working — **has hardcoded credentials** | Remove credentials → IAM role. Replace MD5 → SHA-256. |
| `reassemble_file.txt` | Working — **has hardcoded credentials** | Remove credentials → IAM role. Fix `base64.b64encode` → `base64.urlsafe_b64encode` for Fernet key normalization. |
| `save_to_blockchain.txt` | Working — **has hardcoded private key** | Replace hardcoded private key with AWS KMS asymmetric signing. Migrate from Polygon Mumbai to Polygon PoS mainnet. |

**Still needs to be built (planned in CloudFormation, no code yet):**
- `ListFiles_RDS` — list files for a user
- `UpdatePermissions_RDS` — update permissions in MySQL
- `CreateFolder_RDS` — folder management
- `DeleteFile` — delete file and trigger fragment cleanup
- `RDS_Update_FileFragments` — update fragment index in RDS
- `RDS_Update_Web3_Info` — update web3 info after blockchain write
- `apiauthorizer` — API Gateway custom authorizer
- `Execute_Delete_FileFragments` — physical S3 fragment deletion

### From ETI Dev Corp Chrome extension (`MarkTurnerXinsere/Xinsere`)

| Component | What to do |
|---|---|
| `fileUploader.py` — dynamic slice sizing `math.ceil(fileSize / MAX_SLICES)` | **Port to Fragment Lambda** — better than Max's hardcoded 20,000 bytes. Parameterise `MAX_SLICES`. |
| `fileUploader.py` — `base64.urlsafe_b64encode` KMS key normalization | **Port to reassemble Lambda** — fixes Fernet key format bug present in Max's Lambda. |
| `fileUploader.py` — streaming progress event schema | **Port to browser UI** — event names (`fragmentStart`, `fragmentEnd`, `distributeStart`, etc.) are the right UX pattern for SSE/WebSocket progress. |
| `fileUploader.py` — `fix_decimals` DynamoDB utility | **Port** — needed wherever DynamoDB Decimal fields are serialised to JSON. |
| `fileUploader.py` — `encrypt_file` per-FILE encryption | **Do not port** — one key per file is architecturally weaker than Max's per-fragment approach. Wrong security model. |
| Chrome extension UI | **Throwaway** — Chrome-specific. Not relevant to MCP/API product. |
| `fileuploader_host.py` | **Throwaway** — Chrome Native Messaging protocol. Not used in serverless architecture. |
