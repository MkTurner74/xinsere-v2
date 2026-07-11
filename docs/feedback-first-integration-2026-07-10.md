# Xinsere API — First Third-Party Integration Feedback

*2026-07-10 — from building the Samsyn integration (owg-core), the first external
consumer of the Xinsere `/v1` machine API. Written for the Xinsere product/API
backlog. Integration built and first store exercised the same evening the org
was seeded — that speed is itself a datapoint.*

## What worked well (keep these)

1. **The API surface is small and honest.** 13 endpoints, one auth header, no
   SDK required. A typed client (`lib/xinsere.ts`) was ~150 lines and took
   under an hour against the integration guide.
2. **`/v1/ping` as identity + wiring check** is excellent — org, `party_id`,
   scopes in one call. It became Samsyn's feature flag: configured + ping OK →
   tier on; anything else → every Xinsere surface hides itself.
3. **`sha256` returned at store time** is the single most valuable field in the
   API. It let the OWG asset node carry a provable claim about the bytes with
   zero extra calls — the graph↔bytes loop closes for free.
4. **Plan-based retrieval** (presigned fragment URLs + per-fragment keys) is the
   right design: plaintext never transits Xinsere *or* Samsyn. The reference
   client (`xinsere-client.js`) ported to TypeScript without a single API
   change — retry/resume/verify logic all held up.
5. **Hash-only keys, shown once, org-scoped, with scopes** — nothing to
   criticize; the key hygiene guidance in the docs matched the implementation.
6. **The metadata boundary is clean**: Xinsere never learns filenames beyond the
   chosen folder path, graph structure, or production context. Made the IP/
   privacy conversation with the integrating product trivial.
7. **The error contract table** (401/403/404/413/422/502/503 → what the client
   should do) is rare in API docs and drove Samsyn's fail-closed behavior
   directly. Keep it, and keep 404-for-existence-hiding.

## Friction found (fix these)

1. **Inline-size ambiguity.** Docs say "~4 MB" (the practical serverless body
   cap) but the API's actual `MAX_INLINE_BYTES` default is 500 MB. The client
   had to hardcode a 4 MB guess for the inline/staged switch. → Advertise the
   effective inline cap machine-readably (in `/v1/ping` or the 413 body as
   `max_inline_bytes`) so clients don't guess.
2. **No visibility into chain capacity.** Grants cost gas from a wallet the
   integrator can't see. A grant that will fail for lack of gas looks identical
   to one that will succeed until the 502. → Add something like
   `GET /v1/chain/status` → `{wallet_ok, est_grants_remaining}` so client UIs
   can warn *before* the demo dies on stage. (This bit us: the Amoy wallet held
   ~2 tx of dust and only out-of-band knowledge prevented a surprise.)
3. **Grantee `party_id` discovery is human-only.** Granting to another org
   requires an admin to read the party uuid out of the console. For
   machine-to-machine turnover (the whole point of workflow-bound grants),
   integrators need `GET /v1/parties?slug=` (scoped, opt-in visibility) to
   resolve a counterparty programmatically.
4. **Error body shape is FastAPI's `{detail}`** while most JS ecosystems expect
   `{error}`. Minor, but the client needed a special parse. → Pick one shape,
   document it in the guide.
5. **Store has no on-chain anchor.** Protection at store time writes nothing to
   the chain — only grants/revokes do. For provenance-led pitches (EU AI Act),
   an optional `anchor=true` on store (sha256 → contract event) would let
   integrators claim "existence + integrity anchored on-chain at time T", not
   just "access controlled on-chain". Understand the gas trade-off; even as a
   priced option it strengthens the story.
6. **Docs are behind invite-only sign-in.** Right gate for now, but a future
   third party's engineers can't even *read* the docs before someone provisions
   accounts. → Public reference docs + gated try-it/keys is the standard split.
7. **No webhooks.** Chain writes take seconds; Samsyn does async fail-closed
   polling of its own call, which works — but a `grant.confirmed` /
   `grant.failed` callback would remove the awkward pending states for UIs.
8. **Reference client isn't packaged.** `xinsere-client.js` is genuinely good —
   publish it (npm, TS types) instead of letting every integrator port it by
   hand. Samsyn's port is `navigator/src/lib/xinsere-client.ts` if useful as
   the TS starting point.

## Verified in production (2026-07-10/11)

- Org seeding + key mint (admin console) → `/v1/ping` ✔
- `POST /v1/files` inline store, 942 KB MP4 produced by a Botverse workflow →
  7 fragments scattered, sha256 returned and recorded ✔
- Not yet exercised end-to-end: grants/verify/revoke (pending demo-grantee org
  + wallet gas) and plan-based browser reassembly against a live protected
  asset. Will follow in the next demo-prep session.

## The one-sentence review

A small, honest, security-literate API that a third party integrated in one
session — its gaps are all in *operability* (capacity visibility, counterparty
discovery, eventing), not in the core design.
