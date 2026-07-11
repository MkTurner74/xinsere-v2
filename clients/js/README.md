# xinsere-client

Official TypeScript/JavaScript client for the **Xinsere v1 API** — secure
fragmented storage with on-chain permissions.

Small and honest: one bearer key, a typed method per endpoint, and **resilient
client-side reassembly** (per-fragment AES-256-GCM + whole-file SHA-256) that
self-heals broken transfers. The plaintext never transits Xinsere.

> Status: **v0.1.0, not yet published.** Seeded from the demo reference client and
> the first integrator's TypeScript port. Publishing (name, npm org, entity) is a
> pending decision — see `docs/api-backlog-status-2026-07-10.md`.

## Install (once published)

```bash
npm install xinsere-client
```

## Usage

```ts
import { XinsereClient } from "xinsere-client";

const xin = new XinsereClient({
  baseUrl: "https://xinsere-v2.vercel.app",
  apiKey: process.env.XINSERE_KEY!,
});

// Identity + wiring check
const me = await xin.ping();          // { organization, party_id, scopes, max_inline_bytes, ... }

// Capacity pre-flight — don't grant on empty gas
const chain = await xin.chainStatus();
if (!chain.wallet_ok) throw new Error("Top up the signer wallet before granting");

// Store (auto inline vs staged based on the server's advertised cap)
const rec = await xin.store(bytes, { name: "contract.pdf", contentType: "application/pdf" });

// Grant to another org, resolving its party_id from a slug (no console copy-paste)
const partner = await xin.resolveParty("samsyn");
const grant = await xin.grant(rec.id, partner.party_id);   // grant.tx is PolygonScan-verifiable

// Retrieve client-side — fragments fetched + decrypted locally, integrity verified
const { bytes: plaintext } = await xin.downloadClientSide(rec.id);
```

## Runtimes

- **Node 18+** and modern browsers (global `fetch` + WebCrypto). Pass `opts.fetch`
  to override.
- Server-to-server is the primary target; in a browser the API host must allow
  your origin via CORS.

## Error shape

Every method throws `XinsereError` on a non-2xx response, carrying `.status` and,
when present, a machine `.code` (e.g. `chain_grant_failed`). All API errors share
the `{ "error": "message [code]" }` body shape, including `422` validation errors.

## Build

```bash
npm install
npm run build   # tsc -> dist/
```
