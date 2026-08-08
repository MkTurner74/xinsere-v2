# TAMS demo — time-addressable media over Xinsere-protected segments

**Live:** https://app.xinsere.com/tams (sign in first)
**Code:** `demo/tams.py`, `demo/frontend/tams.html`, tests in `demo/tests/test_tams.py`
**Shipped:** 2026-08-03 (`cc296e4`)
**Companion docs:** `Xinsere-TAMS-Adapter-Spike.md` (thesis) and `Xinsere-TAMS-Development-Plan.md`
(phasing), both in the Ai Companion Docs repo.

---

## 1. What it demonstrates

The spike's thesis, running: **TAMS keeps the timeline and the query; Xinsere holds, protects and
releases the bytes.** A TAMS Media Object resolves to a Xinsere object handle, not a raw S3 key.

Four steps on one page:

1. **Ingest** real HLS segments, each written through the production pipeline — shredded,
   per-fragment AES-256-GCM, scattered across buckets.
2. **Timeline** — flows laid out on a shared TAI axis. Nothing is muxed; alignment is by
   timestamp, so one instant means the same instant in every lane.
3. **Query** a timerange, TAMS-style. What comes back are object handles. No bytes are decrypted
   at this stage — this is the index plane only.
4. **Play** the result in the browser. Every segment the player fetches goes through
   verify → reassemble → SHA-256 → return, with the real latency breakdown charted live.

---

## 2. Data model — why there was no schema migration

This is the part worth understanding, because it is what made the demo shippable in a day.

The existing `nodes` table already had the right shape, so nothing new was created:

| TAMS concept | How it is stored |
|---|---|
| **Flow** | A folder node. |
| **Flow metadata** | A sibling marker node whose **name** carries the JSON, prefixed `_tams:`, with `file_id` NULL. No pipeline object, so one `children()` call returns the flow's metadata *and* its whole segment index together. |
| **Segment** | A file node named `s{start_ns:020d}_e{end_ns:020d}`, whose `file_id` is the Xinsere object handle. |
| **Source / timeline** | A `source_id` string in the flow metadata. Flows sharing one are drawn as lanes on a common axis. |

Two consequences fall out of the naming scheme:

- **Zero-padded names mean lexical order is time order**, so the child listing comes back sorted
  by time with no sort key and no index.
- **A timerange query is a range filter over child names.** There is no separate time index to
  keep consistent.

Timestamps are **TAI nanoseconds** per the AMWA/NMOS timing model — TAI rather than UTC because
TAI is monotonic, and a leap second stepping a media timeline backwards is poison. The fixed
offset (`TAI_MINUS_UTC = 37`) is applied only for display.

Nothing here forks the storage path. A segment goes in through `PipelineService.store()` and comes
out through `PipelineService.retrieve()` exactly like any other object — which is the point of the
demo. If it needed a special path, the thesis would be weaker.

---

## 3. Access model

The gate matches `app._authorize` exactly rather than introducing a second, parallel one.

- **Everyone is verified on-chain, the owner included.** The owner is let through as a *labelled*
  fallback when no grant has been anchored yet, so they can never be locked out of their own flow
  — the same rule the app applies to every other download.
- **The UI reports which of the two authorized the call** (`amoy-contract` vs `owner-fallback`),
  so a fallback is never mistaken for on-chain proof. This matters: segments are not currently
  granted at ingest, so the owner path is normally `owner-fallback` today. See §6.
- **`?as=stranger`** swaps in a party id that holds no grant. The `verify()` call is genuine —
  only the subject changes — so the fail-closed path is demonstrated against the real contract
  rather than simulated.
- **Fail-closed means nothing is returned.** Not a placeholder, not a degraded copy, and not an
  error body that leaks whether the segment exists.
- **An RPC outage denies a stranger** rather than admitting them. Only the owner falls back.

### The verify cache

Positive verdicts are cached for 60s per `(file, party)`. This is the fail-closed cache from the
development plan, and the asymmetry is deliberate:

- A **positive** verdict is cached, so playback doesn't pay an RPC round-trip per segment.
- A **denial is never cached**, so a revoke bites on the very next request.
- An empty or lost cache can only ever block a legitimate user, never expose a file.

---

## 4. API

All routes require a signed-in session. `as` is `owner` (default) or `stranger`.

| Route | Purpose |
|---|---|
| `GET /tams` | The demo page. A shell — it checks `/api/me`; every data route is server-gated regardless. |
| `POST /api/tams/ingest` | Fetch an HLS playlist and store its segments. Body: `url`, `label`, `source_id`, `essence`, `segments`, optional `start_tai_ns`. |
| `GET /api/tams/flows` | Every flow with its timeline extent — the data behind the lane view. |
| `GET /api/tams/flows/{flow_id}/segments?timerange=` | **The TAMS query.** `<flow_id, timerange>` → Media Objects. Index plane only. |
| `GET /api/tams/flows/{flow_id}/playlist.m3u8?timerange=` | An HLS playlist whose every segment URL is a gated Xinsere retrieval. |
| `GET /api/tams/segments/{node_id}/content` | Authorized retrieval. verify → reassemble → SHA-256 → bytes. |
| `DELETE /api/tams/flows/{flow_id}` | Remove a flow and cryptographically erase its segments. |

### Timerange syntax

Half-open, per the spec: `[start_end)`. Bare `start_end` and `start/end` are also accepted;
timestamps are `<seconds>:<nanoseconds>`, and bare seconds work (`7` = `7:0`).

Overlap is genuinely half-open — a segment matches when `start < range_end AND end > range_start`,
so a range that merely touches a boundary does **not** match. A malformed range raises rather than
matching everything: an over-broad query on a rights-gated store is a disclosure bug, not a UX bug.

### Response headers on segment content

Surfaced so the UI can chart a real playback rather than a synthetic measurement:

`X-Xinsere-Verify-Ms`, `X-Xinsere-Verify-Cached`, `X-Xinsere-Auth-Source`, `X-Xinsere-Party`,
`X-Xinsere-Retrieve-Ms`, `X-Xinsere-Index-Ms`, `X-Xinsere-Fetch-Decrypt-Ms`,
`X-Xinsere-Verify-Sha-Ms`, `X-Xinsere-Fragments`.

---

## 5. Guards

Ingest is bounded so a demo can't run past the Vercel function ceiling (300s / 1024MB) and leave a
half-written flow in front of an audience:

| Guard | Value |
|---|---|
| `MAX_SEGMENTS` | 24 (default 6) |
| `MAX_SEGMENT_BYTES` | 32 MB |
| `FETCH_TIMEOUT` | 20s per HTTP fetch |
| `_VERIFY_TTL` | 60s, positive verdicts only |

A master playlist is resolved to its first variant automatically. If a segment fetch fails
partway, ingest keeps whatever landed rather than discarding the flow; if *nothing* lands, the
empty flow folder is removed.

---

## 6. Known gaps — deliberately not faked

1. ~~**Segments run at the deployed `XINSERE_FRAGMENT_COUNT` (7), not a tuned count.**~~
   **CLOSED 2026-08-08.** Fragment count is now derived from each object's size
   (`fragmenter.plan_fragment_count`), so a 2s segment scatters 3 ways instead of 7 — which is
   what the 2026-07-26 benchmark asked for, since segment latency tracks per-fragment round trips
   rather than bytes (10 MB at N=7 retrieves in 291 ms, N=1000 costs 3.26 s). No per-flow pin was
   needed; `store(fragment_count=N)` exists if one ever is. The UI still reports the real count
   used, and the ingest summary now states it explicitly.
2. **Segments are not granted on-chain at ingest**, so the owner path normally resolves via
   `owner-fallback`. Making this a genuine `amoy-contract` path means one **batched, windowed**
   grant per flow (`grantBatchWindowed` + a Merkle proof over the segment set) — never one
   transaction per segment, which at 2s segments would be 1,800 transactions per flow-hour. That
   is Phase 2, and it is also what unlocks the embargo demo.
3. **Multicloud is capable, not deployed.** `MultiCloudObjectStore` is built and unit-tested but
   production is still 100% AWS S3, so segments currently scatter across S3 buckets rather than
   across providers. Say "multicloud-capable" until that changes.
4. **No init-Object protection yet.** The CMAF control point (Fig. 04 in the BBC deck) needs
   content with a discrete init segment; the bundled TAMS samples don't provide one.
5. **The demo ingests over the public internet**, so ingest wall-clock includes fetching from the
   source CDN. Only the `store_ms` figures are Xinsere's own cost.

---

## 7. Tests

`demo/tests/test_tams.py` — 22 tests, no AWS, no chain, no network. They cover the four things
that decide whether a time-addressable store is correct: timestamp round-tripping, half-open
overlap, mapping node names back to segments in time order, and a gate that fails closed
(including the RPC-outage case and the cache asymmetry).

```bash
cd demo && python -m pytest tests/test_tams.py -q
```

**On the travel laptop these cannot run natively** — `cryptography` and `web3`/`ckzg` have no
ARM64 Windows wheels. Stub those third-party modules before importing to run them there; the app
modules themselves import fine.

---

## 8. Deployment note

`app.xinsere.com` deploys on push to `main` — there is no separate deploy step, so any commit to
main is a production release. Vercel's Python runtime now auto-detects the FastAPI app; a
catch-all rewrite to `/api/index` will break every route. See
`session-2026-08-03-tams-demo-and-vercel-routing-fix.md`.
