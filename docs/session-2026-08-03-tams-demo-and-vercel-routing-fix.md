# Session 2026-08-03 — TAMS demo shipped, and a production routing outage found on the way

Mark asked for a demo section of app.xinsere.com to demonstrate and test the TAMS integration
ahead of a BBC R&D meeting on Wed 5 Aug, deployed from the travel laptop rather than Sedona.
Chosen scope: production directly (not preview), core timeline + gated retrieval + in-browser
playback.

## 1. What was built

`/tams` — see `docs/tams-demo.md` for the reference. In short: ingest real HLS segments through
the production pipeline, index them by TAI timerange, query TAMS-style, play the result back with
every segment gated and integrity-checked on the way out.

Three decisions worth recording, because each one avoided a much larger piece of work:

**No schema migration.** The `nodes` table already had the right shape. A flow is a folder node; a
segment is a file node named `s{start_ns:020d}_e{end_ns:020d}` whose `file_id` is the Xinsere
object handle; flow metadata rides on a marker node whose *name* carries the JSON with `file_id`
NULL. Zero-padding means lexical order is time order, so a timerange query is a range filter over
child names — no separate time index to keep consistent. This mattered practically: applying a
Supabase migration from this laptop wasn't possible (DDL needs a connection the CLI env vars don't
provide), so a design needing one would have been undeployable from here.

**No fork of the storage path.** Segments go in through `PipelineService.store()` and come out
through `retrieve()` exactly like any other object. If the demo had needed a special path, the
spike's thesis would be weaker, not stronger.

**The access gate mirrors `app._authorize` rather than duplicating it.** Everyone is verified
on-chain including the owner, who is let through as a *labelled* fallback when no grant is
anchored. The UI reports which of the two authorized the call, so `owner-fallback` can never be
mistaken for on-chain proof. `?as=stranger` makes a genuine contract call against a party with no
grant, so fail-closed is demonstrated rather than simulated.

## 2. The outage

The first production deploy returned **404 on every route**, including `/` — `{"detail":"Not
Found"}`, FastAPI's own 404.

Cause: **Vercel's Python runtime now auto-detects the FastAPI app.** Comparing `vercel inspect`
across deployments made it obvious —

| Deployment | Build output |
|---|---|
| 7 days old (working) | `λ index` (79.58MB) |
| new | `λ fastapi` (79.75MB) |

`vercel.json` carried a catch-all rewrite `/(.*) → /api/index`. Once the function was no longer
built at `api/index.py`, that rewrite pointed at nothing, so the ASGI app answered every path with
its own 404. Deleting the `rewrites` block fixed it (`217f7fb`) — with framework detection the
ASGI app is served directly, so the rewrite is not merely unnecessary but actively wrong. Crons
are unaffected; they hit real FastAPI paths.

**This was not caused by the TAMS commit.** The previous deploy was 7 days old and predated the
runtime change; the first rebuild after it was always going to hit this, whatever the commit
contained. Any Vercel Python project whose last deploy predates the change carries the same latent
failure — checked the other repos, and xinsere-v2 was the only one using that rewrite pattern.

**The keep-warm workflow cannot catch this.** `.github/workflows/keep-warm.yml` pings `/api/warm`
every 5 minutes with `curl ... || true`, so a total outage is swallowed silently and never alerts.
Production had been reachable-but-404ing with nothing flagging it. Worth fixing — that `|| true`
is the difference between a monitor and a decoration.

Verified restored:

```
/                200      /api/warm        {"ok":true,"warmed":{"pipeline":"ok","chain":"ok"}}
/tams            200      /api/tams/flows  401  (correctly gated when signed out)
```

## 3. Testing without a local runtime

The travel laptop had no real Python (only the Windows Store alias stub), so nothing could be run
locally at the start. Installed Python 3.12 ARM64 via winget — but `cryptography` and `web3`/`ckzg`
have **no ARM64 Windows wheels** and fail to build from source, so the app can't be imported
normally here.

Worked around it by stubbing only the *third-party* modules (cryptography, boto3, web3) and
letting `tams.py`, `store.py`, `chain.py` and `supa.py` import for real — which exercises the
committed test file rather than a parallel copy of its assertions. 22 tests pass. They cover
timestamp round-tripping, half-open overlap (including that a touching boundary does *not* match),
playlist and master-variant parsing, and the gate: stranger denied, owner fallback labelled,
positive verdicts cached but denials never, and an RPC outage denying a stranger rather than
admitting them.

Preview deployments were evaluated as a test bed and rejected: every env var on the project is
Production-scoped, so a preview boots with no credentials, and preview URLs sit behind Vercel
Authentication so they can't be curl-tested anyway.

## 4. Not done / next

- **Grant segments on-chain at ingest** via one batched, windowed grant per flow
  (`grantBatchWindowed` + Merkle proof), so the owner path resolves `amoy-contract` rather than
  `owner-fallback`. Never one transaction per segment — at 2s segments that is 1,800 tx per
  flow-hour. This is also what unlocks the embargo demo.
- **Per-call `fragment_count` on `PipelineService.store()`** so segments can be pinned to N=3–5.
  The benchmark is unambiguous that segments want fewer fragments than files.
- **Fix the keep-warm workflow** so an outage actually alerts.
- **Deploy the multicloud path** — code is built and unit-tested, production is still 100% AWS S3.
  Until then the claim is "multicloud-capable".
- **init-Object protection** (Fig. 04) needs CMAF content with a discrete init segment; the
  bundled TAMS samples don't have one, so it needs generating.
- End-to-end ingest/query/playback was verified by Mark in the browser, not automated. A smoke
  test against a live session would be worth having before this is shown regularly.
