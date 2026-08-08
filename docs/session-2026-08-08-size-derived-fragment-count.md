# Session 2026-08-08 — fragment count is derived from file size

Mark's ask: stop splitting everything 7 ways; vary the count by file size, and expose it on the
API. TAMS on-chain grant work was explicitly deferred — BBC have demo access but no official
opinion yet, so it waits until someone asks for it.

## 1. The algorithm already existed — as a finding, not as code

`Fragment-Count-Bucket-Diversity-Findings-2026-07-26.md` (ai-brain, projects/Xinsere) §5 had
settled the frame: **"optimal fragment count isn't the right frame — optimal fragment *size* is."**
Three results from that day's real-AWS benchmark drive everything here:

- Throughput tracks fragment **size**, not count. It collapses below ~500KB–1MB per fragment
  (10MB file: 23.4 → 1.1 MB/s going 32 → 1000 fragments) and plateaus above ~1–3MB.
- Count and bucket diversity are **independent knobs**. For N ≥ bucket_count each bucket holds
  exactly 1/bucket_count of a file whatever N is. The one exception is the reason there's a floor:
  for **N < bucket_count each bucket used holds 1/N**.
- The doc's own next step: *"make `ALLOWED_FRAGMENT_COUNTS` size-derived rather than a fixed small
  set."* That is what this session did.

## 2. The policy

`fragmenter.plan_fragment_count(size)` — two drivers, larger wins, then clamp:

```python
large = ceil(size / TARGET_FRAGMENT_BYTES)              # 16 MiB — only bites above 112 MiB
small = min(DEFAULT_FRAGMENT_COUNT, ceil(size / MIN_FRAGMENT_BYTES))   # 1 MiB ramp, holds at 7
n     = clamp(max(large, small), 3, 64)
```

| Size | Fragments | Per fragment |
|---:|---:|---:|
| 10 KB | 3 | 3.3 KB |
| 2 MiB | 3 | 683 KB |
| 4 MiB | 4 | 1 MiB |
| 7 MiB | 7 | 1 MiB |
| 100 MiB | 7 | 14 MiB |
| 500 MiB | 32 | 16 MiB |
| 1 GiB | 64 | 16 MiB |
| 7 GB | 64 | 112 MiB |

Taking `max` of the two drivers rather than branching on size is what keeps the curve **monotonic** —
a naive `if size < X` split makes a 20 MiB file get *fewer* fragments than a 7 MiB one, which is
indefensible with two files side by side on screen.

**Mark chose the floor of 3** over keeping 7 as a hard minimum. The trade is explicit: a
sub-megabyte file now has 1/3 of its ciphertext in any one bucket rather than 1/7, in exchange for
3 KMS calls + 3 objects instead of 7 on objects where scatter was buying nothing. Both figures are
defence in depth either way — every fragment is separately AES-256-GCM encrypted under its own
KMS-wrapped key, so a bucket compromise alone yields nothing readable at any N.

Ceiling of 64 is the worker-pool cap, itself set from the 2026-07-26 EC2 sweep: 16 → 64 gave a real
15–30% gain, past 64 it flattens and per-call KMS latency gets *worse* (AWS request-rate
throttling, not a GIL limit).

## 3. What changed

- **`config.py`** — `ALLOWED_FRAGMENT_COUNTS = (3,5,7,11,16)` is gone, replaced by
  `MIN_FRAGMENT_BYTES` / `TARGET_FRAGMENT_BYTES` / `MIN_FRAGMENT_COUNT` / `MAX_FRAGMENT_COUNT`.
  The whitelist could not express a size-derived count, and validation is now a range check.
- **`pipeline.py`** — `store(..., fragment_count=N)` per call; constructor `fragment_count` becomes
  an optional *pin* (None = auto). `StoreResult.sizing` reports `auto` / `pinned` / `request`.
- **The worker pool moved from construct-time to per-call.** This was a latent bug waiting for this
  change: one service instance now writes a 3-fragment object and a 64-fragment object, and must
  read back a 7-fragment file written last month. `_workers_for(n)` sizes each fan-out to the work
  in front of it, including on `retrieve()` and `retrieval_plan()`, which take the count from the
  file's own index record.
- **`factory.py`** — `XINSERE_FRAGMENT_COUNT` unset or `auto` → size-derived. A number still pins,
  which is the rollback lever: set it to `7` and behaviour is exactly as before, no code deploy.
- **`/v1` API** — optional `fragment_count` form field on `POST /v1/files` and
  `POST /v1/files/finalize`, parsed and range-checked *before* quota is spent so a bad value is a
  400 rather than a 500 that still counted against the org. `GET /v1/ping` advertises
  `{mode, pinned, min, max}` so integrators don't guess.
- **TAMS** — the stale "needs a per-call fragment_count, that's pipeline work" note is now wrong
  and was removed; 2s segments land on the floor of 3 automatically. Ingest reports
  `fragments_per_segment`, and the UI states it.

## 4. Explicitly verified as unaffected

- **Blockchain.** `chain.py` and `XinserePermissions.sol` contain no reference to fragments at all.
  Merkle leaves are `keccak(SHA-256(file_id) ++ HMAC(grantee_id) [++ keccak(type)])` — file-scoped.
  Grant / revoke / verify / batch roots / the daily access seal are one record per **file**,
  whatever it is stored as. Fragment count never crosses the chain boundary, so read and write
  volume on Amoy is unchanged.
- **Invisible metadata marking.** `watermark.apply()` runs on reassembled whole-file bytes on the
  way *out* — preview (`app.py:1417`), download (`app.py:1540`), folder-zip (`app.py:1614`) — and
  `watermark.extract()` on a whole uploaded file. Nothing in the forensic-mark path sees fragments,
  so marks embed and extract identically at any N.
- **Existing files.** Retrieval has always read `fragment_count` off the file's index record. Every
  file already stored at 7 keeps working with no migration; test H11 asserts exactly this by
  reading a 16-fragment file back through a service pinned to 3.

## 5. Testing

- `lambdas/pipeline/tests/test_matrix.py` — **52 passed, 0 failed**, including new group H
  (12 checks): the curve, monotonicity across 211 sampled sizes, the 1 MiB floor holding,
  auto/pinned/request precedence, out-of-range rejection at both entry points, cross-policy
  retrieval, and worker-pool sizing.
- `demo/tests/test_fragment_sizing.py` (new) — **21 passed**: the API parse-and-reject guard,
  `/v1/ping`'s advertised policy, and that the displayed count comes from the stored value.
- Ran on this laptop. Two notes for whoever runs it next: `cryptography` **now has a win_arm64
  wheel** (46.0.3) so the pipeline matrix runs natively here, contradicting the 2026-08-03 session
  note; `web3` still has none, so the demo suite needs its web3 import stubbed on ARM64 Windows or
  a run on Sedona/CI.

## 6. Not done / next

- **Not deployed.** Committed and pushed only. First push to `main` is a production release, so
  this needs a deliberate deploy plus the `/api/warm` + `/` check from the 2026-08-03 gotchas.
- **The hosted app can't reach the top of the curve.** `MAX_STAGED_BYTES` is 500 MB, so the largest
  file app.xinsere.com will ever ingest lands at 32 fragments. 64 needs the EC2/Fargate path.
- **Wire all 12 cac1 buckets** (still 7 in the live config) — unrelated to count, but it is the
  knob that actually moves per-bucket exposure, and it is a zero-cost config change.
- Re-run `scripts/fragment_benchmark` from inside AWS against the *new* default before quoting
  fresh throughput numbers — the 2026-07-26 table was measured with a pinned count.
