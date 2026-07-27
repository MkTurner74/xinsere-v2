# Session 2026-07-26 (part 4) — worker cap, real-scale route audit, non-AWS provider research

Follow-up to part 3 (region-biased routing + compute selector). New asks:
raise the worker cap based on the earlier scaling test, validate routing at
real scale (~1000 files from the actual Dropbox corpus), and look beyond AWS
for both storage and KMS-equivalent services.

## 1. Worker-pool cap: 16 -> 64

Extended `benchmark_fragment_counts.py` with a `--workers` override and ran a
real EC2 test (fragment_count=1000, workers=16/64/128/256/512, both 10MB and
105MB payloads). Result: 16->64 gave a real ~15-30% throughput gain; beyond
64 it flattens completely, and per-call latency actually **gets worse** —
KMS avg 8.4ms at 16 concurrent calls vs 67.8ms at 128. That's AWS's own
request-rate throttling, not a Python/GIL ceiling, so there's no case for
raising the cap further. Updated `pipeline.py`'s `min(fragment_count, 16)` ->
`min(fragment_count, 64)`. Note: under today's `ALLOWED_FRAGMENT_COUNTS`
(max 16) this is a no-op right now — it matters once fragment counts go
higher, which the future streaming rearchitecture will need.

## 2. Real-scale route-correctness audit (525 real files)

Built `scripts/route_audit/`: `stream_sample.py` streams `DropboxClient.walk()`
directly and stops per-size-bucket early instead of materializing the full
2.4TB tree first (the earlier `enumerate()`-based attempt was too slow to
wait on). Selected a stratified real sample, then deliberately capped the
three largest size-buckets to the 5 smallest files each — routing correctness
depends on fragment count and jitter, not file bytes, and the real corpus is
extremely top-heavy (81 of 591 sampled files = 97% of sampled bytes), so full
1:1 sampling would mean waiting on tens of GB of masters for zero extra
statistical confidence.

Ran 525 real files (18.25GB) through the full pipeline with a 60/25/15
EU/US-East/US-West bias. **525/525 succeeded, 0 failures**, 3,675 real
fragments through live S3+KMS+DynamoDB, each downloaded fresh from Dropbox.
Aggregate split: 57.14/28.57/14.29 — exactly the deterministic N=7
quantization (4/7, 2/7, 1/7), since every file used the same fragment count.
Worth being precise: this isn't new statistical proof beyond the earlier
single-file test, but it IS a clean real-scale proof that the full pipeline
holds up with zero failures at production settings. Took 4.6 hours
wall-clock — almost all of it the last ~10 large files, confirming large
masters really do dominate corpus processing time (matches the earlier
1TB-cost-model finding).

## 3. Non-AWS provider research

**Storage — a major unactioned finding.** A thorough assessment already
exists from 2026-07-12 (`projects/Xinsere/research/2026-07-12-storage-
provider-assessment.md`, ai-brain docs repo) recommending Backblaze B2 +
IDrive e2 + Cloudflare R2 + CoreWeave over AWS S3 — a 2.65TB tenant costs
~$290/month on AWS S3 at heavy download vs ~$16-40/month on the alternatives,
because AWS's $0.09/GB egress dominates everything else. The code
(`MultiCloudObjectStore`, `S3CompatObjectStore`, per-provider endpoint
helpers) is fully built and unit-tested (test_matrix.py Group E) but **never
deployed** — production is still 100% AWS S3.

**KMS alternatives + storage concurrency** (new research, filling gaps the
above doc didn't cover): Google Cloud KMS moved to a soft-enforced,
capacity-based quota model in Feb 2026 specifically designed to avoid
AWS-KMS-style throttling for the ops Xinsere needs — best candidate for a
real load test mirroring today's KMS benchmark. Azure Key Vault has hard
per-vault ceilings (worse for HSM keys than software keys). HashiCorp Vault
Transit's `/datakey/plaintext` is the closest architectural match to AWS
KMS's single-call envelope pattern. On storage: none of B2/R2/IDrive e2
publish an AWS-style auto-scaling spec or a controlled concurrency-latency
benchmark; one real amber flag — a third-party benchmark found R2's
small-object (1KB) p90 PUT latency far worse than S3's, relevant since
post-fragmentation objects at high fragment counts are exactly that small.
Actionable gap: run Xinsere's own concurrency-ramp test against these
providers rather than trust vendor docs.

## 4. HKDF architecture proposal (not built — needs sign-off)

Wrote up cutting KMS calls from N-per-file to 1-per-file: one real KMS call
gets a file master key, then each fragment's actual AES-GCM key is derived
locally via HKDF-SHA256 — no network call. This attacks the KMS-throttling
root cause directly (call volume) rather than tolerating it with a bigger
worker pool, and stays flat regardless of fragment count — much more
important once the streaming rearchitecture needs hundreds of fragments per
large file. Real trade-off: today's fragment-level key independence (one
leaked wrapped-key blob only exposes one fragment) becomes file-level (one
leaked master key + KMS access exposes the whole file) — though this is
largely theoretical given fragment wrapped-keys already all live in the same
DynamoDB table today, and the access-control model is already file-level, not
fragment-level. Written up honestly in
`Xinsere/KMS-Call-Reduction-HKDF-Proposal-2026-07-26.md` (ai-brain docs
repo) as a decision for Mark, not something to ship on the argument alone.

## Next steps (not done this session)
- Decide whether to deploy the existing non-AWS storage plan (B2/IDrive
  e2/R2/CoreWeave) — code is ready, just needs provider accounts + buckets.
- Run a real concurrency-ramp test against Google Cloud KMS and against
  B2/R2/IDrive e2, mirroring today's AWS KMS benchmark methodology.
- Decide on the HKDF proposal's security trade-off; if approved, prototype +
  benchmark before shipping.
- Cap concurrent large-file processing by in-flight bytes (still the
  smaller, faster OOM fix flagged earlier the same day — not done yet).
