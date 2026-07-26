# Session 2026-07-26 (part 2) — serial isolating test, fragment benchmark, bucket diversity

Follow-up to the same day's 4-way compute comparison (all configs OOM'd on
7.14GB files). Three asks: (1) complete the OOM dataset with a serial test,
(2) build a way to measure read/write performance at different fragment
counts, (3) reconcile fragment count against bucket-diversity/regional
security constraints.

## 1. Serial (workers=1) test — changes the OOM diagnosis

Re-ran the same 12-file/16.44GB sample on the same `c7i.4xlarge` (32GB) that
OOM'd earlier, serially instead of concurrent (workers=4). **All 8 remaining
files verified, including both 7.14GB videos, zero failures** — 16.436GB,
1244.9s, 13.2MB/s. Memory checked mid-run: 3.6GB/32GB used while starting the
second 7.14GB file; 381MB after completion.

**Conclusion: the OOM was a concurrency artifact, not a per-file memory
requirement.** A single 7.14GB file alone needs nowhere near 32GB. This
means a smaller, faster fix exists alongside the full streaming rewrite:
cap concurrent large-file processing in the outer worker pool (e.g. by
cumulative in-flight bytes, not just a flat worker count).

## 2. Fragment-count performance benchmark

New `scripts/fragment_benchmark/benchmark_fragment_counts.py` — reuses the
existing `StoreResult`/`RetrieveResult` timing instrumentation (no new
instrumentation needed), sweeps `fragment_count` past today's
`ALLOWED_FRAGMENT_COUNTS` cap via a benchmark-only monkeypatch (production
validation untouched). Must run from inside AWS (confirmed the ~9.5x
network-path gap from earlier in the day would otherwise swamp the signal).

Ran on the same EC2 instance (10MB and 100MiB files, N=7 through 1000).
**Result: throughput tracks fragment SIZE, not fragment count.** Comparable
throughput at comparable fragment sizes regardless of file size (e.g. 10MB@128
fragments [78KB each] ≈ 100MiB@1000 fragments [105KB each], both ~8-11MB/s).
Falls off sharply below ~500KB-1MB per fragment (fixed 16-worker cap means
more fragments beyond 16 = more sequential KMS/S3 round-trip batches, not
more parallelism); plateaus above ~1-3MB per fragment. Supports the
streaming proposal's ~64MiB target fragment size.

## 3. Bucket diversity — real math, real current state

Worked out `fragmenter.route()`'s modular routing precisely: for N ≥
bucket_count, the fraction of a file's fragments in any one bucket converges
to exactly `1/bucket_count`, **independent of fragment count**. More
fragments (given fixed bucket count) does not concentrate a file's data more
in any bucket — it only increases the *number* of small objects per bucket.
Fragment count and bucket diversity are independent knobs, not a joint
trade-off.

Real inventory check: **12 buckets provisioned per region** (cac1/use1/use2/
usw1/usw2 = 60 total), but the live task config only wires in 7 of the 12
cac1 buckets. **Zero buckets exist in any EU/Germany region** — `aws.py`'s
region-segment map doesn't even have an entry for one yet.

Full writeup with tables: `Fragment-Count-Bucket-Diversity-Findings-
2026-07-26.md` (ai-brain docs repo, projects/Xinsere/).

## Cleanup
All EC2 test instances terminated, no stray cost. Benchmark results archived
at `scripts/fragment_benchmark/results-2026-07-26.json`.

## Next steps (not done this session)
- Cap concurrent large-file processing in the worker pool (smaller,
  near-term fix distinct from the full streaming rewrite).
- Wire all 12 existing cac1 buckets into the live config (zero-cost).
- Decide on EU/Germany bucket provisioning ahead of need vs. reactively.
- Streaming rearchitecture itself (see the separate proposal doc) — target
  ~64MiB fragments per this session's benchmark data.
