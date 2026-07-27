# Session 2026-07-26 (part 3) — region-biased routing, compute-tier selector, 1TB cost model

Follow-up to the same day's serial test + fragment benchmark + bucket
diversity work. New asks: (1) which compute tier fits which file size, and
can Lambda/Fargate actually handle real files, (2) what does ingesting 1TB
actually cost, (3) fill in the rest of the bucket count, (4) can the routing
API bias toward a region (EU vs US, east vs west coast), with a UX to show it
ahead of a UK trip, and (5) a job-profile-aware compute-tier selector that
weighs EC2's slower spin-up against Lambda's near-instant one on long jobs.

## 1. Compute tier vs file size, and the Lambda/Fargate capability question

Revisited the earlier 4-way OOM result with the serial test's finding: OOM
was a concurrency artifact, not a per-file ceiling. Reframed per-tier safe
file size as `memory_gb / 3` (the 2-4x multiplier the whole-file architecture
needs), crossed with Lambda's 15-minute timeout at measured 13.2MB/s
throughput (~11.6GB timeout-bound ceiling, looser than its ~3.3GB memory
ceiling). Recommendation: <1GB -> Lambda, 1-4GB -> Fargate, 4GB+ -> EC2, until
the streaming rearchitecture ships and removes the size dependency entirely
(Lambda's 15-min timeout is the one constraint that survives that rewrite).

Full writeup: `Compute-Tier-And-1TB-Cost-Model-2026-07-26.md` (ai-brain docs
repo, projects/Xinsere/).

## 2. 1TB ingest cost model

Built from real 2026-07-26 AWS list prices (S3, KMS, DynamoDB, EC2, Fargate,
Lambda, inter-region transfer). Headline: ~$25-45 one-time to ingest 1TB
(compute + inter-region fragment scatter, roughly 50/50 split), ~$24/month
storage after. The line item most likely to be missed in a back-of-envelope
estimate: inter-region transfer for scattered fragments (~$8-16/TB) is the
same order of magnitude as compute cost, not a rounding error. Fragment count
also turned out to be a real (if small) cost lever: KMS is billed per
fragment, so more fragments = more dollars, not just slower (reinforces the
2026-07-26 fragment-benchmark finding, doesn't fight it). Separately flagged:
S3-egress-to-internet ($0.09/GB) is ~9x storage cost and the actual number
that matters for the client's workstation-delivery use case -- not modeled
here, needs the real access pattern first.

## 3. Bucket count -- filled in, and a live OOM landmine found + fixed

Wired all 12 existing cac1 buckets into the live Fargate task definition
(was only 7) -- zero-cost, bucket infra already existed. While inspecting the
live task def (`xinsere-migrate:1`), found `XINSERE_MIGRATION_WORKERS=12` --
3x the concurrency that already OOM'd at just 4 concurrent large files in the
same day's earlier test, on the same 16GB Fargate tier. Registered a new
revision (`xinsere-migrate:2`) with 12 buckets + workers dropped to 1 (the
only proven-safe setting until the in-flight-bytes concurrency cap is built).
Previous revision still exists for rollback.

## 4. Region-biased routing (EU vs US, east vs west) + a real demo

Added `PipelineService(region_weights={"eu": 0.6, "us-east": 0.25, ...})`.
Design: `ObjectStore.region_group_for(bucket)` gives a coarse region label
(new on the base class, default "default"; AWS backend maps via a new
`_REGION_GROUP` table -- us-east-1/2 -> "us-east", us-west-1/2 -> "us-west",
ca-central-1 -> "canada", eu-west-2 -> "eu"). `fragmenter.route_region_weighted()`
picks a region group per the weights (via a cycle **sized to the file's own
fragment_count**, not a fixed resolution -- fixing a real bug where a
fixed-100-slot cycle sampled by a small, jitter-shifted window at low
fragment counts, missing the requested weights badly for any single file)
then modular-routes within that group's own buckets, so a strong bias still
spreads across every bucket in the favored region. `region_report(file_id)`
reports actual placement by region and bucket for observability/demo.
40/40 test-matrix checks pass (was 34; new Group F).

Provisioned 12 real EU/London (`eu-west-2`) buckets matching the existing
SSE-S3/public-access-block/CORS config exactly (IAM already covers them via
the existing `xinsere-dev-frag-*` wildcard, no policy change needed). Ran a
real end-to-end proof (`scripts/region_bias_demo/run_demo.py`) against live
AWS: stored + retrieved a file with a 60/25/15 EU/US-East/US-West bias,
round-trip verified byte-identical, actual placement (62.5/25/12.5 at N=16,
exact largest-remainder rounding) confirmed via `region_report()`. Captured
both a biased and an unbiased baseline run's real data for a demo page.

## 5. Compute-tier selector (job-profile-aware)

`xinsere_pipeline/compute_selector.py`: `recommend(JobProfile(total_bytes,
file_count, max_file_bytes))` -> the cheapest tier that can safely handle the
largest file today, factoring spin-up overhead (ballparked, not measured:
Lambda ~5s, Fargate ~45s, EC2 ~105s) against steady-state $/hour. Raises
(doesn't silently guess) if no tier is safe for the largest file at today's
whole-file-in-memory ceiling. Evaluates the three PROVEN configs (Lambda
10GB, Fargate 16GB/4vCPU, EC2 32GB) rather than a fully right-sized
optimizer -- recommending an untested smaller config would overclaim
confidence past what's actually been measured. 6 new test-matrix checks
(Group G) confirm: small jobs -> Lambda, files beyond every tier's ceiling
raise, oversized-for-Lambda files never recommend it, and long jobs with
small files favor Fargate/EC2 over Lambda despite Lambda being technically
capable (its 15-min-per-invocation ceiling makes it an awkward operational
fit at that scale even when chunkable).

## Demo page

Built an interactive artifact showing the real region-bias data (toggle
between baseline and EU-biased routing, live bucket manifest) plus the three
compute-tier scenarios, styled as a small ops console. Meant for the UK trip
this week.

## Next steps (not done this session)
- Cap concurrent large-file processing by in-flight bytes (the smaller,
  faster OOM fix flagged earlier the same day) -- would let
  XINSERE_MIGRATION_WORKERS go back above 1 safely.
- Decide whether to route the demo's region-bias policy into the real
  production factory config (`XINSERE_REGION_WEIGHTS` env var already wired)
  or keep it opt-in per deployment.
- Model S3-egress-to-internet cost once the client's real access pattern
  (frequency, location, workstation count) is known.
