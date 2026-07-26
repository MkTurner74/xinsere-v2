# Session 2026-07-26 — 4-way compute comparison: EC2/Fargate/Lambda all OOM

Follow-up to the 2026-07-26 single-config EC2 test session. Mark asked for a
controlled comparison: the same ~10 files, different sizes, run identically
on EC2 (multiple types), Lambda, and Fargate.

## What was built
- `scripts/ec2_ingest/launch.py`: `--root` override so each compute config
  targets its own destination subfolder — otherwise a second config's run
  just resume-skips whatever a prior config already ingested, instead of
  measuring a real cold ingest of the same sample.
- `dropbox_connector.py`: `sample_per_bucket()` (stratified, deterministic
  sample builder) and `save_sample()`/`load_sample()` (persist + replay the
  exact same file set across configs). `load_sample()` also transparently
  handles `s3://` URIs (downloads to `/tmp` first) — needed after Fargate's
  run-task override passed a raw S3 URI straight through and crashed on it.
- `scripts/lambda_ingest/`: a full new Lambda deployment (container image,
  IAM role, `deploy_and_test.py`) running the *same* `MigrationRunner.run()`
  logic as Fargate/EC2 via a handler that returns the JSON report directly —
  deliberately not through Lambda's interactive HTTP response-streaming path
  (the documented 6MB/2MB-per-second ceiling from the 2026-07-24 research),
  so this tests Lambda's compute/memory/network characteristics for the
  ingest workload specifically.
- Created 4 destination test subfolders under the real "Dropbox Import" root,
  one per config (`ec2-c7i-4xlarge`, `ec2-c7g-4xlarge`, `fargate-baseline`,
  `lambda`).

## Bugs hit and fixed along the way (all real, all pushed)
1. `assert_correct_account()` guard needed for the Lambda script too (same
   class of mistake as the EC2 launcher's earlier account mix-up).
2. `docker buildx build --push` attaches an OCI attestation manifest list by
   default — Lambda's `CreateFunction` rejects it outright. Fixed with
   `--provenance=false --sbom=false`.
3. `AWS_REGION` is a Lambda-reserved env var — `UpdateFunctionConfiguration`
   rejects any attempt to set it manually. Dropped from the env dict (the
   handler's `os.environ.get` fallback already covers it).
4. `load_sample()` didn't handle `s3://` URIs — worked for EC2 (which
   pre-downloads via `aws s3 cp` in user-data before setting the env var) but
   Fargate's run-task override passed the raw URI straight to the container,
   crashing on `open("s3://...")`. Fixed by teaching `load_sample()` itself to
   detect and download `s3://` paths, so every consumer gets it for free.
5. boto3's default 60s client read-timeout raced Lambda's own 900s execution
   timeout — the function was still legitimately running when the client
   gave up and reported a false failure. Fixed with an explicit 910s
   `read_timeout`.

## The actual result

Built a real stratified 12-file sample from the full corpus (209,488 files /
2.65TB enumerated once — took ~46 minutes over the public internet, no
per-folder progress logging exists today) spanning 27KB to two 7.14GB video
files, 16.44GB total. Ran it identically on:

| Config | Memory | Result |
|---|---:|---|
| Lambda | 10,240MB (max) | OOM after 452s |
| Fargate (existing task) | 16GB | OOM (SIGKILL, exit 137) |
| EC2 c7i.4xlarge | 32GB | OOM (kernel OOM-killer, ~31.6GB RSS) |
| EC2 c7g.4xlarge | 32GB | OOM (kernel OOM-killer, ~31.6GB RSS) |

All four verified exactly the same 4 smallest files (all <1.5MB), then died
on the next batch. **This is not a speed comparison result — it's proof that
the pipeline's whole-file-in-memory design (no streaming in `store()`/
`retrieve()`) cannot process realistic media file sizes on any tested
compute tier**, not just Lambda's already-known response-streaming
limitation. Lambda's failure is the most conclusive since 10GB is its hard
ceiling — no bigger Lambda exists. EC2 at 32GB (2x Fargate, 3x+ Lambda's max)
also failed, meaning the real requirement is well above 32GB for this file
mix.

Full writeup: `Cloud-Performance-Test-Matrix-2026-07-24.md` in the ai-brain
docs repo (projects/Xinsere/).

## Not done / next
- This reframes the priority: before more compute-tier benchmarking, the
  pipeline needs either (a) a streaming rewrite of `store()`/`retrieve()` so
  memory use doesn't scale with file size, or (b) as a stopgap, a much larger
  memory allocation (try 64GB+ EC2/Fargate) to establish where the real
  ceiling is.
- All test AWS resources torn down (instances terminated, no stray cost);
  Lambda function and EC2/Lambda IAM roles left in place for reuse.
- The 4 destination test subfolders (with their partial 4-file ingests) are
  still in Xinsere under "Dropbox Import" — harmless, but worth knowing
  they're there if cleaning up test data later.
