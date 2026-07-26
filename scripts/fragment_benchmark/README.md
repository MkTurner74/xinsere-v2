# Fragment-count performance benchmark

Answers: independent of memory/OOM limits (see `scripts/ec2_ingest/`), does
fragment count materially change `store()`/`retrieve()` throughput? Reuses
the existing timing instrumentation on `StoreResult`/`RetrieveResult` — no
new instrumentation, just a harness that sweeps `fragment_count` past
today's `ALLOWED_FRAGMENT_COUNTS` cap (benchmark-only monkeypatch; production
validation in `config.py` is untouched).

**Must run from inside AWS** (EC2/Fargate) — from a home network the
~9.5x network-path gap already measured 2026-07-26 would swamp the signal.

## Running it

Reuses the same `xinsere-migrate` container image as Fargate/EC2 (already
has all deps). From an EC2 instance with the image available locally:

```bash
mkdir -p /bench
aws s3 cp s3://xinsere-dev-staging/fragment-benchmark/benchmark_fragment_counts.py /bench/
docker run --rm --network host -e XINSERE_BACKEND=aws -e AWS_REGION=us-east-1 \
  -e XINSERE_S3_BUCKETS="xinsere-dev-frag-cac1-01,...,xinsere-dev-frag-cac1-07" \
  -v /bench:/bench -w /app/demo \
  058264449111.dkr.ecr.us-east-1.amazonaws.com/xinsere-migrate:latest \
  python /bench/benchmark_fragment_counts.py --sizes 10,100,500 \
    --counts 7,16,32,64,128,256,1000 --out /bench/results.json
```

(Upload the script to the staging bucket first if it's changed since the
last run: `aws s3 cp benchmark_fragment_counts.py s3://xinsere-dev-staging/fragment-benchmark/`.)

## 2026-07-26 result summary

See `Fragment-Count-Bucket-Diversity-Findings-2026-07-26.md` (ai-brain docs
repo, projects/Xinsere/) for the full writeup. Headline: **throughput tracks
fragment SIZE, not fragment count** — falls off sharply below ~500KB-1MB per
fragment (the fixed 16-worker cap means more fragments beyond that just means
more sequential KMS/S3 round-trip batches), plateaus above ~1-3MB. Supports
the streaming-rearchitecture proposal's ~64MiB target fragment size.
