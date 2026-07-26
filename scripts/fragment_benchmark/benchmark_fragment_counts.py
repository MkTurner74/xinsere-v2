"""Fragment-count x file-size performance benchmark against REAL AWS backends
(S3 + KMS + DynamoDB) -- Cloud-Performance-Test-Matrix, 2026-07-26.

Answers a narrower question than the OOM test: independent of memory limits,
does fragment count materially change store()/retrieve() throughput and
per-stage latency (KMS vs S3 vs AES-GCM)? Deliberately uses file sizes that
stay well under any memory ceiling (default up to 500MB) so results reflect
the fragment-count variable alone, not a confounded OOM risk -- the serial
EC2 test (same day) is what isolates the memory/OOM breakpoint.

MUST run from inside AWS (EC2/Fargate) to mean anything -- running this from
a home network reproduces the ~9.5x network-path gap already measured
2026-07-26, which would swamp the fragment-count signal entirely.

Reuses the existing store()/retrieve() timing instrumentation (StoreResult/
RetrieveResult.timings, added this session) -- no new instrumentation needed,
just a harness that sweeps the fragment_count knob past today's
ALLOWED_FRAGMENT_COUNTS cap (3,5,7,11,16) for benchmarking purposes only
(monkeypatches the pipeline module's bound name -- production validation in
config.py is untouched).

Usage (env: XINSERE_BACKEND=aws, XINSERE_S3_BUCKETS, AWS_REGION already set,
same as any other script in this repo):
    python benchmark_fragment_counts.py --sizes 10,100,500 \
        --counts 7,16,32,64,128,256,1000 --out results.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

# Two possible layouts: run from within the repo (scripts/fragment_benchmark/),
# or mounted standalone into the xinsere-migrate container at /bench (matches
# that image's WORKDIR /app/demo convention, same as dropbox_connector.py's
# own "../lambdas/pipeline" relative insert).
for candidate in (
    os.path.join(os.path.dirname(__file__), "..", "..", "lambdas", "pipeline"),
    "../lambdas/pipeline",
):
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)
        break

import xinsere_pipeline.pipeline as pipeline_module  # noqa: E402
from xinsere_pipeline.factory import _build_object_store  # noqa: E402
from xinsere_pipeline.backends.aws import DynamoIndexStore, KmsKeyManager  # noqa: E402
from xinsere_pipeline.tenant import load_tenant_config  # noqa: E402


def _agg_row(agg: dict) -> str:
    return f"max={agg['max']:.1f} avg={agg['avg']:.1f}"


def build_backends():
    key_id = os.environ.get("XINSERE_KMS_KEY_ID") or load_tenant_config()["kms_key_id"]
    files_table = os.environ.get("XINSERE_FILES_TABLE", "xinsere_files")
    frags_table = os.environ.get("XINSERE_FRAGMENTS_TABLE", "xinsere_fragments")
    sha_index = os.environ.get("XINSERE_SHA_INDEX", "sha-index")
    return (_build_object_store(), KmsKeyManager(key_id),
           DynamoIndexStore(files_table, frags_table, sha_index=sha_index))


def bench_one(object_store, key_manager, index_store, size: int, fragment_count: int) -> dict:
    # Benchmark-only override of the fragment-count validation -- production
    # code (config.py / everywhere else) is untouched. See module docstring.
    pipeline_module.ALLOWED_FRAGMENT_COUNTS = tuple(
        set(pipeline_module.ALLOWED_FRAGMENT_COUNTS) | {fragment_count})
    svc = pipeline_module.PipelineService(
        object_store, key_manager, index_store, fragment_count=fragment_count)

    content = os.urandom(size)
    sha_before = hashlib.sha256(content).hexdigest()

    t0 = time.perf_counter()
    res = svc.store(content, "application/octet-stream")
    store_wall_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    got = svc.retrieve(res.file_id)
    retrieve_wall_s = time.perf_counter() - t0

    ok = hashlib.sha256(got.content).hexdigest() == sha_before
    svc.delete(res.file_id)   # clean up -- this is synthetic benchmark data

    mb = size / 1e6
    return {
        "size_bytes": size, "fragment_count": fragment_count, "ok": ok,
        "store_wall_s": round(store_wall_s, 3), "store_mb_s": round(mb / store_wall_s, 2),
        "retrieve_wall_s": round(retrieve_wall_s, 3),
        "retrieve_mb_s": round(mb / retrieve_wall_s, 2),
        "store_timings": res.timings, "retrieve_timings": got.timings,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sizes", default="10,100,500", help="Comma-separated MB sizes")
    ap.add_argument("--counts", default="7,16,32,64,128,256,1000",
                    help="Comma-separated fragment counts")
    ap.add_argument("--out", default="fragment_benchmark_results.json")
    args = ap.parse_args()

    sizes = [int(s) * 1024 * 1024 for s in args.sizes.split(",")]
    counts = [int(c) for c in args.counts.split(",")]

    object_store, key_manager, index_store = build_backends()

    results = []
    print(f"{'size(MB)':>9} {'frags':>6} {'store s':>9} {'store MB/s':>11} "
          f"{'retr s':>8} {'retr MB/s':>10} {'kms(store)':>18} {'s3(store)':>18} "
          f"{'s3(retr)':>18} {'kms(retr)':>18} {'ok':>4}")
    print("-" * 150)
    for size in sizes:
        for count in counts:
            r = bench_one(object_store, key_manager, index_store, size, count)
            results.append(r)
            st, rt = r["store_timings"], r["retrieve_timings"]
            print(f"{size/1e6:>9.0f} {count:>6} {r['store_wall_s']:>9.2f} "
                  f"{r['store_mb_s']:>11.1f} {r['retrieve_wall_s']:>8.2f} "
                  f"{r['retrieve_mb_s']:>10.1f} "
                  f"{_agg_row(st['kms_generate']):>18} {_agg_row(st['s3_put']):>18} "
                  f"{_agg_row(rt['s3_get']):>18} {_agg_row(rt['kms_decrypt']):>18} "
                  f"{'OK' if r['ok'] else 'BAD':>4}", flush=True)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results (incl. per-stage timings) written to {args.out}")


if __name__ == "__main__":
    main()
