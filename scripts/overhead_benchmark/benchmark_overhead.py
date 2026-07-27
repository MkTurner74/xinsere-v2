"""Xinsere-overhead benchmark (2026-07-27): isolates what Xinsere's pipeline
actually ADDS on top of a straight, unprocessed copy -- both in time and in
stored bytes -- across a range of real file sizes.

Every earlier benchmark this week (fragment-count, worker-cap, region-bias)
measured Xinsere's OWN throughput, but never against a baseline of "what if
we just copied the file as-is." This answers the actual question clients
ask: how much slower/bigger does Xinsere make a file, and does that change
with file size?

Method, per real Dropbox file:
  1. Download once from Dropbox (shared bytes/timing for both arms below --
     avoids a second download's network variance skewing the comparison).
  2. BASELINE: one whole-file S3 PUT to a single bucket/region, no encryption,
     no fragmentation, no index -- literally "copy the file to S3." Then one
     whole-file S3 GET back. Cleaned up after.
  3. XINSERE: the real store()/retrieve() pipeline, default production
     config (7 fragments, real multi-region scatter) -- reuses the existing
     timing instrumentation, no new instrumentation needed. Cleaned up after.
  4. Stored-byte overhead is computed analytically, not re-measured via extra
     S3 calls: AES-256-GCM appends exactly one 16-byte auth tag per
     encryption operation (the `cryptography` library's documented contract),
     so total fragment ciphertext bytes = original_size + fragment_count*16,
     deterministically -- confirmed once against real S3 object sizes in
     `verify_ciphertext_overhead()` rather than assumed on faith.
  5. DynamoDB metadata footprint (1 file record + N fragment records) is
     reported separately -- it's real storage, but a different KIND from
     "the S3 object got bigger," so it's not folded into the size-overhead %.

MUST run from inside AWS (same reason as fragment_benchmark and the earlier
serial/OOM tests): running from a home network reproduces the ~9.5x
network-path gap already measured, which would swamp the signal here just
as it would anywhere else.

Usage:
    python benchmark_overhead.py --files files.json --out overhead_results.json

`files.json` is a list of {"path": "...", "size": N} -- same shape as
scripts/route_audit's sample manifests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

# Two possible layouts: run from within the repo (scripts/overhead_benchmark/),
# or mounted standalone into the xinsere-migrate container at /bench (that
# image's real absolute layout is /app/demo + /app/lambdas/pipeline, WORKDIR
# /app/demo -- matches fragment_benchmark's same fix for the same reason).
for candidate in (
    os.path.join(os.path.dirname(__file__), "..", "..", "demo"),
    "/app/demo",
):
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)
        break
for candidate in (
    os.path.join(os.path.dirname(__file__), "..", "..", "lambdas", "pipeline"),
    "/app/lambdas/pipeline",
):
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)
        break

from dropbox_connector import DropboxAuth, DropboxClient  # noqa: E402
from xinsere_pipeline.backends.aws import DynamoIndexStore, KmsKeyManager, S3ObjectStore  # noqa: E402
from xinsere_pipeline.pipeline import PipelineService  # noqa: E402
from xinsere_pipeline.tenant import load_tenant_config  # noqa: E402

# Deliberately NOT xinsere-dev-staging: that bucket name doesn't match any
# segment in aws.py's _SEGMENT_REGION map, so S3ObjectStore falls back to a
# GetBucketLocation call the EC2 role isn't granted -- use a real fragment
# bucket instead (recognized via its "use1" segment, no extra API call, no
# IAM change needed). Storing one whole unencrypted object here is still a
# valid "straight copy" baseline -- this bypasses PipelineService entirely.
BASELINE_BUCKET = "xinsere-dev-frag-use1-01"
GCM_TAG_BYTES = 16

# Same representative multi-region bucket slice used elsewhere this week --
# a real file experiences real multi-region scatter, not a single-bucket
# best case, so the overhead number reflects what a customer actually sees.
FRAGMENT_BUCKETS = [
    "xinsere-dev-frag-cac1-01", "xinsere-dev-frag-cac1-02", "xinsere-dev-frag-cac1-03",
    "xinsere-dev-frag-use1-01", "xinsere-dev-frag-use1-02",
    "xinsere-dev-frag-use2-01", "xinsere-dev-frag-use2-02",
    "xinsere-dev-frag-usw1-01", "xinsere-dev-frag-usw1-02",
    "xinsere-dev-frag-usw2-01", "xinsere-dev-frag-usw2-02",
]


def verify_ciphertext_overhead(store, index, svc, content: bytes) -> int:
    """Store one throwaway file, sum its REAL fragment object sizes from S3,
    and confirm they equal original_size + fragment_count*16 exactly -- so
    the per-file report below can use the formula with real evidence behind
    it instead of asserting it on faith."""
    res = svc.store(content, "application/octet-stream", label="overhead-tag-check")
    frags = index.get_fragments(res.file_id)
    real_total = 0
    for fr in frags:
        real_total += len(store.get(fr.bucket, fr.fragment_id))
    svc.delete(res.file_id)
    expected = len(content) + res.fragment_count * GCM_TAG_BYTES
    ok = real_total == expected
    print(f"Ciphertext-overhead check: real={real_total} expected={expected} match={ok}",
          file=sys.stderr)
    if not ok:
        raise RuntimeError(
            f"AES-GCM tag-overhead assumption failed real-world check: "
            f"real={real_total} expected={expected} -- do not trust the analytical formula below")
    return GCM_TAG_BYTES


def bench_one(client, object_store, keys, index, svc, rec: dict) -> dict:
    path, size = rec["path"], rec["size"]

    t0 = time.perf_counter()
    content = client.download(path)
    download_s = time.perf_counter() - t0
    sha_before = hashlib.sha256(content).hexdigest()

    # --- Baseline: straight copy, no processing ---
    key = f"overhead-baseline/{hashlib.sha256(path.encode()).hexdigest()}"
    t0 = time.perf_counter()
    object_store.put(BASELINE_BUCKET, key, content)
    baseline_put_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    got_baseline = object_store.get(BASELINE_BUCKET, key)
    baseline_get_s = time.perf_counter() - t0
    baseline_ok = got_baseline == content
    object_store.delete(BASELINE_BUCKET, key)

    # --- Xinsere: full pipeline ---
    res = svc.store(content, "application/octet-stream", label="overhead-benchmark-2026-07-27")
    store_s = res.timings["total_ms"] / 1000

    got = svc.retrieve(res.file_id)
    retrieve_s = got.timings["total_ms"] / 1000
    xinsere_ok = hashlib.sha256(got.content).hexdigest() == sha_before
    fragment_count = res.fragment_count
    svc.delete(res.file_id)

    stored_bytes = size + fragment_count * GCM_TAG_BYTES  # AES-GCM tag per fragment, verified once
    dynamo_items = 1 + fragment_count  # 1 file record + N fragment records -- separate from S3 size

    def pct(xinsere_v, baseline_v):
        return round(100 * (xinsere_v - baseline_v) / baseline_v, 1) if baseline_v > 0 else None

    return {
        "path": path,
        "size_bytes": size,
        "download_s": round(download_s, 3),
        "baseline_put_s": round(baseline_put_s, 3),
        "baseline_get_s": round(baseline_get_s, 3),
        "xinsere_store_s": round(store_s, 3),
        "xinsere_retrieve_s": round(retrieve_s, 3),
        "store_overhead_ms": round((store_s - baseline_put_s) * 1000, 1),
        "store_overhead_pct": pct(store_s, baseline_put_s),
        "retrieve_overhead_ms": round((retrieve_s - baseline_get_s) * 1000, 1),
        "retrieve_overhead_pct": pct(retrieve_s, baseline_get_s),
        "fragment_count": fragment_count,
        "stored_bytes": stored_bytes,
        "size_overhead_bytes": stored_bytes - size,
        "size_overhead_pct": round(100 * (stored_bytes - size) / size, 6) if size > 0 else None,
        "dynamodb_items": dynamo_items,
        "baseline_ok": baseline_ok,
        "xinsere_ok": xinsere_ok,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", required=True, help="JSON list of {path, size}")
    ap.add_argument("--out", default="overhead_results.json")
    args = ap.parse_args()

    with open(args.files, encoding="utf-8") as f:
        files = json.load(f)

    auth = DropboxAuth()
    client = DropboxClient(auth)

    key_id = os.environ.get("XINSERE_KMS_KEY_ID") or load_tenant_config()["kms_key_id"]
    object_store = S3ObjectStore(FRAGMENT_BUCKETS)
    keys = KmsKeyManager(key_id)
    index = DynamoIndexStore(
        os.environ.get("XINSERE_FILES_TABLE", "xinsere_files"),
        os.environ.get("XINSERE_FRAGMENTS_TABLE", "xinsere_fragments"),
        sha_index=os.environ.get("XINSERE_SHA_INDEX", "sha-index"),
    )
    svc = PipelineService(object_store, keys, index, fragment_count=7)

    # One real-world confirmation of the AES-GCM tag-overhead formula before
    # trusting it for every file below.
    verify_ciphertext_overhead(object_store, index, svc, os.urandom(1024 * 1024))

    results = []
    print(f"{'size':>12} {'dl(s)':>7} {'base_put':>9} {'xin_store':>10} {'store OH':>12} "
          f"{'base_get':>9} {'xin_retr':>9} {'retr OH':>12} {'size OH':>10}")
    print("-" * 110)
    for rec in files:
        r = bench_one(client, object_store, keys, index, svc, rec)
        results.append(r)
        print(f"{r['size_bytes']/1e6:>10.2f}MB {r['download_s']:>7.2f} "
              f"{r['baseline_put_s']:>9.2f} {r['xinsere_store_s']:>10.2f} "
              f"{r['store_overhead_ms']:>8.0f}ms/{r['store_overhead_pct']}% "
              f"{r['baseline_get_s']:>9.2f} {r['xinsere_retrieve_s']:>9.2f} "
              f"{r['retrieve_overhead_ms']:>8.0f}ms/{r['retrieve_overhead_pct']}% "
              f"{r['size_overhead_bytes']:>6}B/{r['size_overhead_pct']}%",
              flush=True)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results written to {args.out}")


if __name__ == "__main__":
    main()
