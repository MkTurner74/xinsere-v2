"""Route-correctness audit at real scale (2026-07-26): ingest a real,
stratified slice of the actual Dropbox corpus through the full pipeline with
region-biased routing, verify every round-trip, and check the AGGREGATE
region distribution across many independent files (each with its own random
jitter) converges to the requested weights -- a different statistical
property than the single-file proofs already run (region_bias_demo/), which
only show one file's own fragments land close to the target split.

Deliberately caps the largest three size buckets instead of taking the full
stratified sample 1:1 -- routing correctness depends on fragment count and
jitter, not file size or content, and the corpus's own byte distribution is
extremely top-heavy (81 of 591 sampled files -- the 100MB+ buckets -- account
for 97% of sampled bytes). Full 1:1 sampling would mean waiting on tens of GB
of large-master downloads for zero additional statistical confidence about
routing. This test data is deleted after the audit -- it's a correctness
check, not a real migration run.

Usage:
    python run_audit.py --sample stream_sample_path.json \
        --weights eu=0.6,us-east=0.25,us-west=0.15 --large-cap 5 --out audit_report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "demo"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambdas", "pipeline"))

from dropbox_connector import DropboxAuth, DropboxClient  # noqa: E402
from xinsere_pipeline.backends.aws import DynamoIndexStore, KmsKeyManager, S3ObjectStore  # noqa: E402
from xinsere_pipeline.pipeline import PipelineService  # noqa: E402
from xinsere_pipeline.tenant import load_tenant_config  # noqa: E402

# Same representative multi-region bucket slice as scripts/region_bias_demo/run_demo.py.
DEMO_BUCKETS = [
    "xinsere-dev-frag-euw2-01", "xinsere-dev-frag-euw2-02", "xinsere-dev-frag-euw2-03",
    "xinsere-dev-frag-use1-01", "xinsere-dev-frag-use1-02",
    "xinsere-dev-frag-use2-01", "xinsere-dev-frag-use2-02",
    "xinsere-dev-frag-usw1-01", "xinsere-dev-frag-usw1-02",
    "xinsere-dev-frag-usw2-01", "xinsere-dev-frag-usw2-02",
]


def parse_weights(raw: str) -> dict[str, float]:
    weights: dict[str, float] = {}
    for part in raw.split(","):
        group, _, val = part.partition("=")
        weights[group.strip()] = float(val.strip())
    return weights


SIZE_BUCKETS = (
    ("<128KB", 0, 128 * 1024),
    ("128KB-10MB", 128 * 1024, 10 * 1024 * 1024),
    ("10-100MB", 10 * 1024 * 1024, 100 * 1024 * 1024),
    ("100-500MB", 100 * 1024 * 1024, 500 * 1024 * 1024),
    ("500MB-2GB", 500 * 1024 * 1024, 2 * 1024 ** 3),
    ("2GB+", 2 * 1024 ** 3, None),
)
LARGE_BUCKETS = {"100-500MB", "500MB-2GB", "2GB+"}


def select_files(sample_json_path: str, large_cap: int) -> list[dict]:
    with open(sample_json_path, encoding="utf-8") as f:
        rows = json.load(f)
    by_bucket: dict[str, list[dict]] = {label: [] for label, _, _ in SIZE_BUCKETS}
    for r in rows:
        size = r["size"]
        for label, lo, hi in SIZE_BUCKETS:
            if size >= lo and (hi is None or size < hi):
                by_bucket[label].append(r)
                break
    selected: list[dict] = []
    for label, files in by_bucket.items():
        if label in LARGE_BUCKETS:
            files = sorted(files, key=lambda r: r["size"])[:large_cap]  # smallest-first
        selected.extend(files)
    return selected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--weights", default="eu=0.6,us-east=0.25,us-west=0.15")
    ap.add_argument("--fragments", type=int, default=7)
    ap.add_argument("--large-cap", type=int, default=5)
    ap.add_argument("--out", default="audit_report.json")
    args = ap.parse_args()

    weights = parse_weights(args.weights)
    files = select_files(args.sample, args.large_cap)
    total_gb = sum(r["size"] for r in files) / 1e9
    print(f"Auditing {len(files)} real files, {total_gb:.2f}GB total, weights={weights}",
          flush=True)

    auth = DropboxAuth()
    client = DropboxClient(auth)

    key_id = os.environ.get("XINSERE_KMS_KEY_ID") or load_tenant_config()["kms_key_id"]
    store = S3ObjectStore(DEMO_BUCKETS)
    keys = KmsKeyManager(key_id)
    index = DynamoIndexStore(
        os.environ.get("XINSERE_FILES_TABLE", "xinsere_files"),
        os.environ.get("XINSERE_FRAGMENTS_TABLE", "xinsere_fragments"),
        sha_index=os.environ.get("XINSERE_SHA_INDEX", "sha-index"),
    )
    svc = PipelineService(store, keys, index, fragment_count=args.fragments,
                          region_weights=weights)

    agg_group: dict[str, int] = {}
    agg_bucket: dict[str, int] = {}
    failures: list[dict] = []
    total_frags = 0
    t0 = time.perf_counter()

    for i, rec in enumerate(files, 1):
        try:
            content = client.download(rec["path"])
            sha_before = hashlib.sha256(content).hexdigest()
            res = svc.store(content, "application/octet-stream", label="route-audit-2026-07-26")
            got = svc.retrieve(res.file_id)
            ok = hashlib.sha256(got.content).hexdigest() == sha_before
            report = svc.region_report(res.file_id)
            if not ok:
                failures.append({"path": rec["path"], "reason": "round_trip_mismatch"})
            else:
                for g, v in report["by_region_group"].items():
                    agg_group[g] = agg_group.get(g, 0) + v["fragments"]
                for b, n in report["by_bucket"].items():
                    agg_bucket[b] = agg_bucket.get(b, 0) + n
                total_frags += report["fragment_count"]
            svc.delete(res.file_id)  # audit data, not a real migration -- clean up
        except Exception as exc:  # noqa: BLE001 -- audit must record, not crash mid-run
            failures.append({"path": rec["path"], "reason": f"{type(exc).__name__}: {exc}"})

        if i % 25 == 0 or i == len(files):
            print(f"  {i}/{len(files)} done, {len(failures)} failures, "
                  f"elapsed={time.perf_counter()-t0:.0f}s", flush=True)

    observed_pct = {g: round(100 * n / total_frags, 2) for g, n in agg_group.items()} if total_frags else {}
    report = {
        "files_attempted": len(files),
        "files_failed": len(failures),
        "failures": failures,
        "total_fragments": total_frags,
        "requested_weights": weights,
        "observed_pct_by_region_group": observed_pct,
        "observed_fragments_by_bucket": agg_bucket,
        "elapsed_s": round(time.perf_counter() - t0, 1),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))
    print(f"\nReport written to {args.out}")


if __name__ == "__main__":
    main()
