"""Real-AWS demo: store a file with region-biased routing, then report where
its fragments actually landed. Built 2026-07-26 for the EU/US region-bias
capability (PipelineService(region_weights=...)) -- proves it against real S3
across 3 real region groups (EU/London, US-East, US-West), not just the local
unit tests.

Usage (needs real AWS creds + XINSERE_KMS_KEY_ID / tenant secret already
configured, same as any other script in this repo):
    python run_demo.py --weights eu=0.6,us-east=0.25,us-west=0.15 \
        --fragments 32 --size-mb 5 --out report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                 "lambdas", "pipeline"))

from xinsere_pipeline.backends.aws import DynamoIndexStore, KmsKeyManager, S3ObjectStore  # noqa: E402
from xinsere_pipeline.pipeline import PipelineService  # noqa: E402
from xinsere_pipeline.tenant import load_tenant_config  # noqa: E402

# The 3 region groups this demo exercises -- a representative slice of the
# full bucket inventory (12/region), enough to show real cross-region scatter
# without every fragment needing its own unique bucket.
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--weights", default="eu=0.6,us-east=0.25,us-west=0.15")
    ap.add_argument("--fragments", type=int, default=32)
    ap.add_argument("--size-mb", type=int, default=5)
    ap.add_argument("--out", default="region_bias_report.json")
    args = ap.parse_args()

    weights = parse_weights(args.weights)
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

    content = os.urandom(args.size_mb * 1024 * 1024)
    print(f"Storing {args.size_mb}MB across {args.fragments} fragments, "
          f"region weights={weights} ...")
    res = svc.store(content, "application/octet-stream", label="uk-region-bias-demo")

    got = svc.retrieve(res.file_id)
    ok = got.content == content
    print(f"Round-trip: {'OK' if ok else 'FAILED'}")

    report = svc.region_report(res.file_id)
    print(json.dumps(report, indent=2))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"requested_weights": weights, "round_trip_ok": ok, **report}, f, indent=2)
    print(f"\nReport written to {args.out}")

    svc.delete(res.file_id)  # demo data, clean up
    print("Cleaned up (fragments + index deleted).")


if __name__ == "__main__":
    main()
