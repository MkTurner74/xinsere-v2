"""Fast stratified sample builder for the route-correctness audit
(2026-07-26): streams `DropboxClient.walk()` directly and stops as soon as
every size bucket is full (or a hard scan cap is hit), instead of
materializing the whole 2.4TB tree first the way `MigrationRunner.enumerate()`
does -- that full walk is what made the first attempt at this too slow to
wait on.

Usage:
    python stream_sample.py --per-bucket 200 --scan-cap 30000 --out sample.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "demo"))

from dropbox_connector import DropboxAuth, DropboxClient, MigrationRunner, save_sample  # noqa: E402

FOLDER = "/Mark Turner"
INCLUDE_TOP = {"Mark Turner"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-bucket", type=int, default=200,
                    help="Target files per size bucket (6 buckets -> up to 6x this many total)")
    ap.add_argument("--scan-cap", type=int, default=30000,
                    help="Hard stop on files SCANNED (not sampled) -- safety valve if a bucket "
                         "never fills (e.g. very few 2GB+ files really exist in this corpus)")
    ap.add_argument("--out", default="stream_sample.json")
    args = ap.parse_args()

    auth = DropboxAuth()
    client = DropboxClient(auth)
    runner = MigrationRunner(client, include_top=INCLUDE_TOP)

    counts = {label: 0 for label, _, _ in runner._SIZE_BUCKETS}
    sampled = []
    scanned = 0
    t0 = time.perf_counter()

    for f in runner._walk(FOLDER):
        scanned += 1
        for label, lo, hi in runner._SIZE_BUCKETS:
            if f.size >= lo and (hi is None or f.size < hi):
                if counts[label] < args.per_bucket:
                    counts[label] += 1
                    sampled.append(f)
                break
        if scanned % 2000 == 0:
            print(f"  scanned={scanned} sampled={len(sampled)} "
                  f"counts={counts} elapsed={time.perf_counter()-t0:.0f}s",
                  file=sys.stderr, flush=True)
        if all(c >= args.per_bucket for c in counts.values()):
            print(f"All buckets full at scanned={scanned}", file=sys.stderr)
            break
        if scanned >= args.scan_cap:
            print(f"Hit scan cap ({args.scan_cap}) before every bucket filled -- "
                  f"some size buckets are naturally rarer in this corpus", file=sys.stderr)
            break

    total_gb = sum(f.size for f in sampled) / 1e9
    print(f"\nSample: {len(sampled)} files, {total_gb:.3f} GB, counts={counts}", file=sys.stderr)
    save_sample(sampled, args.out)
    print(f"Written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
