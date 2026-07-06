"""Xinsere pipeline + blockchain benchmark.

Measures, across file sizes:
  - STORE   : fragment + per-fragment AES-256-GCM encrypt + write to buckets + index
  - RETRIEVE: read fragments + decrypt + reassemble + SHA-256 verify
  - CHAIN   : on-chain grant (write) and verify (read) on Amoy — size-independent,
              since only the opaque file_id is hashed, never the content.

Run:  cd demo ; .venv/Scripts/python benchmark.py [--no-chain]
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "pipeline"))
from xinsere_pipeline import PipelineService  # noqa: E402
from xinsere_pipeline.backends.local import (  # noqa: E402
    LocalIndexStore, LocalKeyManager, LocalObjectStore,
)

SIZES = [
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
    ("50 MB", 50 * 1024 * 1024),
    ("100 MB", 100 * 1024 * 1024),
]


def fmt_ms(s: float) -> str:
    return f"{s * 1000:8.1f}"


def mbps(nbytes: int, secs: float) -> str:
    if secs <= 0:
        return "   —"
    return f"{(nbytes / (1024 * 1024)) / secs:7.0f}"


def bench_pipeline() -> None:
    root = tempfile.mkdtemp(prefix="xinsere-bench-")
    try:
        # Disk-backed object store (like the real demo) so writes include real I/O.
        svc = PipelineService(
            LocalObjectStore(bucket_count=8, root=root),
            LocalKeyManager(),
            LocalIndexStore(),
            fragment_count=7,
        )
        print("\nPIPELINE (fragment + AES-256-GCM encrypt + disk write, N=7)")
        print(f"{'size':>8} | {'store ms':>9} | {'store MB/s':>10} | "
              f"{'retrieve ms':>11} | {'retr MB/s':>9} | {'ok':>3}")
        print("-" * 70)
        for label, n in SIZES:
            content = os.urandom(n)
            t = time.perf_counter()
            res = svc.store(content, "application/octet-stream")
            store_s = time.perf_counter() - t

            t = time.perf_counter()
            out = svc.retrieve(res.file_id)
            retr_s = time.perf_counter() - t

            ok = out.content == content
            print(f"{label:>8} | {fmt_ms(store_s)} | {mbps(n, store_s):>10} | "
                  f"{fmt_ms(retr_s):>11} | {mbps(n, retr_s):>9} | {'OK' if ok else 'BAD':>3}")
            del content, out
    finally:
        shutil.rmtree(root, ignore_errors=True)


def bench_chain() -> None:
    try:
        from chain import CHAIN
    except Exception as exc:  # noqa: BLE001
        print(f"\nCHAIN: skipped ({exc})")
        return
    print("\nBLOCKCHAIN (Amoy) — size-independent (hashes the file_id, not content)")
    try:
        # warm up (loads signer + RPC once)
        CHAIN.verify("bench-warm", "jeremy")
        reads = []
        for i in range(3):
            t = time.perf_counter(); CHAIN.verify(f"bench-read-{i}", "jeremy"); reads.append(time.perf_counter() - t)
        writes = []
        for i in range(3):
            fid = f"bench-grant-{int(time.time())}-{i}"
            t = time.perf_counter(); CHAIN.grant(fid, "jeremy"); writes.append(time.perf_counter() - t)
        print(f"  verify (read):  avg {sum(reads)/len(reads)*1000:6.0f} ms  "
              f"(min {min(reads)*1000:.0f} / max {max(reads)*1000:.0f})")
        print(f"  grant  (write): avg {sum(writes)/len(writes):6.2f} s   "
              f"(min {min(writes):.2f} / max {max(writes):.2f})  [mine + receipt]")
    except Exception as exc:  # noqa: BLE001
        print(f"  chain error: {exc}")


if __name__ == "__main__":
    print("=" * 70)
    print("Xinsere benchmark")
    print("=" * 70)
    bench_pipeline()
    if "--no-chain" not in sys.argv:
        bench_chain()
    print()
