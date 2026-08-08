"""Pipeline configuration and constants."""
from __future__ import annotations

# --- Fragment sizing ---------------------------------------------------------
# Fragment count is DERIVED FROM FILE SIZE (fragmenter.plan_fragment_count); it
# is no longer a fixed 7 for everything. The 2026-07-26 EC2 benchmark settled
# the shape: throughput tracks fragment SIZE, not fragment count. Below roughly
# 500KB-1MB per fragment it collapses (per-call KMS/S3 latency stops being
# amortized -- 10MB went 23.4 -> 1.1 MB/s from 32 to 1000 fragments); above
# ~1-3MB it plateaus. So the constants below are size targets, and the count
# falls out of them.
MIN_FRAGMENT_BYTES = 1 * 1024 * 1024        # the measured knee -- don't go under
TARGET_FRAGMENT_BYTES = 16 * 1024 * 1024    # plateau, and far under S3's 5GB PUT

# The count a mid-sized file settles at: everything from 7 MiB to 112 MiB gets
# exactly this, so the familiar "scattered 7 ways" story is unchanged for the
# overwhelming majority of files.
DEFAULT_FRAGMENT_COUNT = 7

# Floor: below 3 the scatter claim stops meaning anything. Note this is the ONE
# place count affects security -- for N >= bucket_count each bucket holds
# exactly 1/bucket_count of a file regardless of N, but for N < bucket_count
# each bucket used holds 1/N (2026-07-26 findings, §3).
MIN_FRAGMENT_COUNT = 3
# Ceiling: the worker pool caps at 64 (raised 16 -> 64 on real EC2 data), and
# past that AWS's own request-rate throttling makes per-call latency worse.
# More fragments than workers just means more sequential round-trip batches.
MAX_FRAGMENT_COUNT = 64

# AES-256-GCM: 32-byte key, 12-byte nonce, 16-byte auth tag. GCM is authenticated,
# so any tampering with a fragment is detected on decrypt (raises InvalidTag).
DATA_KEY_BYTES = 32
NONCE_BYTES = 12

# Routing modes for distributing fragments across buckets.
ROUTE_MODULAR = "modular"   # seq (+ per-file jitter) % bucket_count
ROUTE_HYBRID = "hybrid"     # odd -> customer buckets, even -> Xinsere buckets
