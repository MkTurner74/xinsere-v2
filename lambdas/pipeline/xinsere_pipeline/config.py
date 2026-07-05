"""Pipeline configuration and constants."""
from __future__ import annotations

# Allowed fragment counts (PRD: default 7, configurable). Odd counts avoid a
# clean halving that could aid correlation.
ALLOWED_FRAGMENT_COUNTS = (3, 5, 7, 11, 16)
DEFAULT_FRAGMENT_COUNT = 7

# AES-256-GCM: 32-byte key, 12-byte nonce, 16-byte auth tag. GCM is authenticated,
# so any tampering with a fragment is detected on decrypt (raises InvalidTag).
DATA_KEY_BYTES = 32
NONCE_BYTES = 12

# Routing modes for distributing fragments across buckets.
ROUTE_MODULAR = "modular"   # seq (+ per-file jitter) % bucket_count
ROUTE_HYBRID = "hybrid"     # odd -> customer buckets, even -> Xinsere buckets
