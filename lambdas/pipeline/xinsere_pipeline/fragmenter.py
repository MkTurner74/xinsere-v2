"""Fragmentation and bucket routing.

Splitting is contiguous and as even as possible; each fragment is encrypted
independently by the pipeline, so a stored fragment is always ciphertext — never
a readable slice of the original.
"""
from __future__ import annotations

from .config import (
    DEFAULT_FRAGMENT_COUNT,
    MAX_FRAGMENT_COUNT,
    MIN_FRAGMENT_BYTES,
    MIN_FRAGMENT_COUNT,
    ROUTE_HYBRID,
    ROUTE_MODULAR,
    TARGET_FRAGMENT_BYTES,
)


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def plan_fragment_count(size: int) -> int:
    """How many fragments a file of `size` bytes should be split into.

    Replaces the flat 7-for-everything default. Two independent drivers, and the
    larger wins, so the curve is monotonic in file size:

    * the LARGE driver, `size / TARGET_FRAGMENT_BYTES`, only bites above 112 MiB
      and keeps big files near the 16 MiB throughput plateau instead of handing
      one worker a multi-gigabyte fragment;
    * the SMALL driver, `size / MIN_FRAGMENT_BYTES` held at DEFAULT_FRAGMENT_COUNT,
      ramps a small file up to 7 rather than starting there -- a 2s media segment
      or a 10KB text file paid 7 KMS calls + 7 S3 PUTs to scatter a few hundred
      bytes each, which is latency and cost with no scatter benefit.

    Then clamp to [MIN_FRAGMENT_COUNT, MAX_FRAGMENT_COUNT]. The resulting curve:

        10 KB -> 3      7 MiB -> 7      500 MiB -> 32
         2 MiB -> 3     20 MiB -> 7        1 GiB -> 64
         4 MiB -> 4    100 MiB -> 7         7 GB -> 64 (112 MiB each)

    Retrieval reads the count off the file's own index record, so files written
    under any policy -- including every file already stored at 7 -- keep working
    unchanged. Nothing here is a migration."""
    if size < 0:
        raise ValueError("size cannot be negative")
    large = _ceil_div(size, TARGET_FRAGMENT_BYTES)
    small = min(DEFAULT_FRAGMENT_COUNT, _ceil_div(size, MIN_FRAGMENT_BYTES))
    n = max(large, small)
    return max(MIN_FRAGMENT_COUNT, min(n, MAX_FRAGMENT_COUNT))


def split(data: bytes, n: int) -> list[bytes]:
    """Split bytes into n contiguous fragments, as even as possible.

    The first (len % n) fragments get one extra byte. For inputs shorter than n,
    trailing fragments are empty (still valid — they encrypt to a token)."""
    if n <= 0:
        raise ValueError("fragment count must be positive")
    total = len(data)
    base, extra = divmod(total, n)
    out: list[bytes] = []
    pos = 0
    for i in range(n):
        size = base + (1 if i < extra else 0)
        out.append(data[pos : pos + size])
        pos += size
    return out


def join(fragments: list[bytes]) -> bytes:
    """Concatenate fragments (must already be in sequence order)."""
    return b"".join(fragments)


def route(sequence: int, buckets: list[str], *, mode: str, jitter: int) -> str:
    """Pick the destination bucket for a fragment.

    modular: (sequence + per-file jitter) % bucket_count — spreads fragments and
             the jitter stops two files sharing an identical bucket pattern.
    hybrid:  even sequences -> first half of buckets, odd -> second half, so a
             breach of one operator's buckets yields only half the fragments.
    """
    count = len(buckets)
    if count == 0:
        raise ValueError("no buckets registered")

    if mode == ROUTE_MODULAR:
        return buckets[(sequence + jitter) % count]

    if mode == ROUTE_HYBRID:
        half = max(1, count // 2)
        if sequence % 2 == 0:
            return buckets[(sequence + jitter) % half]              # group A
        return buckets[half + ((sequence + jitter) % (count - half))]  # group B

    raise ValueError(f"unknown routing mode: {mode}")


def weighted_cycle(weights: dict[str, float], resolution: int = 100) -> list[str]:
    """A deterministic repeating list of region-group labels whose frequency
    matches `weights` (e.g. {"eu": 0.5, "us-east": 0.3, "us-west": 0.2}), built
    to `resolution` slots via largest-remainder rounding so it hits the exact
    total even when weights don't divide evenly."""
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"region weights must sum to 1.0, got {total}")
    order = sorted(weights)  # deterministic regardless of dict insertion order
    raw = {g: weights[g] * resolution for g in order}
    counts = {g: int(raw[g]) for g in order}
    shortfall = resolution - sum(counts.values())
    if shortfall > 0:
        by_remainder = sorted(order, key=lambda g: raw[g] - counts[g], reverse=True)
        for g in by_remainder[:shortfall]:
            counts[g] += 1
    cycle: list[str] = []
    for g in order:
        cycle.extend([g] * counts[g])
    return cycle


def route_region_weighted(
    sequence: int, fragment_count: int, region_buckets: dict[str, list[str]],
    weights: dict[str, float], *, jitter: int,
) -> tuple[str, str]:
    """Region-biased routing: pick a region group per `weights`, then modular-
    route within that group's own bucket list -- so diversity within a favored
    region is preserved even under a strong regional bias (e.g. 80% EU still
    spreads across every EU bucket, not just one).

    The cycle is sized to `fragment_count`, not a fixed resolution: sizing it
    to a large fixed constant (e.g. 100) would sample only a small, jitter-
    shifted window of that cycle for any one file's fragments, which can miss
    the requested proportions badly at small fragment counts (e.g. 16 frags
    against a 100-slot cycle only ever sees ~16 of the 100 slots). Sizing the
    cycle to the file's own fragment count instead guarantees every fragment
    of a SINGLE file participates, hitting the requested weights as closely as
    integer rounding allows for that fragment count.

    `region_buckets` maps group name -> that group's bucket list (built once
    per store() call from ObjectStore.region_group_for(), not per-fragment).
    Returns (bucket, region_group) -- the caller may want the group for
    reporting without a second lookup."""
    missing = set(weights) - set(region_buckets)
    if missing:
        raise ValueError(f"no buckets registered for region group(s): {sorted(missing)}")
    cycle = weighted_cycle(weights, resolution=fragment_count)
    group = cycle[(sequence + jitter) % len(cycle)]
    buckets = region_buckets[group]
    if not buckets:
        raise ValueError(f"region group {group!r} has no buckets")
    bucket = buckets[(sequence + jitter) % len(buckets)]
    return bucket, group
