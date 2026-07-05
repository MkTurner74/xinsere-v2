"""Fragmentation and bucket routing.

Splitting is contiguous and as even as possible; each fragment is encrypted
independently by the pipeline, so a stored fragment is always ciphertext — never
a readable slice of the original.
"""
from __future__ import annotations

from .config import ROUTE_HYBRID, ROUTE_MODULAR


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
