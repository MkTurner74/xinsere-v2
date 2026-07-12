"""Multi-cloud fragment routing.

`MultiCloudObjectStore` presents several provider `ObjectStore`s (AWS S3, Backblaze
B2, Cloudflare R2, IDrive e2, CoreWeave, ...) as one `ObjectStore`. Fragments then
scatter across providers, which is both a cost win (route reads to zero-egress
providers) and a security win (a breach of any one provider yields only partial
fragments) — see ADR-101/103 in `projects/Xinsere/ADR-2026-07-12-...`.

Design: bucket identifiers are **provider-qualified** — ``"<provider>:<bucket>"``.
`buckets()` returns qualified names, so the pipeline's existing scatter/routing
distributes fragments across providers with no pipeline change, and each
`FragmentRecord.bucket` records where the fragment actually lives. Every op splits
the prefix and delegates the *bare* bucket to the right provider store.

Backward compatibility: a bucket identifier with **no** ``:`` prefix (every
fragment written before multi-cloud existed) resolves to the configured
**default provider** — so switching a running deployment from a single
`S3ObjectStore` to this router keeps all existing fragments resolvable.
"""
from __future__ import annotations

from .base import ObjectStore

SEP = ":"


class MultiCloudObjectStore(ObjectStore):
    def __init__(self, providers: dict[str, ObjectStore], default_provider: str) -> None:
        if not providers:
            raise ValueError("MultiCloudObjectStore needs at least one provider")
        if default_provider not in providers:
            raise ValueError(
                f"default_provider '{default_provider}' not in providers {list(providers)}")
        # Preserve insertion order for a stable buckets() listing (scatter routing
        # is deterministic given a stable bucket order).
        self._providers = dict(providers)
        self._default = default_provider

    def buckets(self) -> list[str]:
        out: list[str] = []
        for prov, store in self._providers.items():
            out.extend(f"{prov}{SEP}{b}" for b in store.buckets())
        return out

    def _resolve(self, bucket: str) -> tuple[ObjectStore, str]:
        """Qualified/legacy bucket id -> (provider store, bare bucket name)."""
        prov, sep, bare = bucket.partition(SEP)
        if not sep:
            # Legacy unprefixed name written before multi-cloud — default provider.
            return self._providers[self._default], bucket
        store = self._providers.get(prov)
        if store is None:
            raise KeyError(
                f"unknown storage provider '{prov}' for bucket '{bucket}'; "
                f"known: {list(self._providers)}")
        return store, bare

    def put(self, bucket: str, key: str, data: bytes) -> None:
        store, bare = self._resolve(bucket)
        store.put(bare, key, data)

    def get(self, bucket: str, key: str) -> bytes:
        store, bare = self._resolve(bucket)
        return store.get(bare, key)

    def delete(self, bucket: str, key: str) -> None:
        store, bare = self._resolve(bucket)
        store.delete(bare, key)

    def presign_get(self, bucket: str, key: str, expires_in: int = 300) -> str:
        store, bare = self._resolve(bucket)
        return store.presign_get(bare, key, expires_in=expires_in)
