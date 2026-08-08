"""PipelineService — store and retrieve files as encrypted, scattered fragments.

Store:    strip metadata -> SHA-256 the whole file -> split into N fragments ->
          per-fragment: fresh data key + AES-256-GCM encrypt -> scatter to
          buckets -> index (wrapped key, nonce, bucket, sequence).
Retrieve: read fragments by file_id -> per-fragment unwrap key + decrypt ->
          reassemble in sequence -> verify whole-file SHA-256 -> return bytes.

Permission enforcement lives in the blockchain service, not here — this layer is
storage only. Wire a permission check in front of retrieve() at the API layer.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .backends.base import FileRecord, FragmentRecord, IndexStore, KeyManager, ObjectStore
from .config import (
    MAX_FRAGMENT_COUNT,
    MIN_FRAGMENT_COUNT,
    NONCE_BYTES,
    ROUTE_MODULAR,
)
from .errors import XinsereIntegrityError, XinsereNotFoundError
from . import fragmenter

_log = logging.getLogger("xinsere.pipeline")


WORKER_CAP = 64


def validate_fragment_count(n: int) -> int:
    """Range check for a caller-supplied count. Replaces the old fixed
    ALLOWED_FRAGMENT_COUNTS whitelist (3,5,7,11,16), which couldn't express the
    size-derived counts a large file needs."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise ValueError(f"fragment_count must be an int, got {n!r}")
    if not MIN_FRAGMENT_COUNT <= n <= MAX_FRAGMENT_COUNT:
        raise ValueError(
            f"fragment_count must be between {MIN_FRAGMENT_COUNT} and "
            f"{MAX_FRAGMENT_COUNT}, got {n}"
        )
    return n


@dataclass
class StoreResult:
    file_id: str
    file_sha256: str
    fragment_count: int
    stored_at: str
    # Per-stage wall-clock breakdown (ms), mirroring RetrieveResult.timings — added
    # 2026-07-24 so write-side throughput (KMS/S3/AES-GCM attribution) can be
    # profiled with the same rigor as reads across compute/storage benchmarks.
    timings: dict = field(default_factory=dict)
    # How fragment_count was arrived at: "auto" (derived from file size),
    # "pinned" (this service was constructed with a fixed count), or "request"
    # (the caller passed one to store()). Surfaced so a demo or an API response
    # can say which, rather than leaving 3-vs-7 looking arbitrary.
    sizing: str = "auto"


@dataclass
class RetrieveResult:
    content: bytes
    content_type: str
    file_sha256: str
    # Per-stage wall-clock breakdown (ms), for profiling latency. See retrieve().
    timings: dict = field(default_factory=dict)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def _agg(frag_timings: list[dict], key: str) -> dict:
    """Aggregate a per-fragment timing across the fan-out. `max` is the critical
    path (fragments run concurrently); `sum` is total work done."""
    vals = [ft[key] for ft in frag_timings] or [0.0]
    return {"max": round(max(vals), 1), "avg": round(sum(vals) / len(vals), 1),
            "sum": round(sum(vals), 1)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PipelineService:
    def __init__(
        self,
        object_store: ObjectStore,
        key_manager: KeyManager,
        index_store: IndexStore,
        *,
        fragment_count: int | None = None,
        route_mode: str = ROUTE_MODULAR,
        max_workers: int | None = None,
        region_weights: dict[str, float] | None = None,
    ) -> None:
        # fragment_count=None (the default) means SIZE-DERIVED per file, via
        # fragmenter.plan_fragment_count. Passing an int pins every file this
        # service stores to that count -- the escape hatch for a caller that
        # needs a specific N (benchmarks, a tenant policy, a rollback).
        if fragment_count is not None:
            validate_fragment_count(fragment_count)
        self._objects = object_store
        self._keys = key_manager
        self._index = index_store
        self._n = fragment_count
        self._mode = route_mode
        # Optional region bias (e.g. {"eu": 0.7, "us-east": 0.2, "us-west": 0.1})
        # -- when set, overrides route_mode entirely: fragmenter.route_region_weighted
        # picks the region group per the weights, then spreads within that
        # group's own buckets. None (default) preserves today's behaviour exactly.
        self._region_weights = dict(region_weights) if region_weights else None
        # Per-fragment work is I/O-bound: an S3 GET/PUT (often cross-region) plus a
        # KMS round-trip, both of which release the GIL. So pool width should track
        # the fragment count, NOT cpu_count — on serverless os.cpu_count() is 1-2,
        # which serialized the fan-out into several sequential waves.
        #
        # Cap raised 16 -> 64 on 2026-07-26 after a real EC2 test (fragment_count=
        # 1000, workers swept 16/64/128/256/512): 16->64 gave a real ~15-30%
        # throughput gain; beyond 64 it flattens completely and per-call KMS/S3
        # latency actually gets WORSE (KMS avg 8.4ms at 16 workers -> 67.8ms at
        # 128) -- that's AWS's own request-rate throttling, not a Python/GIL
        # limit, so there's no benefit to raising this further.
        #
        # Sized PER CALL rather than once here, because the count now varies by
        # file: a service that stored a 10KB file (3 fragments) must still fan a
        # 1GiB file (64) out 64 ways, and must still retrieve an old 7-fragment
        # file 7 ways. An explicit max_workers still overrides everything.
        self._max_workers = max_workers

    def _workers_for(self, n: int) -> int:
        return self._max_workers or max(1, min(n, WORKER_CAP))

    def _count_for(self, size: int, requested: int | None) -> tuple[int, str]:
        """Resolve the fragment count for one store(): explicit request, else this
        service's pin, else derived from the file's size."""
        if requested is not None:
            return validate_fragment_count(requested), "request"
        if self._n is not None:
            return self._n, "pinned"
        return fragmenter.plan_fragment_count(size), "auto"

    # --- Store ---------------------------------------------------------------

    def store(
        self,
        content: bytes,
        content_type: str,
        *,
        label: str | None = None,
        fragment_count: int | None = None,
    ) -> StoreResult:
        """Fragment, encrypt, scatter, and index a file. Metadata (filename,
        path, type inference) is never persisted — only the opaque file_id,
        the whole-file SHA-256, and the caller's optional label.

        `fragment_count` pins this one file to a specific N (3..64). Leave it
        None and the count is derived from the file's size — see
        fragmenter.plan_fragment_count for the curve and the data behind it."""
        t_all = time.perf_counter()
        file_id = uuid.uuid4().hex
        file_sha = _sha256_hex(content)
        n, sizing = self._count_for(len(content), fragment_count)
        workers = self._workers_for(n)

        fragments = fragmenter.split(content, n)
        buckets = self._objects.buckets()
        jitter = int.from_bytes(os.urandom(2), "big")  # per-file routing jitter

        # Region-biased routing needs bucket->group once per file (constant
        # across all its fragments), not re-derived per fragment.
        region_buckets = None
        if self._region_weights is not None:
            region_buckets = {}
            for b in buckets:
                region_buckets.setdefault(self._objects.region_group_for(b), []).append(b)

        # Encrypt + scatter every fragment concurrently; .result() order matches
        # submit order, so records stay in sequence. Any worker error propagates.
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(self._encrypt_and_store, file_id, seq, frag, buckets, jitter,
                            n, region_buckets)
                for seq, frag in enumerate(fragments)
            ]
            results = [f.result() for f in futures]
        fanout_ms = _ms(t0)
        records = [r[0] for r in results]
        frag_timings = [r[1] for r in results]

        t0 = time.perf_counter()
        for rec in records:
            self._index.put_fragment(rec)

        self._index.put_file(
            FileRecord(
                file_id=file_id,
                file_sha256=file_sha,
                content_type=content_type,
                fragment_count=n,
                size=len(content),
                created_at=_now_iso(),
                label=label,
            )
        )
        index_ms = _ms(t0)

        timings = {
            "total_ms": _ms(t_all),
            "fanout_ms": fanout_ms,   # wall-clock of the parallel encrypt+PUT fan-out
            "index_ms": index_ms,
            "fragments": n,
            "sizing": sizing,
            "fragment_bytes": -(-len(content) // n) if n else 0,
            "workers": workers,
            "bytes": len(content),
            "kms_generate": _agg(frag_timings, "kms_ms"),
            "aes_gcm": _agg(frag_timings, "aes_ms"),
            "s3_put": _agg(frag_timings, "s3_ms"),
        }
        _log.info("store %s %s", file_id, timings)
        return StoreResult(file_id, file_sha, n, _now_iso(), timings, sizing)

    def _encrypt_and_store(self, file_id, seq, frag, buckets, jitter, n,
                            region_buckets=None) -> tuple[FragmentRecord, dict]:
        """Worker: fresh key -> AES-256-GCM encrypt -> write to a bucket.

        Returns (record, timing) where timing splits the KMS key generation, the
        local AES-GCM encrypt, and the S3 write — the write-side mirror of
        _read_and_decrypt's breakdown, for compute/storage benchmarking."""
        t0 = time.perf_counter()
        data_key, wrapped = self._keys.generate_data_key()
        kms_ms = _ms(t0)

        t0 = time.perf_counter()
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(data_key).encrypt(nonce, frag, None)
        aes_ms = _ms(t0)

        t0 = time.perf_counter()
        fragment_id = f"{uuid.uuid4().hex}_{seq}"  # UUID + seq only; no file link
        if region_buckets is not None:
            bucket, _group = fragmenter.route_region_weighted(
                seq, n, region_buckets, self._region_weights, jitter=jitter)
        else:
            bucket = fragmenter.route(seq, buckets, mode=self._mode, jitter=jitter)
        self._objects.put(bucket, fragment_id, ciphertext)
        s3_ms = _ms(t0)

        rec = FragmentRecord(
            file_id=file_id, sequence=seq, fragment_id=fragment_id,
            bucket=bucket, wrapped_key=wrapped, nonce=nonce,
        )
        return rec, {"seq": seq, "kms_ms": kms_ms, "aes_ms": aes_ms, "s3_ms": s3_ms}

    # --- Retrieve ------------------------------------------------------------

    def retrieve(self, file_id: str) -> RetrieveResult:
        """Reassemble and decrypt a file. Raises if any fragment is missing or
        tampered, or if the reassembled bytes fail the whole-file SHA-256.

        Records a per-stage timing breakdown on the result (and logs it) so the
        latency can be attributed to index / S3 / KMS / crypto rather than guessed."""
        t_all = time.perf_counter()

        t0 = time.perf_counter()
        file_rec = self._index.get_file(file_id)
        if file_rec is None:
            raise XinsereNotFoundError(f"unknown file_id: {file_id}")
        frags = self._index.get_fragments(file_id)
        if len(frags) != file_rec.fragment_count:
            raise XinsereIntegrityError(
                f"expected {file_rec.fragment_count} fragments, found {len(frags)}"
            )
        index_ms = _ms(t0)

        # Read + decrypt every fragment concurrently; map() preserves order and
        # re-raises any worker error (missing fragment, tamper) to the caller.
        t0 = time.perf_counter()
        workers = self._workers_for(len(frags))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(self._read_and_decrypt, frags))
        fetch_ms = _ms(t0)
        plaintext_fragments = [r[0] for r in results]
        frag_timings = [r[1] for r in results]

        t0 = time.perf_counter()
        content = fragmenter.join(plaintext_fragments)
        join_ms = _ms(t0)

        t0 = time.perf_counter()
        if _sha256_hex(content) != file_rec.file_sha256:
            raise XinsereIntegrityError("reassembled file failed SHA-256 check")
        verify_ms = _ms(t0)

        timings = {
            "total_ms": _ms(t_all),
            "index_ms": index_ms,
            "fetch_decrypt_ms": fetch_ms,   # wall-clock of the parallel fan-out
            "join_ms": join_ms,
            "verify_sha_ms": verify_ms,
            "fragments": file_rec.fragment_count,
            "workers": workers,
            "bytes": len(content),
            # per-fragment breakdown across the fan-out (max = critical path):
            "s3_get": _agg(frag_timings, "s3_ms"),
            "kms_decrypt": _agg(frag_timings, "kms_ms"),
            "aes_gcm": _agg(frag_timings, "aes_ms"),
        }
        _log.info("retrieve %s %s", file_id, timings)
        return RetrieveResult(content, file_rec.content_type, file_rec.file_sha256, timings)

    def retrieval_plan(self, file_id: str, *, url_ttl: int = 300) -> dict:
        """Client-side reassembly plan: per-fragment presigned GET URLs plus the
        unwrapped data keys and nonces, in sequence order. The file bytes never
        touch this process — the (already-authorized) client fetches fragments
        straight from storage and decrypts locally with AES-256-GCM.

        Security contract for callers: run the permission check BEFORE calling
        this, and hand the plan only to that authorized client over TLS. URLs are
        single-object and short-lived; keys are per-fragment data keys (not the
        master key — KMS/CMK is never exposed).

        Raises NotImplementedError if the object store cannot presign (local dev);
        callers should fall back to server-side retrieve()."""
        file_rec = self._index.get_file(file_id)
        if file_rec is None:
            raise XinsereNotFoundError(f"unknown file_id: {file_id}")
        frags = self._index.get_fragments(file_id)
        if len(frags) != file_rec.fragment_count:
            raise XinsereIntegrityError(
                f"expected {file_rec.fragment_count} fragments, found {len(frags)}"
            )

        def _one(fr: FragmentRecord) -> dict:
            return {
                "sequence": fr.sequence,
                "url": self._objects.presign_get(fr.bucket, fr.fragment_id, expires_in=url_ttl),
                "key": self._keys.decrypt_data_key(fr.wrapped_key),   # bytes; caller encodes
                "nonce": fr.nonce,
            }

        # Presign + KMS-unwrap all fragments concurrently (I/O-bound, like retrieve).
        with ThreadPoolExecutor(max_workers=self._workers_for(len(frags))) as pool:
            plan_frags = list(pool.map(_one, frags))

        return {
            "file_id": file_id,
            "file_sha256": file_rec.file_sha256,
            "content_type": file_rec.content_type,
            "size": file_rec.size,
            "fragment_count": file_rec.fragment_count,
            "fragments": plan_frags,
        }

    def _read_and_decrypt(self, fr: FragmentRecord) -> tuple[bytes, dict]:
        """Worker: read a fragment -> unwrap key -> AES-256-GCM decrypt.

        Returns (plaintext, timing) where timing splits the S3 read, the KMS
        unwrap, and the local AES-GCM decrypt so we can see which one dominates."""
        t0 = time.perf_counter()
        try:
            ciphertext = self._objects.get(fr.bucket, fr.fragment_id)
        except (KeyError, FileNotFoundError) as exc:
            raise XinsereIntegrityError(f"fragment object missing: seq {fr.sequence}") from exc
        s3_ms = _ms(t0)

        t0 = time.perf_counter()
        try:
            data_key = self._keys.decrypt_data_key(fr.wrapped_key)
        except InvalidTag as exc:
            # Envelope unwrap failed authentication — a corrupted or forged wrapped
            # key. Treat as an integrity failure, never a crashed retrieve. (The KMS
            # backend surfaces its own operational errors distinctly.)
            raise XinsereIntegrityError(
                f"fragment data key failed authentication (corrupted/forged?): seq {fr.sequence}"
            ) from exc
        kms_ms = _ms(t0)

        t0 = time.perf_counter()
        try:
            plaintext = AESGCM(data_key).decrypt(fr.nonce, ciphertext, None)
        except InvalidTag as exc:
            raise XinsereIntegrityError(
                f"fragment key/ciphertext failed authentication (tampered?): seq {fr.sequence}"
            ) from exc
        aes_ms = _ms(t0)

        return plaintext, {"seq": fr.sequence, "s3_ms": s3_ms, "kms_ms": kms_ms, "aes_ms": aes_ms}

    def region_report(self, file_id: str) -> dict:
        """Per-region-group and per-bucket fragment distribution for a stored
        file. Demo/observability only — region is derived from each fragment's
        bucket at report time (via ObjectStore.region_group_for), not stored
        redundantly on the fragment record."""
        file_rec = self._index.get_file(file_id)
        if file_rec is None:
            raise XinsereNotFoundError(f"unknown file_id: {file_id}")
        frags = self._index.get_fragments(file_id)
        by_bucket: dict[str, int] = {}
        by_group: dict[str, int] = {}
        for fr in frags:
            by_bucket[fr.bucket] = by_bucket.get(fr.bucket, 0) + 1
            group = self._objects.region_group_for(fr.bucket)
            by_group[group] = by_group.get(group, 0) + 1
        total = len(frags) or 1
        return {
            "file_id": file_id,
            "fragment_count": len(frags),
            "by_region_group": {
                g: {"fragments": n, "pct": round(100 * n / total, 1)}
                for g, n in sorted(by_group.items())
            },
            "by_bucket": dict(sorted(by_bucket.items())),
        }

    # --- Existence / lifecycle ----------------------------------------------

    def exists(self, file_sha256: str) -> bool:
        """Whether a file with this content hash has been stored (no I/O)."""
        return self._index.find_file_by_sha(file_sha256) is not None

    def delete(self, file_id: str) -> None:
        """Cryptographic erasure: remove every fragment object and all index
        records. Without the wrapped keys and ordering, any leftover ciphertext
        is unrecoverable."""
        file_rec = self._index.get_file(file_id)
        if file_rec is None:
            raise XinsereNotFoundError(f"unknown file_id: {file_id}")
        for fr in self._index.get_fragments(file_id):
            self._objects.delete(fr.bucket, fr.fragment_id)
        self._index.delete_file(file_id)
