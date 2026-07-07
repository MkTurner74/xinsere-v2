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
    ALLOWED_FRAGMENT_COUNTS,
    DEFAULT_FRAGMENT_COUNT,
    NONCE_BYTES,
    ROUTE_MODULAR,
)
from .errors import XinsereIntegrityError, XinsereNotFoundError
from . import fragmenter

_log = logging.getLogger("xinsere.pipeline")


@dataclass
class StoreResult:
    file_id: str
    file_sha256: str
    fragment_count: int
    stored_at: str


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
        fragment_count: int = DEFAULT_FRAGMENT_COUNT,
        route_mode: str = ROUTE_MODULAR,
        max_workers: int | None = None,
    ) -> None:
        if fragment_count not in ALLOWED_FRAGMENT_COUNTS:
            raise ValueError(
                f"fragment_count must be one of {ALLOWED_FRAGMENT_COUNTS}, got {fragment_count}"
            )
        self._objects = object_store
        self._keys = key_manager
        self._index = index_store
        self._n = fragment_count
        self._mode = route_mode
        # Per-fragment work is I/O-bound: an S3 GET/PUT (often cross-region) plus a
        # KMS round-trip, both of which release the GIL. So pool width should track
        # the fragment count, NOT cpu_count — on serverless os.cpu_count() is 1-2,
        # which serialized the fan-out into several sequential waves. fragment_count
        # is bounded (<=16 by ALLOWED_FRAGMENT_COUNTS), so one thread per fragment
        # is safe; keep an explicit ceiling as a guard.
        self._workers = max_workers or min(fragment_count, 16)

    # --- Store ---------------------------------------------------------------

    def store(
        self,
        content: bytes,
        content_type: str,
        *,
        label: str | None = None,
    ) -> StoreResult:
        """Fragment, encrypt, scatter, and index a file. Metadata (filename,
        path, type inference) is never persisted — only the opaque file_id,
        the whole-file SHA-256, and the caller's optional label."""
        file_id = uuid.uuid4().hex
        file_sha = _sha256_hex(content)

        fragments = fragmenter.split(content, self._n)
        buckets = self._objects.buckets()
        jitter = int.from_bytes(os.urandom(2), "big")  # per-file routing jitter

        # Encrypt + scatter every fragment concurrently; .result() order matches
        # submit order, so records stay in sequence. Any worker error propagates.
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = [
                pool.submit(self._encrypt_and_store, file_id, seq, frag, buckets, jitter)
                for seq, frag in enumerate(fragments)
            ]
            records = [f.result() for f in futures]

        for rec in records:
            self._index.put_fragment(rec)

        self._index.put_file(
            FileRecord(
                file_id=file_id,
                file_sha256=file_sha,
                content_type=content_type,
                fragment_count=self._n,
                size=len(content),
                created_at=_now_iso(),
                label=label,
            )
        )
        return StoreResult(file_id, file_sha, self._n, _now_iso())

    def _encrypt_and_store(self, file_id, seq, frag, buckets, jitter) -> FragmentRecord:
        """Worker: fresh key -> AES-256-GCM encrypt -> write to a bucket."""
        data_key, wrapped = self._keys.generate_data_key()
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(data_key).encrypt(nonce, frag, None)
        fragment_id = f"{uuid.uuid4().hex}_{seq}"  # UUID + seq only; no file link
        bucket = fragmenter.route(seq, buckets, mode=self._mode, jitter=jitter)
        self._objects.put(bucket, fragment_id, ciphertext)
        return FragmentRecord(
            file_id=file_id, sequence=seq, fragment_id=fragment_id,
            bucket=bucket, wrapped_key=wrapped, nonce=nonce,
        )

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
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
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
            "workers": self._workers,
            "bytes": len(content),
            # per-fragment breakdown across the fan-out (max = critical path):
            "s3_get": _agg(frag_timings, "s3_ms"),
            "kms_decrypt": _agg(frag_timings, "kms_ms"),
            "aes_gcm": _agg(frag_timings, "aes_ms"),
        }
        _log.info("retrieve %s %s", file_id, timings)
        return RetrieveResult(content, file_rec.content_type, file_rec.file_sha256, timings)

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
        data_key = self._keys.decrypt_data_key(fr.wrapped_key)
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
