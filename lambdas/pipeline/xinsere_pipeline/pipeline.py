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
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        # Fragments are processed concurrently — AES-GCM and disk/S3 I/O both
        # release the GIL, so threads give real parallelism. One worker per
        # fragment, capped by CPU count.
        self._workers = max_workers or min(fragment_count, os.cpu_count() or 4)

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
        tampered, or if the reassembled bytes fail the whole-file SHA-256."""
        file_rec = self._index.get_file(file_id)
        if file_rec is None:
            raise XinsereNotFoundError(f"unknown file_id: {file_id}")

        frags = self._index.get_fragments(file_id)
        if len(frags) != file_rec.fragment_count:
            raise XinsereIntegrityError(
                f"expected {file_rec.fragment_count} fragments, found {len(frags)}"
            )

        # Read + decrypt every fragment concurrently; map() preserves order and
        # re-raises any worker error (missing fragment, tamper) to the caller.
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            plaintext_fragments = list(pool.map(self._read_and_decrypt, frags))

        content = fragmenter.join(plaintext_fragments)
        if _sha256_hex(content) != file_rec.file_sha256:
            raise XinsereIntegrityError("reassembled file failed SHA-256 check")

        return RetrieveResult(content, file_rec.content_type, file_rec.file_sha256)

    def _read_and_decrypt(self, fr: FragmentRecord) -> bytes:
        """Worker: read a fragment -> unwrap key -> AES-256-GCM decrypt."""
        try:
            ciphertext = self._objects.get(fr.bucket, fr.fragment_id)
        except (KeyError, FileNotFoundError) as exc:
            raise XinsereIntegrityError(f"fragment object missing: seq {fr.sequence}") from exc
        try:
            data_key = self._keys.decrypt_data_key(fr.wrapped_key)
            return AESGCM(data_key).decrypt(fr.nonce, ciphertext, None)
        except InvalidTag as exc:
            raise XinsereIntegrityError(
                f"fragment key/ciphertext failed authentication (tampered?): seq {fr.sequence}"
            ) from exc

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
