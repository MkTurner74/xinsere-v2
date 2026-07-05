"""Local, in-memory/filesystem backends for testing.

These faithfully model the AWS behaviour the pipeline depends on:
- LocalKeyManager does real AES-256-GCM envelope encryption under a master key,
  exactly like KMS wraps a data key under a CMK.
- LocalObjectStore treats subdirectories as independent buckets.
- LocalIndexStore is an in-memory stand-in for DynamoDB.

Nothing here talks to AWS, so the full pipeline + test matrix runs offline.
"""
from __future__ import annotations

import os
import shutil
from copy import deepcopy

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import DATA_KEY_BYTES, NONCE_BYTES
from .base import FileRecord, FragmentRecord, IndexStore, KeyManager, ObjectStore


class LocalKeyManager(KeyManager):
    """Envelope encryption under an in-process master key (KMS stand-in)."""

    def __init__(self, master_key: bytes | None = None) -> None:
        self._master = master_key or os.urandom(DATA_KEY_BYTES)
        self._aead = AESGCM(self._master)

    def generate_data_key(self) -> tuple[bytes, bytes]:
        plaintext = os.urandom(DATA_KEY_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        wrapped = nonce + self._aead.encrypt(nonce, plaintext, None)
        return plaintext, wrapped

    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        nonce, blob = wrapped_key[:NONCE_BYTES], wrapped_key[NONCE_BYTES:]
        return self._aead.decrypt(nonce, blob, None)


class LocalObjectStore(ObjectStore):
    """Subdirectories as buckets. In-memory by default; on-disk if root given."""

    def __init__(self, bucket_count: int = 8, root: str | None = None) -> None:
        self._names = [f"xinsere-frag-{i:02d}" for i in range(bucket_count)]
        self._root = root
        # In-memory store: {bucket: {key: data}}
        self._mem: dict[str, dict[str, bytes]] = {b: {} for b in self._names}
        if root:
            for b in self._names:
                os.makedirs(os.path.join(root, b), exist_ok=True)

    def buckets(self) -> list[str]:
        return list(self._names)

    def _path(self, bucket: str, key: str) -> str:
        return os.path.join(self._root, bucket, key)  # type: ignore[arg-type]

    def put(self, bucket: str, key: str, data: bytes) -> None:
        if self._root:
            with open(self._path(bucket, key), "wb") as f:
                f.write(data)
        else:
            self._mem[bucket][key] = data

    def get(self, bucket: str, key: str) -> bytes:
        if self._root:
            with open(self._path(bucket, key), "rb") as f:
                return f.read()
        return self._mem[bucket][key]

    def delete(self, bucket: str, key: str) -> None:
        if self._root:
            try:
                os.remove(self._path(bucket, key))
            except FileNotFoundError:
                pass
        else:
            self._mem[bucket].pop(key, None)

    # Test helpers (not part of the interface) --------------------------------

    def all_objects(self) -> list[tuple[str, str, bytes]]:
        """Every (bucket, key, data) currently stored — for test assertions."""
        out: list[tuple[str, str, bytes]] = []
        if self._root:
            for b in self._names:
                d = os.path.join(self._root, b)
                for k in os.listdir(d):
                    with open(os.path.join(d, k), "rb") as f:
                        out.append((b, k, f.read()))
        else:
            for b, items in self._mem.items():
                for k, v in items.items():
                    out.append((b, k, v))
        return out

    def cleanup(self) -> None:
        if self._root and os.path.isdir(self._root):
            shutil.rmtree(self._root, ignore_errors=True)


class LocalIndexStore(IndexStore):
    """In-memory DynamoDB stand-in."""

    def __init__(self) -> None:
        self._files: dict[str, FileRecord] = {}
        self._fragments: dict[str, list[FragmentRecord]] = {}

    def put_file(self, rec: FileRecord) -> None:
        self._files[rec.file_id] = deepcopy(rec)

    def get_file(self, file_id: str) -> FileRecord | None:
        rec = self._files.get(file_id)
        return deepcopy(rec) if rec else None

    def find_file_by_sha(self, file_sha256: str) -> FileRecord | None:
        for rec in self._files.values():
            if rec.file_sha256 == file_sha256:
                return deepcopy(rec)
        return None

    def put_fragment(self, rec: FragmentRecord) -> None:
        self._fragments.setdefault(rec.file_id, []).append(deepcopy(rec))

    def get_fragments(self, file_id: str) -> list[FragmentRecord]:
        frags = self._fragments.get(file_id, [])
        return sorted((deepcopy(f) for f in frags), key=lambda f: f.sequence)

    def delete_file(self, file_id: str) -> None:
        self._files.pop(file_id, None)
        self._fragments.pop(file_id, None)
