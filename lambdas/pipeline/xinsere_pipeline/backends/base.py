"""Abstract backend interfaces.

The pipeline depends only on these three interfaces. Swap local fakes for AWS
implementations (S3 / KMS / DynamoDB) without touching pipeline logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


# --- Key management (KMS envelope encryption) -------------------------------

class KeyManager(ABC):
    """Envelope encryption for per-fragment data keys.

    generate_data_key() returns a fresh (plaintext_key, wrapped_key). The
    plaintext is used once, in memory, to encrypt a fragment and then discarded.
    Only the wrapped_key is persisted; unwrapping requires the master key
    (customer CMK in production), which the storage layer never holds.
    """

    @abstractmethod
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Return (plaintext_key_32B, wrapped_key)."""

    @abstractmethod
    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap wrapped_key -> plaintext_key_32B."""


# --- Object storage (S3 multi-bucket) ---------------------------------------

class ObjectStore(ABC):
    """A set of independent buckets holding opaque fragment blobs."""

    @abstractmethod
    def buckets(self) -> list[str]:
        """Names of all registered buckets, stable order."""

    @abstractmethod
    def put(self, bucket: str, key: str, data: bytes) -> None: ...

    @abstractmethod
    def get(self, bucket: str, key: str) -> bytes: ...

    @abstractmethod
    def delete(self, bucket: str, key: str) -> None: ...


# --- Index (DynamoDB metadata) ----------------------------------------------

@dataclass
class FileRecord:
    file_id: str
    file_sha256: str          # SHA-256 of the original whole-file bytes (hex)
    content_type: str
    fragment_count: int
    size: int
    created_at: str           # ISO8601
    label: str | None = None  # optional caller label; never a filename


@dataclass
class FragmentRecord:
    file_id: str
    sequence: int
    fragment_id: str          # "{uuid}_{sequence}" — no link to the filename
    bucket: str
    wrapped_key: bytes        # KMS-wrapped per-fragment data key
    nonce: bytes              # AES-GCM nonce


class IndexStore(ABC):
    """Metadata store: file records + fragment index."""

    @abstractmethod
    def put_file(self, rec: FileRecord) -> None: ...

    @abstractmethod
    def get_file(self, file_id: str) -> FileRecord | None: ...

    @abstractmethod
    def find_file_by_sha(self, file_sha256: str) -> FileRecord | None: ...

    @abstractmethod
    def put_fragment(self, rec: FragmentRecord) -> None: ...

    @abstractmethod
    def get_fragments(self, file_id: str) -> list[FragmentRecord]:
        """All fragments for a file, sorted by sequence ascending."""

    @abstractmethod
    def delete_file(self, file_id: str) -> None:
        """Remove the file record and all its fragment records."""
