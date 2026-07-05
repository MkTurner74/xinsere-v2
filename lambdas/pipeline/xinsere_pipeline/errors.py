"""Pipeline error types."""


class XinsereError(Exception):
    """Base class for all pipeline errors."""


class XinsereNotFoundError(XinsereError):
    """A file_id (or its fragments) does not exist in the index."""


class XinsereIntegrityError(XinsereError):
    """A fragment is missing, tampered with, or the reassembled file fails its
    SHA-256 check. Retrieval must fail loudly rather than return partial data."""
