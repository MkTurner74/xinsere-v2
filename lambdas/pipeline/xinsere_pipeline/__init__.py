"""Xinsere file-fragment pipeline.

Store a file: strip metadata -> fragment into N chunks -> per-fragment AES-256
encryption with an independent data key -> scatter fragments across buckets ->
index in the (pluggable) metadata store. Retrieve reverses it and verifies the
whole-file SHA-256 before returning a byte.

The backends (object store, key manager, index store) are abstract so the exact
same pipeline runs against local fakes for testing and real S3/KMS/DynamoDB in
production. See backends/local.py and backends/aws.py.
"""

from .pipeline import PipelineService, StoreResult, RetrieveResult
from .errors import XinsereIntegrityError, XinsereNotFoundError

__all__ = [
    "PipelineService",
    "StoreResult",
    "RetrieveResult",
    "XinsereIntegrityError",
    "XinsereNotFoundError",
]
