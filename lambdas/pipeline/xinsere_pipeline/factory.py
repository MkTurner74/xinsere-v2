"""Env-driven backend selection for the pipeline.

`XINSERE_BACKEND=aws` builds the production pipeline (S3 + KMS + DynamoDB);
anything else (default) builds a local disk/in-memory pipeline for offline dev and
tests. The demo app and the Vercel entrypoint both call `build_pipeline_from_env()`
so the wiring lives in one place.
"""
from __future__ import annotations

import os

from .pipeline import PipelineService

FRAGMENT_COUNT = int(os.environ.get("XINSERE_FRAGMENT_COUNT", "7"))


def _aws_pipeline() -> PipelineService:
    from .backends.aws import DynamoIndexStore, KmsKeyManager, S3ObjectStore
    from .tenant import load_tenant_config

    buckets_env = os.environ.get("XINSERE_S3_BUCKETS", "").strip()
    if not buckets_env:
        raise RuntimeError(
            "XINSERE_BACKEND=aws requires XINSERE_S3_BUCKETS (comma-separated bucket names)")
    buckets = [b.strip() for b in buckets_env.split(",") if b.strip()]

    # KMS key: explicit env wins, else the canonical key from the tenant secret.
    key_id = os.environ.get("XINSERE_KMS_KEY_ID") or load_tenant_config()["kms_key_id"]
    if not key_id:
        raise RuntimeError("No KMS key id (set XINSERE_KMS_KEY_ID or the tenant secret)")

    files_table = os.environ.get("XINSERE_FILES_TABLE", "xinsere_files")
    frags_table = os.environ.get("XINSERE_FRAGMENTS_TABLE", "xinsere_fragments")
    sha_index = os.environ.get("XINSERE_SHA_INDEX", "sha-index")

    return PipelineService(
        S3ObjectStore(buckets),
        KmsKeyManager(key_id),
        DynamoIndexStore(files_table, frags_table, sha_index=sha_index),
        fragment_count=FRAGMENT_COUNT,
    )


def _local_pipeline() -> PipelineService:
    from .backends.local import LocalIndexStore, LocalKeyManager, LocalObjectStore

    return PipelineService(
        LocalObjectStore(bucket_count=8),
        LocalKeyManager(master_key=os.urandom(32)),
        LocalIndexStore(),
        fragment_count=FRAGMENT_COUNT,
    )


def build_pipeline_from_env() -> PipelineService:
    if os.environ.get("XINSERE_BACKEND", "local").lower() == "aws":
        return _aws_pipeline()
    return _local_pipeline()
