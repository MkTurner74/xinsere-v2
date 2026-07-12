"""Env-driven backend selection for the pipeline.

`XINSERE_BACKEND=aws` builds the production pipeline (S3 + KMS + DynamoDB);
anything else (default) builds a local disk/in-memory pipeline for offline dev and
tests. The demo app and the Vercel entrypoint both call `build_pipeline_from_env()`
so the wiring lives in one place.

Storage is pluggable (ADR-101). By default the AWS path uses a single multi-region
`S3ObjectStore` — the proven path we validate the Dropbox migration on first
(ADR-101b). Set `XINSERE_STORAGE_PROVIDERS` (e.g. ``aws,b2,r2``) to scatter
fragments across several S3-compatible providers via `MultiCloudObjectStore`
instead — a config change, no code change. KMS + DynamoDB are unchanged either way.
"""
from __future__ import annotations

import os

from .backends.base import ObjectStore
from .pipeline import PipelineService

FRAGMENT_COUNT = int(os.environ.get("XINSERE_FRAGMENT_COUNT", "7"))


def _aws_s3_store() -> ObjectStore:
    from .backends.aws import S3ObjectStore

    buckets_env = os.environ.get("XINSERE_S3_BUCKETS", "").strip()
    if not buckets_env:
        raise RuntimeError(
            "XINSERE_BACKEND=aws requires XINSERE_S3_BUCKETS (comma-separated bucket names)")
    buckets = [b.strip() for b in buckets_env.split(",") if b.strip()]
    return S3ObjectStore(buckets)


def _build_object_store() -> ObjectStore:
    """Single S3 store (default, AWS-first) or a multi-cloud router if configured.

    `XINSERE_STORAGE_PROVIDERS` = comma-separated provider names. ``aws`` maps to the
    multi-region `S3ObjectStore`; every other name is a generic S3-compatible
    provider configured via ``XINSERE_<NAME>_*`` env (endpoint/region/buckets/keys).
    The default (resolve legacy unprefixed buckets) is the first listed provider,
    overridable with `XINSERE_STORAGE_DEFAULT_PROVIDER`.
    """
    providers_env = os.environ.get("XINSERE_STORAGE_PROVIDERS", "").strip()
    if not providers_env:
        return _aws_s3_store()

    from .backends.router import MultiCloudObjectStore
    from .backends.s3compat import env_provider_store

    names = [n.strip().lower() for n in providers_env.split(",") if n.strip()]
    stores: dict[str, ObjectStore] = {}
    for name in names:
        stores[name] = _aws_s3_store() if name == "aws" else env_provider_store(name)

    default = os.environ.get("XINSERE_STORAGE_DEFAULT_PROVIDER", "").strip().lower() or names[0]
    return MultiCloudObjectStore(stores, default_provider=default)


def _aws_pipeline() -> PipelineService:
    from .backends.aws import DynamoIndexStore, KmsKeyManager
    from .tenant import load_tenant_config

    # KMS key: explicit env wins, else the canonical key from the tenant secret.
    key_id = os.environ.get("XINSERE_KMS_KEY_ID") or load_tenant_config()["kms_key_id"]
    if not key_id:
        raise RuntimeError("No KMS key id (set XINSERE_KMS_KEY_ID or the tenant secret)")

    files_table = os.environ.get("XINSERE_FILES_TABLE", "xinsere_files")
    frags_table = os.environ.get("XINSERE_FRAGMENTS_TABLE", "xinsere_fragments")
    sha_index = os.environ.get("XINSERE_SHA_INDEX", "sha-index")

    return PipelineService(
        _build_object_store(),
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
