"""File-bytes storage for the app: the real DPD pipeline, backend chosen by env.

`XINSERE_BACKEND=aws` -> S3 + KMS + DynamoDB (production). Otherwise an ephemeral
local pipeline for offline dev. The app calls PIPELINE.store()/retrieve(); the
folder tree + shares live in Supabase (see supa.py), not here.
"""
from __future__ import annotations

import os
import sys
import uuid

import boto3

# Make the pipeline package importable from the sibling lambdas/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lambdas", "pipeline"))

from xinsere_pipeline import XinsereIntegrityError  # noqa: E402,F401
from xinsere_pipeline.factory import build_pipeline_from_env  # noqa: E402

# --- Staging bucket for direct-to-S3 uploads (bypasses the 4.5 MB function cap) ---
# The client PUTs the raw file straight to S3 via a presigned URL; the finalize
# step pulls it here, runs it through the pipeline (fragment/encrypt/scatter), and
# deletes the staging copy. Only the tiny presign/finalize calls hit the function.
STAGING_BUCKET = os.environ.get("XINSERE_STAGING_BUCKET", "xinsere-dev-staging")
# Cap on what the (memory-bound) serverless function will process from staging.
MAX_INLINE_BYTES = int(os.environ.get("XINSERE_MAX_INLINE_BYTES", str(500 * 1024 * 1024)))


def _s3():
    return boto3.client("s3", region_name=os.environ.get("AWS_REGION") or "us-east-1")


def presign_put(user_id: str) -> tuple[str, str]:
    """Return (staging_key, presigned_put_url). Key is namespaced by user so the
    finalize step can verify ownership. ContentType is intentionally unsigned so the
    browser can PUT without a header-match dance."""
    key = f"staging/{user_id}/{uuid.uuid4().hex}"
    url = _s3().generate_presigned_url(
        "put_object", Params={"Bucket": STAGING_BUCKET, "Key": key}, ExpiresIn=3600)
    return key, url


def staged_size(key: str) -> int:
    return int(_s3().head_object(Bucket=STAGING_BUCKET, Key=key)["ContentLength"])


def read_staged(key: str) -> bytes:
    return _s3().get_object(Bucket=STAGING_BUCKET, Key=key)["Body"].read()


def delete_staged(key: str) -> None:
    try:
        _s3().delete_object(Bucket=STAGING_BUCKET, Key=key)
    except Exception:
        pass


_PIPELINE = None


def get_pipeline():
    """Lazy singleton. Building the AWS pipeline touches Secrets Manager, so we
    defer it out of import time — cheaper cold starts, and import never crashes if
    creds/env aren't present yet."""
    global _PIPELINE
    if _PIPELINE is None:
        _PIPELINE = build_pipeline_from_env()
    return _PIPELINE
