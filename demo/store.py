"""File-bytes storage for the app: the real DPD pipeline, backend chosen by env.

`XINSERE_BACKEND=aws` -> S3 + KMS + DynamoDB (production). Otherwise an ephemeral
local pipeline for offline dev. The app calls PIPELINE.store()/retrieve(); the
folder tree + shares live in Supabase (see supa.py), not here.
"""
from __future__ import annotations

import os
import sys
import uuid
# boto3 is imported lazily inside _s3() — it's a heavy import and only the S3
# staging helpers need it, so cold boots that don't stage a direct upload skip it.

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
# Two distinct caps, deliberately different (security audit 2026-07-10, finding 3):
#   MAX_INLINE_BYTES  — the DIRECT-body path (POST /v1/files, /api/upload). The bytes
#     are read whole into the function's memory, so this must stay small (a 500 MB
#     inline body OOMs a 1 GB function). ~8 MB comfortably clears the serverless body
#     limit while forcing anything larger onto the staged path. Advertised to clients
#     in /v1/ping and the 413 body so they don't have to guess.
#   MAX_STAGED_BYTES  — the FINALIZE path (client PUT straight to S3, we then pull and
#     fragment). Bounded by what the memory-bound function can process from staging.
MAX_INLINE_BYTES = int(os.environ.get("XINSERE_MAX_INLINE_BYTES", str(8 * 1024 * 1024)))
MAX_STAGED_BYTES = int(os.environ.get("XINSERE_MAX_STAGED_BYTES", str(500 * 1024 * 1024)))


def _s3():
    import boto3
    from botocore.config import Config
    # Force SigV4: with SigV2 presigned PUTs, Content-Type is part of the
    # string-to-sign, so the browser's MIME type (e.g. application/pdf) must match
    # the signed one exactly — it doesn't, so documents 403 while type-less files
    # (fonts) slip through. SigV4 signs only `host`, so the browser may send any
    # Content-Type as an unsigned header.
    region = os.environ.get("AWS_REGION") or "us-east-1"
    return boto3.client(
        "s3",
        region_name=region,
        # Regional endpoint pinned — the global endpoint 307-redirects for new
        # buckets (no CORS on the redirect), which kills browser uploads.
        endpoint_url=f"https://s3.{region}.amazonaws.com",
        config=Config(signature_version="s3v4"),
    )


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
