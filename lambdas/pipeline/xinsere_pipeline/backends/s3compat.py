"""Generic S3-compatible object store (Backblaze B2, Cloudflare R2, IDrive e2,
CoreWeave, Wasabi, MinIO, ...).

The Xinsere reassembly model depends on **SigV4 presigned GET URLs with CORS**, so
the only providers usable here are ones that pass that gate (see
`projects/Xinsere/research/2026-07-12-storage-provider-assessment.md`). This class
speaks the plain S3 API against a single custom endpoint — unlike `S3ObjectStore`,
which is AWS-specific (multi-region clients, region-from-bucket-name parsing, the
regional-endpoint 307/CORS workaround). A non-AWS provider exposes one endpoint and
its own region label, so one client per store is correct.

Per ADR-101 (`ADR-2026-07-12-...`), storage is pluggable: this is one `ObjectStore`
implementation among several, selected by config in `factory.py`. Fragments record
their provider in the bucket identifier (see `router.MultiCloudObjectStore`), so a
deployment can scatter fragments across several providers for cost (zero egress) and
security (a breach of one provider yields only partial fragments).
"""
from __future__ import annotations

import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .base import ObjectStore

# SigV4 is mandatory: presigned GETs must be v4 (the gate every candidate provider
# was checked against), and v2 signs Content-Type into PUTs (the staging-bucket bug).
def _config(addressing_style: str | None) -> Config:
    s3 = {"addressing_style": addressing_style} if addressing_style else {}
    return Config(signature_version="s3v4", s3=s3)


class S3CompatObjectStore(ObjectStore):
    """One S3-compatible endpoint holding several fragment buckets.

    Args:
        buckets: fragment bucket names on this provider.
        endpoint_url: the provider's S3 endpoint (e.g.
            ``https://s3.us-west-004.backblazeb2.com`` for B2,
            ``https://<account>.r2.cloudflarestorage.com`` for R2).
        region_name: the provider's region label. Some providers are strict
            (B2 ``us-west-004``); R2 uses ``auto``.
        access_key / secret_key: credentials. If omitted, boto3's default chain
            is used (env/instance) — but non-AWS providers normally need explicit
            keys, so pass them (the factory sources them per-provider from env).
        addressing_style: ``"path"`` or ``"virtual"``. Default lets boto3 decide;
            some providers/self-hosted (MinIO) require ``"path"``.
        client_factory: override for tests — ``() -> boto3-like s3 client``.
    """

    def __init__(
        self,
        buckets: list[str],
        endpoint_url: str,
        region_name: str,
        access_key: str | None = None,
        secret_key: str | None = None,
        addressing_style: str | None = None,
        client_factory=None,
    ) -> None:
        self._names = list(buckets)
        if client_factory is not None:
            self._s3 = client_factory()
        else:
            self._s3 = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                region_name=region_name,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                config=_config(addressing_style),
            )

    def buckets(self) -> list[str]:
        return list(self._names)

    def put(self, bucket: str, key: str, data: bytes) -> None:
        # Payloads are already client-side envelope-encrypted (AES-256-GCM) before
        # they arrive; provider-side SSE, where offered, is defence in depth.
        self._s3.put_object(Bucket=bucket, Key=key, Body=data)

    def get(self, bucket: str, key: str) -> bytes:
        try:
            return self._s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                raise FileNotFoundError(f"{bucket}/{key}") from exc
            raise

    def presign_get(self, bucket: str, key: str, expires_in: int = 300) -> str:
        # Single object, short TTL, handed only to a caller that already passed the
        # permission check. The provider must serve this URL with CORS for the app
        # origin (configured out-of-band per provider) so the browser can fetch it.
        return self._s3.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in)

    def delete(self, bucket: str, key: str) -> None:
        self._s3.delete_object(Bucket=bucket, Key=key)


# Provider endpoint templates — filled from env by the factory. Kept here so the
# provider list lives next to the code that talks to them.
def b2_endpoint(region: str) -> str:
    return f"https://s3.{region}.backblazeb2.com"


def r2_endpoint(account_id: str) -> str:
    return f"https://{account_id}.r2.cloudflarestorage.com"


def wasabi_endpoint(region: str) -> str:
    return f"https://s3.{region}.wasabisys.com"


def env_provider_store(prefix: str) -> S3CompatObjectStore:
    """Build an S3CompatObjectStore from ``XINSERE_<PREFIX>_*`` env vars.

    Required: ``_ENDPOINT``, ``_REGION``, ``_BUCKETS`` (comma-separated),
    ``_ACCESS_KEY``, ``_SECRET_KEY``. Optional: ``_ADDRESSING`` (path|virtual).
    """
    p = f"XINSERE_{prefix.upper()}_"

    def req(name: str) -> str:
        v = os.environ.get(p + name, "").strip()
        if not v:
            raise RuntimeError(f"multi-cloud provider '{prefix}' requires {p}{name}")
        return v

    buckets = [b.strip() for b in req("BUCKETS").split(",") if b.strip()]
    return S3CompatObjectStore(
        buckets=buckets,
        endpoint_url=req("ENDPOINT"),
        region_name=req("REGION"),
        access_key=req("ACCESS_KEY"),
        secret_key=req("SECRET_KEY"),
        addressing_style=os.environ.get(p + "ADDRESSING") or None,
    )
