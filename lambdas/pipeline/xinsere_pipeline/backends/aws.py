"""Production backends: AWS KMS, S3 (multi-bucket), DynamoDB.

These mirror the local backends against real AWS. They are written to spec but
cannot be integration-tested until the P0 infra exists (S3 buckets, KMS CMK,
DynamoDB tables — P0-01..P0-04, AWS-team-owned). The pipeline and its full test
matrix run today against the local backends; swapping these in is a config change.

DynamoDB table shapes assumed:
  files:      PK file_id (S)                        + GSI "sha-index" on file_sha256
  fragments:  PK file_id (S), SK sequence (N)       — Query returns sorted by SK
"""
from __future__ import annotations

import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# SigV4 explicitly: the default signer can still emit SigV2 presigned URLs, which
# are deprecated (and sign Content-Type into PUTs — see the staging-bucket bug).
_SIGV4 = Config(signature_version="s3v4")

from .base import FileRecord, FragmentRecord, IndexStore, KeyManager, ObjectStore


def _region() -> str:
    # Explicit region: serverless runtimes (e.g. Vercel) have no ~/.aws/config, and
    # botocore won't always read AWS_REGION, so pass it in rather than rely on it.
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


class KmsKeyManager(KeyManager):
    def __init__(self, key_id: str, kms_client=None) -> None:
        self._key_id = key_id
        self._kms = kms_client or boto3.client("kms", region_name=_region())

    def generate_data_key(self) -> tuple[bytes, bytes]:
        resp = self._kms.generate_data_key(KeyId=self._key_id, KeySpec="AES_256")
        return resp["Plaintext"], resp["CiphertextBlob"]

    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        return self._kms.decrypt(CiphertextBlob=wrapped_key)["Plaintext"]


# Bucket-name segment -> AWS region. Fragment buckets are named
# `xinsere-dev-frag-<seg>-NN`; the segment encodes the region so we can pick the
# right regional S3 client without a metadata call. Unknown buckets fall back to
# GetBucketLocation.
_SEGMENT_REGION = {
    "use1": "us-east-1", "use2": "us-east-2",
    "usw1": "us-west-1", "usw2": "us-west-2",
    "cac1": "ca-central-1",
}


class S3ObjectStore(ObjectStore):
    """Multi-bucket S3 store spanning several AWS regions.

    A single-region S3 client cannot PUT to a bucket in another region without a
    redirect/signing error, and the Xinsere fragment buckets are deliberately
    scattered across regions. So we keep one client per region and route each
    bucket to its own regional client. Region is inferred from the bucket-name
    segment (fast, no API call); anything unrecognized is resolved once via
    GetBucketLocation and cached.
    """

    def __init__(self, bucket_names: list[str], client_factory=None,
                 default_region: str = "us-east-1") -> None:
        self._names = list(bucket_names)
        self._default_region = default_region
        # client_factory(region) -> boto3 s3 client; overridable for tests.
        # Pin the REGIONAL endpoint explicitly. The global endpoint answers for a
        # brand-new bucket with a 307 redirect for up to ~24h — and that redirect
        # carries no CORS headers, so browser fragment fetches die with
        # "Failed to fetch". Regional endpoints work from the moment of creation.
        self._factory = client_factory or (
            lambda region: boto3.client(
                "s3", region_name=region,
                endpoint_url=f"https://s3.{region}.amazonaws.com", config=_SIGV4))
        self._clients: dict[str, object] = {}   # region -> client
        self._bucket_region: dict[str, str] = {}  # bucket -> region (cache)

    def buckets(self) -> list[str]:
        return list(self._names)

    def _region_for(self, bucket: str) -> str:
        cached = self._bucket_region.get(bucket)
        if cached:
            return cached
        region = None
        parts = bucket.split("-")
        for seg in parts:
            if seg in _SEGMENT_REGION:
                region = _SEGMENT_REGION[seg]
                break
        if region is None:
            # Authoritative fallback. us-east-1 reports LocationConstraint=None.
            loc = self._client(self._default_region).get_bucket_location(
                Bucket=bucket).get("LocationConstraint")
            region = loc or "us-east-1"
        self._bucket_region[bucket] = region
        return region

    def _client(self, region: str):
        client = self._clients.get(region)
        if client is None:
            client = self._factory(region)
            self._clients[region] = client
        return client

    def _for(self, bucket: str):
        return self._client(self._region_for(bucket))

    def put(self, bucket: str, key: str, data: bytes) -> None:
        # Buckets enforce SSE (SSE-S3/AES256) at rest; fragment payloads are also
        # already client-side envelope-encrypted (AES-256-GCM) before they arrive.
        self._for(bucket).put_object(Bucket=bucket, Key=key, Body=data)

    def get(self, bucket: str, key: str) -> bytes:
        try:
            return self._for(bucket).get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                raise FileNotFoundError(f"s3://{bucket}/{key}") from exc
            raise

    def presign_get(self, bucket: str, key: str, expires_in: int = 300) -> str:
        # Signed by the bucket's own regional client (SigV4 requires the right
        # region). Single object, short TTL — handed only to a caller that has
        # already passed the permission check.
        return self._for(bucket).generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in)

    def delete(self, bucket: str, key: str) -> None:
        self._for(bucket).delete_object(Bucket=bucket, Key=key)


class DynamoIndexStore(IndexStore):
    def __init__(
        self,
        files_table: str,
        fragments_table: str,
        sha_index: str = "sha-index",
        dynamodb=None,
    ) -> None:
        self._db = dynamodb or boto3.resource("dynamodb", region_name=_region())
        self._files = self._db.Table(files_table)
        self._fragments = self._db.Table(fragments_table)
        self._sha_index = sha_index

    def put_file(self, rec: FileRecord) -> None:
        item = {
            "file_id": rec.file_id,
            "file_sha256": rec.file_sha256,
            "content_type": rec.content_type,
            "fragment_count": rec.fragment_count,
            "size": rec.size,
            "created_at": rec.created_at,
        }
        if rec.label is not None:
            item["label"] = rec.label
        self._files.put_item(Item=item)

    def get_file(self, file_id: str) -> FileRecord | None:
        item = self._files.get_item(Key={"file_id": file_id}).get("Item")
        return self._to_file(item) if item else None

    def find_file_by_sha(self, file_sha256: str) -> FileRecord | None:
        from boto3.dynamodb.conditions import Key

        resp = self._files.query(
            IndexName=self._sha_index,
            KeyConditionExpression=Key("file_sha256").eq(file_sha256),
            Limit=1,
        )
        items = resp.get("Items", [])
        return self._to_file(items[0]) if items else None

    def put_fragment(self, rec: FragmentRecord) -> None:
        self._fragments.put_item(
            Item={
                "file_id": rec.file_id,
                "sequence": rec.sequence,
                "fragment_id": rec.fragment_id,
                "bucket": rec.bucket,
                "wrapped_key": rec.wrapped_key,  # Binary
                "nonce": rec.nonce,              # Binary
            }
        )

    def get_fragments(self, file_id: str) -> list[FragmentRecord]:
        from boto3.dynamodb.conditions import Key

        resp = self._fragments.query(
            KeyConditionExpression=Key("file_id").eq(file_id),
            ScanIndexForward=True,  # sorted by sequence ascending
        )
        return [self._to_fragment(i) for i in resp.get("Items", [])]

    def delete_file(self, file_id: str) -> None:
        for fr in self.get_fragments(file_id):
            self._fragments.delete_item(Key={"file_id": file_id, "sequence": fr.sequence})
        self._files.delete_item(Key={"file_id": file_id})

    @staticmethod
    def _to_file(item: dict) -> FileRecord:
        return FileRecord(
            file_id=item["file_id"],
            file_sha256=item["file_sha256"],
            content_type=item["content_type"],
            fragment_count=int(item["fragment_count"]),
            size=int(item["size"]),
            created_at=item["created_at"],
            label=item.get("label"),
        )

    @staticmethod
    def _to_fragment(item: dict) -> FragmentRecord:
        def _b(v) -> bytes:
            # boto3 returns Binary; .value is bytes.
            return bytes(v.value) if hasattr(v, "value") else bytes(v)

        return FragmentRecord(
            file_id=item["file_id"],
            sequence=int(item["sequence"]),
            fragment_id=item["fragment_id"],
            bucket=item["bucket"],
            wrapped_key=_b(item["wrapped_key"]),
            nonce=_b(item["nonce"]),
        )
