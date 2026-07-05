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

import boto3
from botocore.exceptions import ClientError

from .base import FileRecord, FragmentRecord, IndexStore, KeyManager, ObjectStore


class KmsKeyManager(KeyManager):
    def __init__(self, key_id: str, kms_client=None) -> None:
        self._key_id = key_id
        self._kms = kms_client or boto3.client("kms")

    def generate_data_key(self) -> tuple[bytes, bytes]:
        resp = self._kms.generate_data_key(KeyId=self._key_id, KeySpec="AES_256")
        return resp["Plaintext"], resp["CiphertextBlob"]

    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        return self._kms.decrypt(CiphertextBlob=wrapped_key)["Plaintext"]


class S3ObjectStore(ObjectStore):
    def __init__(self, bucket_names: list[str], s3_client=None) -> None:
        self._names = list(bucket_names)
        self._s3 = s3_client or boto3.client("s3")

    def buckets(self) -> list[str]:
        return list(self._names)

    def put(self, bucket: str, key: str, data: bytes) -> None:
        # SSE-KMS enforced at the bucket level (P0-08); no plaintext at rest.
        self._s3.put_object(Bucket=bucket, Key=key, Body=data)

    def get(self, bucket: str, key: str) -> bytes:
        try:
            return self._s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                raise FileNotFoundError(f"s3://{bucket}/{key}") from exc
            raise

    def delete(self, bucket: str, key: str) -> None:
        self._s3.delete_object(Bucket=bucket, Key=key)


class DynamoIndexStore(IndexStore):
    def __init__(
        self,
        files_table: str,
        fragments_table: str,
        sha_index: str = "sha-index",
        dynamodb=None,
    ) -> None:
        self._db = dynamodb or boto3.resource("dynamodb")
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
