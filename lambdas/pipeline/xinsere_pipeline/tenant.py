"""Tenant configuration loaded from AWS Secrets Manager.

The dev tenant secret (`xinsere/dev/tenant-default`) holds the canonical KMS key
and the HMAC salt used to hash grantee ids on-chain. Both the pipeline (KMS) and
the blockchain permission layer (grantee hashing) MUST use these same values, or
grants written by one component won't verify in another.
"""
from __future__ import annotations

import functools
import json
import os

import boto3

TENANT_SECRET_ID = os.environ.get("XINSERE_TENANT_SECRET_ID", "xinsere/dev/tenant-default")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


@functools.lru_cache(maxsize=8)
def load_tenant_config(secret_id: str = TENANT_SECRET_ID, region: str = AWS_REGION) -> dict:
    """Return {kms_key_id, kms_key_arn, hmac_party_id_salt}. Cached per secret."""
    raw = boto3.client("secretsmanager", region_name=region).get_secret_value(
        SecretId=secret_id)["SecretString"]
    data = json.loads(raw)
    return {
        "kms_key_id": data.get("kms_key_id") or data.get("kms_key_arn"),
        "kms_key_arn": data.get("kms_key_arn"),
        "hmac_party_id_salt": data.get("hmac_party_id_salt"),
    }
