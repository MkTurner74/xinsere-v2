"""Runtime configuration + fail-closed production guards.

Central place for the security-relevant environment. `validate_production_config()`
is called once at app startup (app.py); in the AWS backend it REFUSES to boot when a
security-critical secret is missing or still set to its development default — so a
misconfigured production deploy fails loudly instead of serving with a known secret.

Local/offline dev (`XINSERE_BACKEND` != aws) keeps the friendly defaults.
"""
from __future__ import annotations

import os

# Sentinels that must never reach production.
DEFAULT_SESSION_SECRET = "xinsere-demo-dev-secret"
DEFAULT_TENANT_SALT = "dev-tenant-salt-change-me"


def is_production() -> bool:
    """Production == the real AWS pipeline backend (S3/KMS/DynamoDB)."""
    return os.environ.get("XINSERE_BACKEND", "local").lower() == "aws"


def session_secret() -> str:
    return os.environ.get("XINSERE_SESSION_SECRET", DEFAULT_SESSION_SECRET)


def https_only() -> bool:
    """Secure-cookie flag. Defaults ON in production, OFF for local http dev.
    Explicit `XINSERE_HTTPS_ONLY` always wins."""
    env = os.environ.get("XINSERE_HTTPS_ONLY")
    if env is not None:
        return env.lower() == "true"
    return is_production()


def _tenant_salt_configured() -> bool:
    """True if a NON-default HMAC salt is resolvable (env or tenant secret).
    Mirrors chain._tenant_salt() resolution order without importing web3/boto3
    eagerly — a missing tenant secret is treated as 'not configured'."""
    env = os.environ.get("XINSERE_TENANT_SALT")
    if env and env != DEFAULT_TENANT_SALT:
        return True
    try:
        from xinsere_pipeline.tenant import load_tenant_config
        salt = load_tenant_config().get("hmac_party_id_salt")
        return bool(salt) and salt != DEFAULT_TENANT_SALT
    except Exception:
        return False


def validate_production_config() -> None:
    """Fail-closed startup check. Raises RuntimeError in production when a
    security-critical value is missing or default. No-op in local/dev."""
    if not is_production():
        return
    problems: list[str] = []
    if session_secret() in ("", DEFAULT_SESSION_SECRET):
        problems.append(
            "XINSERE_SESSION_SECRET is unset/default — session cookies would be "
            "signed with a publicly-known key")
    if not _tenant_salt_configured():
        problems.append(
            "HMAC tenant salt is unset/default — set XINSERE_TENANT_SALT or provide "
            "hmac_party_id_salt in the tenant secret (on-chain grantee privacy depends on it)")
    if problems:
        raise RuntimeError(
            "Refusing to start in production with insecure configuration:\n  - "
            + "\n  - ".join(problems))
