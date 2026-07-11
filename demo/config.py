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


def _tenant_salt_status() -> tuple[str, str | None]:
    """Resolve the HMAC tenant salt's security state without importing web3/boto3
    eagerly. Returns (state, detail):
      'ok'           — a non-default salt is configured (env or tenant secret)
      'bad'          — POSITIVELY insecure (empty / the dev default)
      'unverifiable' — could not read the tenant secret at boot (transient?)
    We distinguish 'bad' from 'unverifiable' so a Secrets Manager hiccup at cold
    start can't brick the whole app — only a *known-insecure* value is fatal."""
    env = os.environ.get("XINSERE_TENANT_SALT")
    if env is not None:
        if env == "" or env == DEFAULT_TENANT_SALT:
            return "bad", "XINSERE_TENANT_SALT is empty or the insecure dev default"
        return "ok", None
    try:
        from xinsere_pipeline.tenant import load_tenant_config
        salt = load_tenant_config().get("hmac_party_id_salt")
    except Exception as exc:
        return "unverifiable", f"could not read the tenant secret at boot ({type(exc).__name__})"
    if not salt or salt == DEFAULT_TENANT_SALT:
        return "bad", "tenant secret hmac_party_id_salt is missing or the insecure dev default"
    return "ok", None


def validate_production_config() -> None:
    """Fail-closed startup check. Raises RuntimeError in production ONLY when a
    security-critical value is positively known to be insecure (default/empty).
    An unverifiable salt logs a loud warning but does not block boot. No-op in dev."""
    if not is_production():
        return
    import logging
    log = logging.getLogger("xinsere.config")
    fatal: list[str] = []
    if session_secret() in ("", DEFAULT_SESSION_SECRET):
        fatal.append(
            "XINSERE_SESSION_SECRET is unset/default — session cookies would be "
            "signed with a publicly-known key")
    state, detail = _tenant_salt_status()
    if state == "bad":
        fatal.append(
            f"HMAC tenant salt is insecure — {detail}; set XINSERE_TENANT_SALT or "
            "hmac_party_id_salt in the tenant secret (on-chain grantee privacy depends on it)")
    elif state == "unverifiable":
        log.error("SECURITY: tenant salt unverifiable at startup — %s. Proceeding, but "
                  "confirm the salt is configured; the chain layer must not fall back to "
                  "the dev default in production.", detail)
    if fatal:
        raise RuntimeError(
            "Refusing to start in production with insecure configuration:\n  - "
            + "\n  - ".join(fatal))
