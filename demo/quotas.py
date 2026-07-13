"""Per-API-key usage quotas — anti-exfiltration rate + egress limits.

Enforced at the /v1 edge so a single leaked key cannot drain an org: a burst of
requests is capped per-minute, and bulk data egress (server-side downloads and
client-side retrieval plans) is capped per-day. Counters are durable in Postgres
via the atomic xinsere_bump_usage() RPC (migration 0004) — no shared in-process
state, which matters on serverless.

Failure posture: if the counter store is briefly unreachable we **fail open** (log
+ allow) rather than break legitimate traffic on a transient Supabase hiccup —
matching the codebase's "telemetry never blocks auth" rule. The tamper-proof
on-chain access log (next feature) is the backstop that makes exfiltration
*detectable* even across such a window.

Limits are global defaults via env; per-key overrides can be added later without
touching callers.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import HTTPException

import supa

_log = logging.getLogger("xinsere.quotas")

# Generous defaults — meant to stop bulk exfiltration, not normal integration use.
RATE_PER_MIN = int(os.environ.get("XINSERE_RATE_PER_MIN", "300"))
EGRESS_BYTES_PER_DAY = int(os.environ.get("XINSERE_EGRESS_BYTES_PER_DAY", str(20 * 1024 ** 3)))  # 20 GiB
EGRESS_FILES_PER_DAY = int(os.environ.get("XINSERE_EGRESS_FILES_PER_DAY", "5000"))

# Per-ORG daily ceilings (Finding 8): egress can't be multiplied across an org's
# keys, and ingest is bounded so a self-serve connector can't run up unbounded cost.
EGRESS_BYTES_PER_DAY_ORG = int(os.environ.get("XINSERE_EGRESS_BYTES_PER_DAY_ORG", str(200 * 1024 ** 3)))  # 200 GiB
EGRESS_FILES_PER_DAY_ORG = int(os.environ.get("XINSERE_EGRESS_FILES_PER_DAY_ORG", "50000"))
INGEST_BYTES_PER_DAY_ORG = int(os.environ.get("XINSERE_INGEST_BYTES_PER_DAY_ORG", str(500 * 1024 ** 3)))  # 500 GiB
INGEST_FILES_PER_DAY_ORG = int(os.environ.get("XINSERE_INGEST_FILES_PER_DAY_ORG", "200000"))


def _bump(key_id: str, window: str, bucket: str,
          requests: int = 0, nbytes: int = 0, files: int = 0) -> dict:
    """Atomic increment; returns the post-increment totals for this window/bucket."""
    rows = supa._rest("POST", "/rpc/xinsere_bump_usage", supa.SERVICE_ROLE_KEY, json_body={
        "p_key_id": key_id, "p_window": window, "p_bucket": bucket,
        "p_requests": requests, "p_bytes": nbytes, "p_files": files})
    row = (rows[0] if isinstance(rows, list) and rows else rows) or {}
    return {"requests": int(row.get("requests", 0)),
            "bytes": int(row.get("bytes", 0)),
            "files": int(row.get("files", 0))}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enforce_request(ctx: dict) -> None:
    """Count this request against the caller's per-minute rate limit; 429 if over."""
    key_id = ctx.get("key_id")
    if not key_id:
        return
    bucket = _now().strftime("%Y-%m-%d %H:%M")
    try:
        usage = _bump(key_id, "minute", bucket, requests=1)
    except Exception as exc:  # fail-open on counter-store trouble
        _log.warning("rate counter unavailable (fail-open) key=%s: %s", key_id, exc)
        return
    if usage["requests"] > RATE_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_PER_MIN}/min) [rate_limited] — slow down")


def record_and_enforce_egress(ctx: dict, nbytes: int) -> None:
    """Count a file egress (one file, `nbytes`) against the per-day quota; 429 if
    over on either bytes or file count. Call before serving a download/plan."""
    key_id = ctx.get("key_id")
    if not key_id:
        return
    bucket = _now().strftime("%Y-%m-%d")
    try:
        usage = _bump(key_id, "day", bucket, nbytes=int(nbytes or 0), files=1)
    except Exception as exc:  # fail-open on counter-store trouble
        _log.warning("egress counter unavailable (fail-open) key=%s: %s", key_id, exc)
        return
    if usage["bytes"] > EGRESS_BYTES_PER_DAY or usage["files"] > EGRESS_FILES_PER_DAY:
        raise HTTPException(
            status_code=429,
            detail=(f"Daily egress quota exceeded "
                    f"({EGRESS_FILES_PER_DAY} files / {EGRESS_BYTES_PER_DAY} bytes) "
                    f"[egress_quota] — try again tomorrow or contact your admin"))
    _enforce_org(ctx, egress_bytes=int(nbytes or 0), egress_files=1)


def _bump_org(org_id: str, bucket: str, **counts) -> dict:
    rows = supa._rest("POST", "/rpc/xinsere_bump_org_usage", supa.SERVICE_ROLE_KEY,
                      json_body={"p_org_id": org_id, "p_bucket": bucket,
                                 **{f"p_{k}": int(v) for k, v in counts.items()}})
    return (rows[0] if isinstance(rows, list) and rows else rows) or {}


def _enforce_org(ctx: dict, *, egress_bytes: int = 0, egress_files: int = 0,
                 ingest_bytes: int = 0, ingest_files: int = 0) -> None:
    """Count this op against the org's daily ceilings; 429 if over. Fail-open on a
    counter hiccup (per-key limits + the on-chain access log are the backstops)."""
    org_id = ctx.get("org_id")
    if not org_id:
        return
    bucket = _now().strftime("%Y-%m-%d")
    try:
        u = _bump_org(org_id, bucket, egress_bytes=egress_bytes, egress_files=egress_files,
                      ingest_bytes=ingest_bytes, ingest_files=ingest_files)
    except Exception as exc:
        _log.warning("org usage counter unavailable (fail-open) org=%s: %s", org_id, exc)
        return
    if int(u.get("egress_bytes", 0)) > EGRESS_BYTES_PER_DAY_ORG or \
            int(u.get("egress_files", 0)) > EGRESS_FILES_PER_DAY_ORG:
        raise HTTPException(status_code=429,
                            detail="Organization daily egress quota exceeded [org_egress_quota]")
    if int(u.get("ingest_bytes", 0)) > INGEST_BYTES_PER_DAY_ORG or \
            int(u.get("ingest_files", 0)) > INGEST_FILES_PER_DAY_ORG:
        raise HTTPException(status_code=429,
                            detail="Organization daily ingest quota exceeded [org_ingest_quota]")


def record_and_enforce_ingest(ctx: dict, nbytes: int) -> None:
    """Count a stored file (one file, `nbytes`) against the org's per-day ingest
    ceiling; 429 if over. Call before the pipeline stores an uploaded file."""
    _enforce_org(ctx, ingest_bytes=int(nbytes or 0), ingest_files=1)
