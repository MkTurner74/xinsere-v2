"""Per-user grant-rate cap for interactive shares (Finding 2 completion).

Companion to share_grants.py. The batch path bounds the on-chain COST of a single
share action (<=1 flat-gas tx per 1,000 files); this bounds the RATE of share
actions per user, so an abusive/compromised interactive account can't drain the
shared gas wallet with a loop of share calls.

Durable counters in Postgres via the atomic xinsere_bump_share_rate() RPC
(migration 0012) — no in-process state (serverless). Fail-OPEN on a counter-store
hiccup, matching quotas.py ("telemetry never blocks legitimate action"); the
low-balance wallet guard and the batch cap are the backstops.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import HTTPException

import supa

_log = logging.getLogger("xinsere.share_quota")

# Generous — meant to stop a drain loop, not normal use. A human sharing many
# folders in a burst stays well under these; a script firing grants does not.
SHARE_PER_MIN = int(os.environ.get("XINSERE_SHARE_PER_MIN", "40"))
SHARE_PER_DAY = int(os.environ.get("XINSERE_SHARE_PER_DAY", "1000"))


def _bump(user_id: str, window: str, bucket: str, count: int = 1) -> int:
    rows = supa._rest("POST", "/rpc/xinsere_bump_share_rate", supa.SERVICE_ROLE_KEY,
                      json_body={"p_user_id": user_id, "p_window": window,
                                 "p_bucket": bucket, "p_count": count})
    row = (rows[0] if isinstance(rows, list) and rows else rows) or {}
    return int(row.get("count", 0))


def enforce_share_rate(user_id: str) -> None:
    """Count one interactive share action against the user's per-minute and per-day
    caps; 429 if over either. Fail-open if the counter store is briefly unreachable."""
    if not user_id or not supa.SERVICE_ROLE_KEY:
        return
    now = datetime.now(timezone.utc)
    try:
        per_min = _bump(user_id, "minute", now.strftime("%Y-%m-%d %H:%M"))
        per_day = _bump(user_id, "day", now.strftime("%Y-%m-%d"))
    except Exception as exc:  # fail-open on counter trouble (wallet guard is the backstop)
        _log.warning("share-rate counter unavailable (fail-open) user=%s: %s", user_id, exc)
        return
    if per_min > SHARE_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail=f"Too many shares — limit is {SHARE_PER_MIN}/min [share_rate_limited]. Slow down.")
    if per_day > SHARE_PER_DAY:
        raise HTTPException(
            status_code=429,
            detail=f"Daily share limit reached ({SHARE_PER_DAY}/day) [share_rate_limited].")
