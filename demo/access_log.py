"""Tamper-evident, per-user access log + daily on-chain Merkle anchor.

Every data access — by an API key or (later) an interactive user — is recorded
against the INDIVIDUAL acting identity, so a breach or anomaly scopes back to whose
credentials were used, and the same signal catches an insider mass-download.

Integrity model (see migration 0005):
- Each access is one append-only row with a content hash `entry_hash =
  sha256(canonical(event))`. No write-time chaining, so concurrent serverless
  writes never contend.
- A daily job builds a **Merkle root** over that day's entry_hashes and anchors it
  on-chain (Polygon). You can't alter or delete any entry from an anchored day
  without changing the root, which is immutable on-chain. That anchor — not a
  fragile write-time chain — is the tamper-proof guarantee.

Export: `to_ocsf()` maps a row to an OCSF File Activity event so a customer's own
SIEM/UEBA can consume the log as ground truth (build-vs-buy: integrate, don't
rebuild the analytics). We ship the source of truth; they keep their scoring.

Failure posture: recording is best-effort/fail-open — a logging outage must never
block a legitimate access. The on-chain anchor plus alerting are the backstop.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

import supa

_log = logging.getLogger("xinsere.access_log")

GENESIS = "0" * 64


# --- pure integrity primitives (unit-tested, no I/O) -------------------------

def canonical(event: dict) -> bytes:
    """Deterministic serialization for hashing: sorted keys, compact, UTF-8."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def entry_hash(event: dict) -> str:
    return hashlib.sha256(canonical(event)).hexdigest()


def _pair(a: str, b: str) -> str:
    return hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    """Binary Merkle root over hex leaf hashes. Empty -> genesis; odd level
    duplicates the last node (standard). Deterministic given leaf order."""
    if not hashes:
        return GENESIS
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def build_daily_root(entries: list[dict]) -> tuple[str, int]:
    """(merkle_root, count) over a day's entries, ordered deterministically by
    (ts, id) so the root is reproducible from the stored rows at audit time."""
    ordered = sorted(entries, key=lambda e: (e.get("ts", ""), e.get("id", "")))
    return merkle_root([e["entry_hash"] for e in ordered]), len(ordered)


# --- OCSF File Activity mapping (SIEM export) --------------------------------

# OCSF File System Activity (class_uid 1001) activity ids we emit.
_OCSF_ACTIVITY = {
    "file.read": 2,           # Read
    "file.download_plan": 2,  # Read (keys handed out)
    "file.import": 1,         # Create (cloud-to-cloud migration ingest)
    "file.delete": 4,         # Delete
    "grant": 6,               # (Access) — mapped to a permission change
    "revoke": 6,
}


def to_ocsf(row: dict) -> dict:
    """Map a stored access_log row to an OCSF File System Activity event."""
    return {
        "category_uid": 1,            # System Activity
        "class_uid": 1001,           # File System Activity
        "class_name": "File System Activity",
        "activity_id": _OCSF_ACTIVITY.get(row.get("action"), 0),
        "time": row.get("ts"),
        "severity_id": 1,
        "actor": {
            "user": {"uid": row.get("actor_id"), "type": row.get("actor_type")},
            "session": {"uid": row.get("key_id")} if row.get("key_id") else None,
        },
        "file": {"uid": row.get("file_id"), "name": row.get("node_id"),
                 "size": row.get("bytes")},
        "metadata": {
            "product": {"name": "Xinsere", "vendor_name": "Xinsere Inc."},
            "org_uid": row.get("org_id"),
            # Xinsere enrichment: the tamper-proof anchor a SIEM can trust.
            "xinsere": {"entry_hash": row.get("entry_hash"),
                        "action": row.get("action"),
                        "anchor_day": str(row.get("day"))},
        },
    }


# --- recorder (fail-open) ----------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_entry(*, org_id, actor_id, actor_type, action,
                key_id=None, file_id=None, node_id=None, bytes=0, meta=None) -> dict:
    """Construct the access event and its content hash (no I/O)."""
    ts = _now_iso()
    day = ts[:10]
    core = {  # the fields the entry_hash commits to
        "ts": ts, "day": day, "org_id": org_id, "actor_id": actor_id,
        "actor_type": actor_type, "key_id": key_id, "action": action,
        "file_id": file_id, "node_id": node_id, "bytes": int(bytes or 0),
        "meta": meta or {},
    }
    return {**core, "entry_hash": entry_hash(core)}


def record(*, org_id, actor_id, actor_type, action,
           key_id=None, file_id=None, node_id=None, bytes=0, meta=None) -> dict | None:
    """Record one access. Best-effort: never raises to the caller (fail-open)."""
    entry = build_entry(org_id=org_id, actor_id=actor_id, actor_type=actor_type,
                        action=action, key_id=key_id, file_id=file_id,
                        node_id=node_id, bytes=bytes, meta=meta)
    try:
        supa._rest("POST", "/access_log", supa.SERVICE_ROLE_KEY, json_body={
            "org_id": org_id, "actor_id": actor_id, "actor_type": actor_type,
            "key_id": key_id, "action": action, "file_id": file_id,
            "node_id": node_id, "bytes": int(bytes or 0),
            "entry_hash": entry["entry_hash"], "meta": entry["meta"]})
    except Exception as exc:  # fail-open — logging must never block access
        _log.warning("access_log insert failed (fail-open) actor=%s action=%s: %s",
                     actor_id, action, exc)
    return entry
