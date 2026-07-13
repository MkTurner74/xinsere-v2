"""Interactive share grant/revoke over the capped Merkle batch path (Finding 2).

Replaces the per-file `CHAIN.grant`/`CHAIN.revoke` loops in the interactive app
(1 tx/file -> denial-of-wallet on the shared gas wallet) with flat-gas batch roots:
<= 1 tx per `cap` files regardless of how many files a folder holds.

Design invariants that make root-level revocation exact:
  * every interactive share action anchors SINGLE-GRANTEE, node-scoped roots, so
    revoking a whole root (revokeBatchRoot) revokes precisely that share and
    touches no other grantee;
  * each anchored root is recorded in `share_batches` under (node_id, grantee), so
    a later unshare/erase/move revokes exactly the right roots -- no guessing from
    the proof cache.

The download gate already trusts batch grants (app._has_access -> verify_batch),
so callers need no read-side change. All writes here use the SERVICE-ROLE key
(the batch/share_batches tables are deny-by-default RLS); the caller MUST have
authorized the owner action before invoking these.
"""
from __future__ import annotations

import logging

import batch_grant
import supa
from chain import CHAIN

_log = logging.getLogger("xinsere.share_grants")


def grant_share(svc: str, files: list[dict], grantee: str, share_node: str,
                source: str) -> batch_grant.BatchResult | None:
    """Anchor read grants for (each file, `grantee`) as capped batches and record
    the resulting root(s) under (`share_node`, `grantee`). Returns the BatchResult
    (None if there were no files to grant). Raises if nothing anchored (so the
    caller can surface a 502 and the owner can retry) -- a partial anchor keeps the
    roots it did land and records them, so a retry is idempotent."""
    grants = [batch_grant.Grant(f["file_id"], grantee) for f in files if f.get("file_id")]
    if not grants:
        return None
    res = batch_grant.preserve(grants, supa=supa, token=svc, source=source, scope=share_node)
    for root_hex in res.roots:
        try:
            supa.insert_share_batch(svc, share_node, grantee, root_hex)
        except Exception as exc:  # mapping is best-effort telemetry-adjacent; log loudly
            _log.warning("share_batch mapping insert failed node=%s grantee=%s root=%s: %s",
                         share_node, grantee, root_hex[:12], exc)
    if not res.roots:
        raise RuntimeError(f"share grant anchored no roots: {res.failed}")
    return res


def revoke_share(svc: str, share_node: str, grantee: str) -> dict:
    """Revoke every batch root recorded for (`share_node`, `grantee`) with a single
    revokeBatchRoot per root. Root-level revoke is exact here because interactive
    roots are single-grantee. Fail-closed: if a revoke tx errors, the mapping row
    is KEPT so the owner sees the share and can retry; other roots still process.
    Returns {revoked, errors, roots}."""
    roots = supa.share_batch_roots(svc, share_node, grantee)
    revoked, errors = 0, 0
    for root_hex in roots:
        try:
            root = bytes.fromhex(root_hex[2:] if root_hex.startswith("0x") else root_hex)
            if CHAIN.root_anchored(root):          # 0 == already revoked/never anchored
                CHAIN.revoke_batch_root(root)
            try:
                supa.set_batch_status(svc, root_hex, "revoked")
            except Exception:
                pass                                # cosmetic status; on-chain revoke is truth
            supa.delete_share_batch(svc, share_node, grantee, root_hex)
            revoked += 1
        except Exception as exc:
            errors += 1
            _log.warning("revoke_batch_root failed node=%s grantee=%s root=%s: %s",
                         share_node, grantee, root_hex[:12], exc)
    return {"revoked": revoked, "errors": errors, "roots": len(roots)}


def reanchor_share(svc: str, share_node: str, grantee: str,
                   files: list[dict], source: str = "reanchor") -> dict:
    """Revoke the current roots for (`share_node`, `grantee`) and re-anchor grants
    over `files` (the share_node subtree's CURRENT file set). Used by `move`, where
    the tree changed under a folder share: re-preserving files_under(share_node)
    after the move naturally includes/excludes the moved subtree. Brief window
    between revoke and re-grant is accepted (rare op, sequential txs)."""
    rev = revoke_share(svc, share_node, grantee)
    res = None
    try:
        res = grant_share(svc, files, grantee, share_node, source)
    except Exception as exc:
        _log.warning("reanchor re-grant failed node=%s grantee=%s: %s", share_node, grantee, exc)
    return {"revoked": rev["revoked"], "revoke_errors": rev["errors"],
            "regranted": (res.grants if res else 0)}
