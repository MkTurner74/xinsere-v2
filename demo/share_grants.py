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
from concurrent.futures import ThreadPoolExecutor

import batch_grant
import supa
from chain import CHAIN

_log = logging.getLogger("xinsere.share_grants")


def grant_share(svc: str, files: list[dict], grantee: str, share_node: str,
                source: str, share_type: str = "download",
                not_before: int = 0, not_after: int = 0) -> batch_grant.BatchResult | None:
    """Anchor grants for (each file, `grantee`) as capped batches and record
    the resulting root(s) under (`share_node`, `grantee`). `share_type` binds the
    permission level into each Merkle leaf (0016): `view` grants pass only the
    preview gate, never download. `not_before`/`not_after` (unix seconds, 0 =
    unbounded) anchor a validity WINDOW enforced on-chain by verifyBatch — an
    end-dated share needs no revoke tx. Returns the BatchResult (None if there were
    no files to grant). Raises if nothing anchored (so the caller can surface a 502
    and the owner can retry) -- a partial anchor keeps the roots it did land and
    records them, so a retry is idempotent."""
    grants = [batch_grant.Grant(f["file_id"], grantee, share_type)
              for f in files if f.get("file_id")]
    if not grants:
        return None
    res = batch_grant.preserve(grants, supa=supa, token=svc, source=source, scope=share_node,
                               not_before=not_before, not_after=not_after)
    for root_hex in res.roots:
        try:
            supa.insert_share_batch(svc, share_node, grantee, root_hex)
        except Exception as exc:
            # Best-effort is SAFE only because revoke_share also derives roots from
            # the proof cache (batch_grants ⋈ permission_batches) — a lost mapping
            # row no longer strands a live on-chain grant. Still log loudly.
            _log.warning("share_batch mapping insert failed node=%s grantee=%s root=%s: %s",
                         share_node, grantee, root_hex[:12], exc)
    if not res.roots:
        raise RuntimeError(f"share grant anchored no roots: {res.failed}")
    return res


def revoke_share(svc: str, share_node: str, grantee: str) -> dict:
    """Revoke every batch root anchored for (`share_node`, `grantee`) with a single
    revokeBatchRoot per root. Root-level revoke is exact here because interactive
    roots are single-grantee. Fail-closed: if a revoke tx errors, the mapping row
    is KEPT so the owner sees the share and can retry; other roots still process.
    Returns {revoked, errors, roots}.

    Roots come from the union of the share_batches mapping AND a derivation from
    the proof cache (batch_grants ⋈ permission_batches). The derivation makes
    revocation correct even for shares whose mapping row was never recorded
    (2026-07-15 incident: migration 0011 unapplied in prod). If NEITHER source is
    readable we cannot know what to revoke — report an error so the caller keeps
    the share row (fail closed) instead of deleting it with grants still live."""
    roots: set[str] = set()
    mapped_ok = derived_ok = True
    try:
        roots.update(supa.share_batch_roots(svc, share_node, grantee))
    except Exception as exc:
        mapped_ok = False
        _log.warning("share_batches lookup failed (migration 0011 applied?) "
                     "node=%s grantee=%s: %s", share_node, grantee, exc)
    try:
        roots.update(supa.derived_share_roots(svc, share_node, grantee))
    except Exception as exc:
        derived_ok = False
        _log.warning("derived-root lookup failed node=%s grantee=%s: %s",
                     share_node, grantee, exc)
    if not mapped_ok and not derived_ok:
        return {"revoked": 0, "errors": 1, "roots": 0}
    revoked, errors = 0, 0
    # Classify roots with parallel view calls, then revoke the anchored ones in ONE
    # nonce-sequenced send pass — a share can hold many grant-on-add roots (one per
    # file added while shared), and sequential per-root confirmation waits blew the
    # serverless request budget (2026-07-15 hang).
    anchored: list[tuple[str, bytes]] = []      # need an on-chain revoke tx
    cleanup: list[str] = []                     # already revoked/never anchored
    def _classify(root_hex: str):
        root = bytes.fromhex(root_hex[2:] if root_hex.startswith("0x") else root_hex)
        return root, CHAIN.root_anchored(root)   # 0 == already revoked/never anchored
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [(rh, ex.submit(_classify, rh)) for rh in sorted(roots)]
        for root_hex, fut in futures:
            try:
                root, anchored_ts = fut.result()
                (anchored.append((root_hex, root)) if anchored_ts
                 else cleanup.append(root_hex))
            except Exception as exc:
                errors += 1
                _log.warning("root check failed node=%s grantee=%s root=%s: %s",
                             share_node, grantee, root_hex[:12], exc)
    results = CHAIN.revoke_batch_roots([r for _, r in anchored]) if anchored else []
    for (root_hex, _), res in zip(anchored, results):
        if isinstance(res, Exception):
            errors += 1
            _log.warning("revoke_batch_root failed node=%s grantee=%s root=%s: %s",
                         share_node, grantee, root_hex[:12], res)
            continue                            # mapping kept — owner retries (fail closed)
        _cleanup_mapping(svc, share_node, grantee, root_hex)
        revoked += 1
    for root_hex in cleanup:
        _cleanup_mapping(svc, share_node, grantee, root_hex)
        revoked += 1
    return {"revoked": revoked, "errors": errors, "roots": len(roots)}


def _cleanup_mapping(svc: str, share_node: str, grantee: str, root_hex: str) -> None:
    """Best-effort bookkeeping after an on-chain revoke — the chain is truth, so a
    failed status write or a missing mapping row (derived root) is never an error."""
    try:
        supa.set_batch_status(svc, root_hex, "revoked")
    except Exception:
        pass
    try:
        supa.delete_share_batch(svc, share_node, grantee, root_hex)
    except Exception:
        pass


def reanchor_share(svc: str, share_node: str, grantee: str,
                   files: list[dict], source: str = "reanchor",
                   share_type: str = "download") -> dict:
    """Revoke the current roots for (`share_node`, `grantee`) and re-anchor grants
    over `files` (the share_node subtree's CURRENT file set). Used by `move`, where
    the tree changed under a folder share: re-preserving files_under(share_node)
    after the move naturally includes/excludes the moved subtree. Brief window
    between revoke and re-grant is accepted (rare op, sequential txs)."""
    rev = revoke_share(svc, share_node, grantee)
    res = None
    try:
        res = grant_share(svc, files, grantee, share_node, source, share_type)
    except Exception as exc:
        _log.warning("reanchor re-grant failed node=%s grantee=%s: %s", share_node, grantee, exc)
    return {"revoked": rev["revoked"], "revoke_errors": rev["errors"],
            "regranted": (res.grants if res else 0)}
