"""Merkle aggregate batch-grant engine — reusable across every migration connector.

Preserves a set of (file, grantee) permission grants at scale for the cost of a
handful of on-chain transactions instead of one-per-grant. See
ADR-2026-07-13-merkle-aggregate-batch-grant.md.

Flow per batch (<= cap leaves):
    build leaves -> merkle root -> grantBatch(root, size)  [1 tx, flat gas]
      -> store batch header + per-grant proofs in Supabase (rebuildable cache)
      -> READ THE ROOT BACK on-chain and re-verify a sample of proofs
      -> only then mark the batch 'live' (download gate trusts live batches)

Safety (Mark's three conditions, enforced here):
  * CAP: leaves are chunked at `cap` (default 1,000) so a bad root can only ever
    affect that chunk — never the whole migration.
  * FLAT GAS: only the root is anchored on-chain; batch size doesn't change gas.
  * FAIL CLOSED + REBUILDABLE: the on-chain root is truth; the proof cache is a
    convenience regenerable from the manifest. A batch that fails its read-back
    check stays non-'live' and is never trusted.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import chain
import merkle

_log = logging.getLogger("xinsere.batch_grant")

DEFAULT_CAP = int(os.environ.get("XINSERE_BATCH_MAX", "1000"))
# How many proofs to re-verify on-chain after anchoring before trusting a batch.
# All of them for small batches; a sample for large ones (each is a free view call,
# but they add wall-time). 0 disables (not recommended).
READBACK_SAMPLE = int(os.environ.get("XINSERE_BATCH_READBACK_SAMPLE", "8"))


@dataclass
class Grant:
    """One permission to preserve: grantee `grantee_id` may access file `file_id`
    at `grant_type` level. `download` (the default, and every pre-0016 grant)
    uses the legacy 2-part leaf; other types bind the level into the leaf."""
    file_id: str
    grantee_id: str
    grant_type: str = "download"

    def hashes(self) -> tuple[bytes, bytes]:
        return chain.file_hash(self.file_id), chain.grantee_hash(self.grantee_id)

    def leaf(self) -> bytes:
        return merkle.leaf_typed(*self.hashes(), self.grant_type)


@dataclass
class BatchResult:
    batches: int = 0
    grants: int = 0
    tx_hashes: list[str] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)  # (root_or_scope, reason)

    def as_dict(self) -> dict:
        return {"batches": self.batches, "grants": self.grants,
                "tx_hashes": self.tx_hashes, "roots": self.roots, "failed": self.failed}


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def preserve(grants: list[Grant], *, supa, token: str, source: str, scope: str | None,
             cap: int = DEFAULT_CAP, chain_client=chain.CHAIN,
             readback_sample: int = READBACK_SAMPLE) -> BatchResult:
    """Anchor `grants` as capped Merkle batches. `supa`/`token` are the (service-role)
    Supabase client + key for the proof cache. Returns a BatchResult; per-batch
    failures are isolated so one bad chunk never aborts the rest."""
    res = BatchResult()
    # Dedupe (a folder-level share can enumerate the same (file,grantee) twice).
    uniq = list({(g.file_id, g.grantee_id, g.grant_type): g for g in grants}.values())
    if not uniq:
        return res

    for chunk in _chunks(uniq, cap):
        # Deterministic leaf order = the commitment; store leaf_index so proofs are
        # regenerable in exactly this order at audit time.
        leaves = [g.leaf() for g in chunk]
        root = merkle.root(leaves)
        root_hex = merkle.hx(root)
        try:
            batch = supa.insert_permission_batch(token, root_hex, len(chunk), source, scope)
            batch_id = batch.get("id")

            # 1 tx, flat gas — anchor the root. If a prior partial run already anchored
            # this exact root (crash after the tx, before caching proofs), DON'T re-anchor:
            # the contract reverts on a duplicate root. Resume by (re)caching proofs +
            # read-back instead — makes the whole pass idempotent/resumable.
            if chain_client.root_anchored(root) == 0:
                tx = chain_client.grant_batch(root, len(chunk))
                supa.set_batch_status(token, root_hex, "pending", tx_hash=tx)
            else:
                tx = batch.get("tx_hash") or "already-anchored"

            # Store the proof cache (rebuildable, but cached for the hot path).
            rows = []
            for idx, g in enumerate(chunk):
                pf = merkle.proof(leaves, idx)
                row = {
                    "batch_id": batch_id,
                    "merkle_root": root_hex, "file_id": g.file_id,
                    "grantee_id": g.grantee_id, "leaf": merkle.hx(leaves[idx]),
                    "leaf_index": idx, "proof": [merkle.hx(p) for p in pf],
                }
                # Only send the column for typed grants, so download-level shares
                # keep working during the deploy window before migration 0016.
                if g.grant_type and g.grant_type != "download":
                    row["grant_type"] = g.grant_type
                rows.append(row)
            supa.insert_batch_grants(token, rows)

            # READ-BACK GATE: confirm the root is anchored on-chain AND a sample of
            # proofs actually verify against it before we trust this batch.
            if chain_client.root_anchored(root) == 0:
                raise RuntimeError("root not anchored on read-back")
            sample = range(len(chunk)) if not readback_sample else \
                _sample_indices(len(chunk), readback_sample)
            for idx in sample:
                if not chain_client.verify_batch(leaves[idx], root, merkle.proof(leaves, idx)):
                    raise RuntimeError(f"read-back proof failed at leaf {idx}")

            supa.set_batch_status(token, root_hex, "live", anchored_at=_now_iso())
            res.batches += 1
            res.grants += len(chunk)
            res.tx_hashes.append(tx)
            res.roots.append(root_hex)
            _log.info("batch anchored root=%s size=%d tx=%s", root_hex[:12], len(chunk), tx)
        except Exception as exc:  # noqa: BLE001 — isolate the chunk, continue
            try:
                supa.set_batch_status(token, root_hex, "failed")
            except Exception:
                pass
            res.failed.append((root_hex, str(exc)))
            _log.warning("batch FAILED root=%s size=%d: %s", root_hex[:12], len(chunk), exc)
    return res


def _sample_indices(n: int, k: int) -> list[int]:
    """Deterministic spread of up to k indices across [0, n) — always includes the
    first and last (the odd-node edges most likely to expose a builder bug). No RNG
    (workflow determinism), just even spacing."""
    if k >= n:
        return list(range(n))
    if k <= 1:
        return [0]
    step = (n - 1) / (k - 1)
    return sorted({int(round(i * step)) for i in range(k)})
