"""Batch-grant resilience (Jeremy/Mark prod findings, 2026-07-21):

* permission_batches/batch_grants upserts must name their real unique keys —
  re-sharing the same (file, grantee) after the contract cutover produced the
  same Merkle root as a pre-cutover row and 409'd the share.
* The read-back gate must tolerate RPC read-after-write lag: a load-balanced
  public endpoint can serve rootAnchored=0 from a node one block behind the
  tx it just confirmed. Retried, not failed.
"""
import batch_grant
import merkle
import supa
from batch_grant import Grant


def test_insert_permission_batch_upserts_on_merkle_root(monkeypatch):
    seen = {}

    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        seen.update(path=path, params=params, prefer=prefer, body=json_body)
        return [json_body]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    supa.insert_permission_batch("svc", "0xabc", 3, "share", "node-1")
    assert seen["path"] == "/permission_batches"
    assert seen["params"] == {"on_conflict": "merkle_root"}
    assert "merge-duplicates" in seen["prefer"]
    assert seen["body"]["status"] == "pending"   # upsert resets a stale row


def test_insert_batch_grants_upserts_on_composite_key(monkeypatch):
    seen = {}
    monkeypatch.setattr(supa, "_rest",
                        lambda m, p, t, params=None, json_body=None, prefer=None:
                        seen.update(params=params) or None)
    supa.insert_batch_grants("svc", [{"file_id": "f", "grantee_id": "g",
                                      "merkle_root": "0xabc"}])
    assert seen["params"] == {"on_conflict": "file_id,grantee_id,merkle_root"}


class LaggyChain:
    """Anchors correctly, but the first `lag` post-anchor reads return 0 —
    models a load-balanced RPC serving a node behind the tx's block."""

    def __init__(self, lag=2):
        self.anchored = {}
        self.lag = lag
        self.reads_after_anchor = 0

    def grant_batch(self, root, size):
        self.anchored[root] = 1_000_000
        return "0xtx1"

    def grant_batch_windowed(self, root, size, nb, na):
        self.anchored[root] = 1_000_000
        return "0xtx1"

    def root_anchored(self, root):
        if root not in self.anchored:
            return 0
        self.reads_after_anchor += 1
        return 0 if self.reads_after_anchor <= self.lag else self.anchored[root]

    def verify_batch(self, leaf, root, proof):
        return root in self.anchored and merkle.verify_like_contract(leaf, root, proof)


class FakeSupa:
    def __init__(self):
        self.batches, self.grants = {}, []

    def insert_permission_batch(self, token, merkle_root, leaf_count, source, scope,
                                not_before=0, not_after=0):
        self.batches[merkle_root] = {"leaf_count": leaf_count, "status": "pending"}
        return self.batches[merkle_root]

    def set_batch_status(self, token, merkle_root, status, *, tx_hash=None, anchored_at=None):
        self.batches.setdefault(merkle_root, {})["status"] = status

    def insert_batch_grants(self, token, rows):
        self.grants.extend(rows)


def test_readback_rides_out_rpc_lag(monkeypatch):
    monkeypatch.setattr(batch_grant, "READBACK_DELAY_S", 0.001)
    ch, sp = LaggyChain(lag=2), FakeSupa()
    res = batch_grant.preserve([Grant("file-l", "user-l")], supa=sp, token="t",
                               source="share", scope="n", chain_client=ch)
    assert res.batches == 1 and res.failed == []
    assert sp.batches[res.roots[0]]["status"] == "live"


def test_readback_still_fails_closed_when_never_anchored(monkeypatch):
    monkeypatch.setattr(batch_grant, "READBACK_DELAY_S", 0.001)

    class NeverAnchors(LaggyChain):
        def grant_batch(self, root, size):
            return "0xtx1"   # tx "succeeds" but nothing lands on-chain

    ch, sp = NeverAnchors(), FakeSupa()
    res = batch_grant.preserve([Grant("file-x", "user-x")], supa=sp, token="t",
                               source="share", scope="n", chain_client=ch)
    assert res.batches == 0 and len(res.failed) == 1
    assert "not anchored" in res.failed[0][1]
    assert any(b.get("status") == "failed" for b in sp.batches.values())