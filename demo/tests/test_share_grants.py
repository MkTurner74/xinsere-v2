"""Unit tests for interactive share grant/revoke over the batch path (Finding 2).

Proves the denial-of-wallet fix: a folder share anchors ONE batch (not one tx per
file), the anchored root(s) are recorded under (node, grantee), and unshare revokes
exactly those roots. Chain + Supabase are faked — we test the orchestration logic.
"""
import batch_grant
import share_grants
import supa
from chain import CHAIN


def _fake_preserve_factory(recorder, roots=("0xroot1",)):
    def _preserve(grants, *, supa, token, source, scope, **kw):
        recorder["preserve_calls"].append(
            {"n": len(grants), "source": source, "scope": scope})
        res = batch_grant.BatchResult()
        res.roots = list(roots)
        res.tx_hashes = [f"0xtx_{r}" for r in roots]
        res.grants = len(grants)
        res.batches = len(roots)
        return res
    return _preserve


def _wire(monkeypatch, roots=("0xroot1",)):
    rec = {"preserve_calls": [], "inserted": [], "deleted": [], "revoked_roots": [],
           "status": [], "mapping": {}}
    monkeypatch.setattr(batch_grant, "preserve", _fake_preserve_factory(rec, roots))
    monkeypatch.setattr(supa, "insert_share_batch",
                        lambda tok, n, g, r: (rec["inserted"].append((n, g, r)),
                                              rec["mapping"].setdefault((n, g), []).append(r)))
    monkeypatch.setattr(supa, "delete_share_batch",
                        lambda tok, n, g, r: rec["deleted"].append((n, g, r)))
    monkeypatch.setattr(supa, "share_batch_roots",
                        lambda tok, n, g: list(rec["mapping"].get((n, g), [])))
    monkeypatch.setattr(supa, "set_batch_status",
                        lambda tok, r, s, **kw: rec["status"].append((r, s)))
    monkeypatch.setattr(CHAIN, "root_anchored", lambda root: 1)   # anchored
    monkeypatch.setattr(CHAIN, "revoke_batch_root",
                        lambda root: rec["revoked_roots"].append(root) or "0xrevtx")
    return rec


FILES = [{"file_id": "fileA"}, {"file_id": "fileB"}, {"file_id": "fileC"}]


def test_grant_share_anchors_one_batch_and_records_root(monkeypatch):
    rec = _wire(monkeypatch)
    res = share_grants.grant_share("svc", FILES, "grantee-1", "fld_x", "share")
    # ONE preserve call over all 3 files (not 3 separate grant txs) — the DoS fix.
    assert len(rec["preserve_calls"]) == 1
    assert rec["preserve_calls"][0]["n"] == 3
    assert rec["preserve_calls"][0]["scope"] == "fld_x"
    # The anchored root is recorded under (node, grantee) for later revocation.
    assert ("fld_x", "grantee-1", "0xroot1") in rec["inserted"]
    assert res.grants == 3


def test_grant_share_no_files_is_noop(monkeypatch):
    rec = _wire(monkeypatch)
    assert share_grants.grant_share("svc", [], "g", "fld_x", "share") is None
    assert rec["preserve_calls"] == []
    assert rec["inserted"] == []


def test_grant_share_raises_if_nothing_anchored(monkeypatch):
    rec = _wire(monkeypatch, roots=())            # preserve anchors no roots
    try:
        share_grants.grant_share("svc", FILES, "g", "fld_x", "share")
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError when no root anchored")


def test_revoke_share_revokes_recorded_roots(monkeypatch):
    rec = _wire(monkeypatch, roots=("0xa1", "0xb2"))
    share_grants.grant_share("svc", FILES, "g", "fld_x", "share")   # records r1, r2
    out = share_grants.revoke_share("svc", "fld_x", "g")
    assert out["revoked"] == 2 and out["errors"] == 0
    assert set(rec["revoked_roots"]) == {bytes.fromhex("a1"), bytes.fromhex("b2")}
    # mapping rows deleted so a re-unshare is idempotent
    assert ("fld_x", "g", "0xa1") in rec["deleted"]
    assert ("fld_x", "g", "0xb2") in rec["deleted"]


def test_revoke_share_fail_closed_keeps_mapping(monkeypatch):
    rec = _wire(monkeypatch, roots=("0xa1",))
    share_grants.grant_share("svc", FILES, "g", "fld_x", "share")

    def _boom(root):
        raise RuntimeError("amoy down")
    monkeypatch.setattr(CHAIN, "revoke_batch_root", _boom)
    out = share_grants.revoke_share("svc", "fld_x", "g")
    assert out["errors"] == 1 and out["revoked"] == 0
    assert rec["deleted"] == []          # mapping kept for retry (fail-closed)


def test_revoke_share_skips_already_revoked_root(monkeypatch):
    rec = _wire(monkeypatch, roots=("0xa1",))
    share_grants.grant_share("svc", FILES, "g", "fld_x", "share")
    monkeypatch.setattr(CHAIN, "root_anchored", lambda root: 0)   # already revoked
    out = share_grants.revoke_share("svc", "fld_x", "g")
    # no revoke tx sent, but the (stale) mapping is still cleaned up, no error
    assert out["errors"] == 0 and out["revoked"] == 1
    assert rec["revoked_roots"] == []
    assert ("fld_x", "g", "0xa1") in rec["deleted"]


def test_reanchor_share_revokes_then_regrants(monkeypatch):
    rec = _wire(monkeypatch, roots=("0xa1",))
    share_grants.grant_share("svc", FILES, "g", "fld_x", "share")
    out = share_grants.reanchor_share("svc", "fld_x", "g", FILES[:2], "move")
    assert out["revoked"] == 1
    assert out["regranted"] == 2          # re-preserved the 2 current files
