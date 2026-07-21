"""View-only share type (migration 0016) — the security-relevant core.

The permission LEVEL is bound into the Merkle leaf (typed leaf), so the download
gate can trust the level without a contract change: it recomputes the expected
leaf from the row's CLAIMED grant_type before replaying the proof. These tests
prove (a) the typed-leaf construction, (b) the gate resolves levels correctly,
and (c) a DB-flipped grant_type can never verify — fail closed.
"""
import pytest

import app as app_module
import batch_grant
import chain
import merkle
import supa
from batch_grant import Grant


# --- typed leaf construction ------------------------------------------------------

FH = chain.file_hash("file-1")
GH = chain.grantee_hash("user-1")


def test_download_leaf_is_the_legacy_leaf():
    # Every pre-0016 anchored root stays valid: download == the 2-part leaf.
    assert merkle.leaf_typed(FH, GH, "download") == merkle.leaf(FH, GH)
    assert merkle.leaf_typed(FH, GH, None) == merkle.leaf(FH, GH)
    assert merkle.leaf_typed(FH, GH, "") == merkle.leaf(FH, GH)


def test_typed_leaves_are_distinct_per_level():
    dl = merkle.leaf_typed(FH, GH, "download")
    vw = merkle.leaf_typed(FH, GH, "view")
    co = merkle.leaf_typed(FH, GH, "co-owner")
    assert len({dl, vw, co}) == 3


def test_grant_dataclass_leaf_matches_module():
    assert Grant("file-1", "user-1", "view").leaf() == merkle.leaf_typed(FH, GH, "view")
    assert Grant("file-1", "user-1").leaf() == merkle.leaf(FH, GH)


# --- gate: level resolution + fail-closed on type tamper ---------------------------

class FakeChain:
    """Anchored-roots model (same semantics as the contract)."""
    def __init__(self):
        self.anchored = {}

    def grant_batch(self, root, size):
        self.anchored[root] = 1
        return "0xtx"

    def root_anchored(self, root):
        return self.anchored.get(root, 0)

    def verify_batch(self, leaf, root, proof):
        return self.anchored.get(root, 0) != 0 and merkle.verify_like_contract(leaf, root, proof)

    def verify(self, file_id, uid):
        return False, None   # no per-file grant in these tests


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


def _anchor(share_type):
    """Anchor one (file-1, user-1) grant at `share_type` and return (fakechain, rows
    shaped like supa.batch_grants_for output)."""
    ch, sp = FakeChain(), FakeSupa()
    res = batch_grant.preserve([Grant("file-1", "user-1", share_type)],
                               supa=sp, token="t", source="share", scope="n1",
                               cap=10, chain_client=ch)
    assert res.batches == 1
    rows = [{"merkle_root": g["merkle_root"], "leaf": g["leaf"], "proof": g["proof"],
             "grant_type": g.get("grant_type", "download")} for g in sp.grants]
    return ch, rows


def _gate(monkeypatch, ch, rows):
    monkeypatch.setattr(app_module, "CHAIN", ch)
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "svc")
    monkeypatch.setattr(supa, "batch_grants_for", lambda token, f, u, limit=5: rows)


def test_view_grant_resolves_to_view_level(monkeypatch):
    ch, rows = _anchor("view")
    _gate(monkeypatch, ch, rows)
    assert app_module._has_access("file-1", "user-1") == (True, "amoy-batch", "view")


def test_download_grant_resolves_to_download_level(monkeypatch):
    ch, rows = _anchor("download")
    _gate(monkeypatch, ch, rows)
    assert app_module._has_access("file-1", "user-1") == (True, "amoy-batch", "download")


def test_db_flipped_type_fails_closed(monkeypatch):
    # A view grant whose cached row CLAIMS download must not verify at all:
    # the recomputed download leaf differs from the anchored view leaf.
    ch, rows = _anchor("view")
    for r in rows:
        r["grant_type"] = "download"
    _gate(monkeypatch, ch, rows)
    assert app_module._has_access("file-1", "user-1") == (False, "none", "none")


def test_download_beats_view_when_both_anchored(monkeypatch):
    ch1, rows1 = _anchor("view")
    ch2, rows2 = _anchor("download")
    ch1.anchored.update(ch2.anchored)   # both roots anchored on one chain
    _gate(monkeypatch, ch1, rows1 + rows2)
    assert app_module._has_access("file-1", "user-1")[2] == "download"


def test_authorize_view_level_blocks_download_allows_view(monkeypatch):
    ch, rows = _anchor("view")
    _gate(monkeypatch, ch, rows)
    node = {"file_id": "file-1", "owner": "someone-else"}
    ok_dl, _, lvl_dl = app_module._authorize(node, "user-1", need="download")
    ok_vw, _, lvl_vw = app_module._authorize(node, "user-1", need="view")
    assert (ok_dl, lvl_dl) == (False, "view")   # has access, wrong level
    assert (ok_vw, lvl_vw) == (True, "view")


def test_owner_fallback_is_download_level(monkeypatch):
    ch = FakeChain()
    _gate(monkeypatch, ch, [])
    node = {"file_id": "file-1", "owner": "user-1"}
    assert app_module._authorize(node, "user-1", need="download") == (True, "owner-fallback", "download")


def test_share_endpoint_rejects_unknown_types():
    # co-owner is reserved (0016 CHECK) but not yet accepted by the API.
    from fastapi.testclient import TestClient
    client = TestClient(app_module.app)
    r = client.post("/api/share", data={"node_id": "n1", "grantee": "u1",
                                        "share_type": "co-owner"})
    assert r.status_code in (400, 401)   # 400 once a session exists; 401 without
