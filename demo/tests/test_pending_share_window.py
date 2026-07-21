"""Pending-invite validity windows (0021) — the perpetual-shares gap, closed.

Before 0021 an external-email invite lost its window: pending_shares had no
window columns, so first-login materialization granted forever no matter what
the owner set in the dialog. These tests prove:

  * insert_pending_share stores the window, and degrades (strip-and-retry, once)
    to a windowless insert if 0021 hasn't been applied — deploy-order-safe;
  * pending_shares_for_email walks the select fallbacks and defaults the window;
  * _reconcile_pending threads the stub's window into grant_share + insert_share;
  * an invite whose window CLOSED before the invitee joined is dropped without
    any grant (no gas, nothing on-chain that could never verify);
  * a windowless stub still materializes perpetual (pre-0021 behavior intact).
"""
import time
from types import SimpleNamespace

import pytest

import supa


@pytest.fixture(autouse=True)
def _reset_pending_flag():
    supa._PENDING_WINDOW_COLUMNS = True
    supa._SHARE_WINDOW_COLUMNS = True
    yield
    supa._PENDING_WINDOW_COLUMNS = True
    supa._SHARE_WINDOW_COLUMNS = True


# --- supa.shares_for_node (owner UI reads per-person windows) ----------------

def test_shares_for_node_selects_window(monkeypatch):
    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        assert "not_before" in params["select"]
        return [{"grantee": "u1", "tx": "0x1", "share_type": "view",
                 "not_before": 5, "not_after": 9}]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    rows = supa.shares_for_node("t", "n1")
    assert rows[0]["not_before"] == 5 and rows[0]["not_after"] == 9


def test_shares_for_node_pre_0020_falls_back(monkeypatch):
    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        if "not_before" in params["select"]:
            raise supa.SupabaseError(400, "column does not exist")
        return [{"grantee": "u1", "tx": "0x1", "share_type": "download"}]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    rows = supa.shares_for_node("t", "n1")
    assert rows[0]["grantee"] == "u1" and "not_before" not in rows[0]


# --- supa.insert_pending_share ----------------------------------------------

def test_insert_pending_share_sends_window(monkeypatch):
    seen = {}

    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        seen.update(method=method, path=path, body=json_body, params=params)
        return [json_body]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    supa.insert_pending_share("svc", "node-1", "New@Ex.com", "owner-1",
                              "download", not_before=100, not_after=200)
    assert seen["path"] == "/pending_shares"
    assert seen["body"]["email"] == "new@ex.com"
    assert seen["body"]["not_before"] == 100 and seen["body"]["not_after"] == 200
    # Without on_conflict the merge-duplicates upsert only merges on the PK, so a
    # re-invite 409'd on the (node_id, email) unique constraint (2026-07-21).
    assert seen["params"] == {"on_conflict": "node_id,email"}


def test_insert_pending_share_windowless_omits_columns(monkeypatch):
    seen = {}
    monkeypatch.setattr(supa, "_rest",
                        lambda m, p, t, params=None, json_body=None, prefer=None:
                        seen.update(body=json_body) or [json_body])
    supa.insert_pending_share("svc", "node-1", "a@b.c", "owner-1")
    assert "not_before" not in seen["body"] and "not_after" not in seen["body"]


def test_insert_pending_share_pre_0021_strips_and_retries(monkeypatch):
    calls = []

    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        calls.append(json_body)
        if "not_before" in json_body:
            raise supa.SupabaseError(400, "column does not exist")
        return [json_body]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    out = supa.insert_pending_share("svc", "node-1", "a@b.c", "owner-1",
                                    "download", not_after=999)
    assert len(calls) == 2 and "not_after" not in calls[1]
    assert out["email"] == "a@b.c"
    # Flag flipped: the next windowed insert goes straight to windowless (one call).
    calls.clear()
    supa.insert_pending_share("svc", "node-2", "a@b.c", "owner-1",
                              "download", not_after=999)
    assert len(calls) == 1 and "not_after" not in calls[0]


def test_insert_pending_share_409_is_not_treated_as_missing_column(monkeypatch):
    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        raise supa.SupabaseError(409, "duplicate key")

    monkeypatch.setattr(supa, "_rest", fake_rest)
    with pytest.raises(supa.SupabaseError):
        supa.insert_pending_share("svc", "node-1", "a@b.c", "owner-1",
                                  "download", not_after=999)
    assert supa._PENDING_WINDOW_COLUMNS is True   # flag must not flip on a real conflict


# --- supa.pending_shares_for_email ------------------------------------------

def test_pending_shares_for_email_selects_window(monkeypatch):
    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        assert "not_before" in params["select"]
        return [{"id": "p1", "node_id": "n1", "invited_by": "o1",
                 "share_type": "view", "not_before": 5, "not_after": 9}]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    rows = supa.pending_shares_for_email("svc", "A@B.C")
    assert rows[0]["not_before"] == 5 and rows[0]["not_after"] == 9


def test_pending_shares_for_email_pre_0021_defaults_window(monkeypatch):
    def fake_rest(method, path, token, params=None, json_body=None, prefer=None):
        if "not_before" in params["select"]:
            raise supa.SupabaseError(400, "column does not exist")
        return [{"id": "p1", "node_id": "n1", "invited_by": "o1", "share_type": "view"}]

    monkeypatch.setattr(supa, "_rest", fake_rest)
    rows = supa.pending_shares_for_email("svc", "a@b.c")
    assert rows[0]["not_before"] == 0 and rows[0]["not_after"] == 0
    assert rows[0]["share_type"] == "view"


# --- app._reconcile_pending ---------------------------------------------------

class ReconcileHarness:
    """Fakes the supa + share_grants surface _reconcile_pending touches."""

    def __init__(self, monkeypatch, pending):
        import app
        self.granted, self.shares, self.deleted = [], [], []
        monkeypatch.setattr(app.supa, "SERVICE_ROLE_KEY", "svc")
        monkeypatch.setattr(app.supa, "pending_shares_for_email",
                            lambda t, e: list(pending))
        monkeypatch.setattr(app.supa, "files_under",
                            lambda t, n: [{"id": "f1", "sha256": "ab" * 32}])
        monkeypatch.setattr(app.supa, "insert_share",
                            lambda t, n, g, tx, st, not_before=0, not_after=0:
                            self.shares.append((n, g, st, not_before, not_after)))
        monkeypatch.setattr(app.supa, "delete_pending_share",
                            lambda t, pid: self.deleted.append(pid))
        monkeypatch.setattr(
            app.share_grants, "grant_share",
            lambda svc, files, grantee, node, source, stype, not_before=0, not_after=0:
            self.granted.append((node, grantee, stype, not_before, not_after))
            or SimpleNamespace(tx_hashes=["0xabc"]))
        self.app = app


def test_reconcile_threads_window_through(monkeypatch):
    na = int(time.time()) + 3600
    h = ReconcileHarness(monkeypatch, [
        {"id": "p1", "node_id": "n1", "share_type": "download",
         "not_before": 42, "not_after": na}])
    out = h.app._reconcile_pending("user-9", "a@b.c")
    assert out == {"materialized": 1, "expired": 0}
    assert h.granted == [("n1", "user-9", "download", 42, na)]
    assert h.shares == [("n1", "user-9", "download", 42, na)]
    assert h.deleted == ["p1"]


def test_reconcile_drops_already_expired_invite_without_granting(monkeypatch):
    h = ReconcileHarness(monkeypatch, [
        {"id": "p1", "node_id": "n1", "share_type": "download",
         "not_before": 0, "not_after": int(time.time()) - 5}])
    out = h.app._reconcile_pending("user-9", "a@b.c")
    assert out == {"materialized": 0, "expired": 1}
    assert h.granted == [] and h.shares == []
    assert h.deleted == ["p1"]          # stub cleaned up, no gas spent


def test_reconcile_windowless_stub_stays_perpetual(monkeypatch):
    h = ReconcileHarness(monkeypatch, [
        {"id": "p2", "node_id": "n2", "share_type": "view"}])
    out = h.app._reconcile_pending("user-9", "a@b.c")
    assert out == {"materialized": 1, "expired": 0}
    assert h.granted == [("n2", "user-9", "view", 0, 0)]
    assert h.shares == [("n2", "user-9", "view", 0, 0)]


def test_reconcile_future_start_still_materializes(monkeypatch):
    nb = int(time.time()) + 3600
    h = ReconcileHarness(monkeypatch, [
        {"id": "p3", "node_id": "n3", "share_type": "download",
         "not_before": nb, "not_after": 0}])
    out = h.app._reconcile_pending("user-9", "a@b.c")
    assert out == {"materialized": 1, "expired": 0}
    assert h.granted == [("n3", "user-9", "download", nb, 0)]
