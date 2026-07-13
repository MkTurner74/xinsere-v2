"""Tests for the daily access-log on-chain anchor (Finding 6)."""
import access_log
import supa


class _FakeChain:
    def __init__(self): self.calls = []
    def grant_batch(self, root, count):
        self.calls.append((root, count))
        return "0xanchortx"


def _wire(monkeypatch, entries, existing=None):
    store = {"anchor": existing}

    def _rest(method, path, token, **kw):
        if path == "/access_log_anchors" and method == "GET":
            return [store["anchor"]] if store["anchor"] else []
        if path == "/access_log_anchors" and method == "POST":
            store["anchor"] = kw["json_body"]
            return None
        if path == "/access_log" and method == "GET":
            return entries
        return None
    monkeypatch.setattr(supa, "_rest", _rest)
    return store


def test_anchor_day_anchors_non_empty(monkeypatch):
    entries = [{"id": "1", "ts": "2026-07-13T01:00:00Z", "entry_hash": "aa"*32},
               {"id": "2", "ts": "2026-07-13T02:00:00Z", "entry_hash": "bb"*32}]
    store = _wire(monkeypatch, entries)
    fc = _FakeChain()
    res = access_log.anchor_day("svc", "2026-07-13", chain_client=fc)
    assert res["status"] == "anchored" and res["count"] == 2 and res["tx"] == "0xanchortx"
    assert len(fc.calls) == 1
    assert store["anchor"]["tx_hash"] == "0xanchortx"


def test_anchor_day_empty_spends_no_gas(monkeypatch):
    _wire(monkeypatch, [])
    fc = _FakeChain()
    res = access_log.anchor_day("svc", "2026-07-13", chain_client=fc)
    assert res["status"] == "empty-no-anchor" and res["count"] == 0
    assert fc.calls == []                      # no on-chain tx for an empty day


def test_anchor_day_idempotent(monkeypatch):
    existing = {"day": "2026-07-13", "merkle_root": "cc"*32, "entry_count": 5, "tx_hash": "0xprev"}
    _wire(monkeypatch, [{"id": "1", "ts": "t", "entry_hash": "aa"*32}], existing=existing)
    fc = _FakeChain()
    res = access_log.anchor_day("svc", "2026-07-13", chain_client=fc)
    assert res["status"] == "already-anchored" and res["tx"] == "0xprev"
    assert fc.calls == []                      # never re-anchors
