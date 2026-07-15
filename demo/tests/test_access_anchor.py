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


# --- hourly per-org anchor (0018) --------------------------------------------

def _wire_period(monkeypatch, entries, existing=None):
    store = {"anchor": existing, "org_roots": None, "anchor_writes": []}

    def _rest(method, path, token, **kw):
        if path == "/access_log_anchor_periods" and method == "GET":
            return [store["anchor"]] if store["anchor"] else []
        if path == "/access_log_anchor_periods" and method == "POST":
            store["anchor"] = kw["json_body"]
            store["anchor_writes"].append(kw["json_body"])
            return None
        if path == "/access_log_org_roots" and method == "POST":
            store["org_roots"] = kw["json_body"]
            return None
        if path == "/access_log" and method == "GET":
            return entries
        return None
    monkeypatch.setattr(supa, "_rest", _rest)
    return store


def test_anchor_period_groups_by_org_one_tx(monkeypatch):
    entries = [
        {"id": "1", "ts": "2026-07-15T14:05:00Z", "org_id": "org-a", "entry_hash": "aa"*32},
        {"id": "2", "ts": "2026-07-15T14:10:00Z", "org_id": "org-b", "entry_hash": "bb"*32},
        {"id": "3", "ts": "2026-07-15T14:20:00Z", "org_id": "org-a", "entry_hash": "cc"*32},
        {"id": "4", "ts": "2026-07-15T14:30:00Z", "org_id": None, "entry_hash": "dd"*32},
    ]
    store = _wire_period(monkeypatch, entries)
    fc = _FakeChain()
    res = access_log.anchor_period("svc", "2026-07-15T14", chain_client=fc)
    assert res["status"] == "anchored" and res["count"] == 4 and res["orgs"] == 3
    assert len(fc.calls) == 1                              # ONE tx seals all orgs
    roots = {r["org_id"]: r for r in store["org_roots"]}
    assert set(roots) == {"org-a", "org-b", access_log.PLATFORM_ORG}
    assert roots["org-a"]["entry_count"] == 2
    # global root is reproducible from the stored org roots
    rebuilt = access_log.build_global_root(
        {o: (r["merkle_root"], r["entry_count"]) for o, r in roots.items()})
    assert store["anchor"]["merkle_root"] == rebuilt
    assert store["anchor"]["tx_hash"] == "0xanchortx"


def test_anchor_period_empty_writes_nothing(monkeypatch):
    """Mark, 2026-07-15: a silent hour writes NO rows and spends NO gas."""
    store = _wire_period(monkeypatch, [])
    fc = _FakeChain()
    res = access_log.anchor_period("svc", "2026-07-15T03", chain_client=fc)
    assert res["status"] == "empty-skipped"
    assert fc.calls == [] and store["org_roots"] is None and store["anchor_writes"] == []


def test_anchor_period_idempotent(monkeypatch):
    existing = {"period": "2026-07-15T14", "seq": 0, "merkle_root": "ee"*32,
                "entry_count": 7, "tx_hash": "0xprev"}
    _wire_period(monkeypatch, [{"id": "1", "ts": "2026-07-15T14:05:00Z",
                                "org_id": "org-a", "entry_hash": "aa"*32}], existing=existing)
    fc = _FakeChain()
    res = access_log.anchor_period("svc", "2026-07-15T14", chain_client=fc)
    assert res["status"] == "already-anchored" and res["tx"] == "0xprev"
    assert fc.calls == []


def test_org_leaf_binds_org_to_root():
    """Same root under two org ids must produce different leaves — the global
    tree commits to WHICH org a root belongs to, not just the root bytes."""
    root = "ab" * 32
    assert access_log.org_leaf("org-a", root) != access_log.org_leaf("org-b", root)


def test_silent_org_absent_from_roots():
    roots = access_log.build_org_roots(
        [{"id": "1", "ts": "t", "org_id": "org-a", "entry_hash": "aa"*32}])
    assert "org-b" not in roots and set(roots) == {"org-a"}
