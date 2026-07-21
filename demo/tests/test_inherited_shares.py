"""Inherited-share display (Jeremy's find, 2026-07-21): a folder share is ONE row
on the folder, so files inside showed no sign of being shared. node_view now merges
ancestor-chain share rows into children's shared_with, marked inherited + via."""
import app


PMAP = {"cc33": {"id": "cc33", "name": "Owner"},
        "aa11": {"id": "aa11", "name": "Grantee One"},
        "bb22": {"id": "bb22", "name": "Grantee Two"}}
NODE = {"id": "f1", "type": "file", "name": "x.jpg", "parent": "fold", "owner": "cc33"}


def test_node_view_merges_inherited_and_direct_wins(monkeypatch):
    monkeypatch.setattr(app.supa, "shares_for_node",
                        lambda t, n: [{"grantee": "aa11", "tx": "0xd", "share_type": "co-owner"}])
    inherited = [
        {"node_id": "fold", "grantee": "aa11", "tx": "0xa", "share_type": "view", "via": "Contrast project"},
        {"node_id": "fold", "grantee": "bb22", "tx": "0xb", "share_type": "download",
         "not_after": 123, "via": "Contrast project"},
    ]
    v = app.node_view(NODE, "cc33", "t", PMAP, inherited=inherited)
    sw = {e["id"]: e for e in v["shared_with"]}
    assert set(sw) == {"aa11", "bb22"}
    # Direct share beats the inherited row for the same grantee (level can be raised).
    assert sw["aa11"]["share_type"] == "co-owner" and "inherited" not in sw["aa11"]
    assert sw["bb22"]["inherited"] is True
    assert sw["bb22"]["via"] == "Contrast project" and sw["bb22"]["not_after"] == 123


def test_node_view_skips_inherited_rows_on_the_node_itself(monkeypatch):
    monkeypatch.setattr(app.supa, "shares_for_node", lambda t, n: [])
    v = app.node_view(NODE, "cc33", "t", PMAP, inherited=[
        {"node_id": "f1", "grantee": "bb22", "tx": "0xc", "share_type": "download"}])
    assert v["shared_with"] == []   # its own rows come from shares_for_node, not here


def test_node_view_no_shared_with_for_non_owner(monkeypatch):
    monkeypatch.setattr(app.supa, "shares_for_node",
                        lambda t, n: (_ for _ in ()).throw(AssertionError("must not query")))
    v = app.node_view(NODE, "aa11", "t", PMAP, inherited=[
        {"node_id": "fold", "grantee": "bb22", "tx": "0xb", "share_type": "download"}])
    assert "shared_with" not in v
