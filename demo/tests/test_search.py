"""Global search — the injection-relevant bits. The query lands in a PostgREST
ilike filter, so wildcard and filter metacharacters must never survive, and the
endpoint must sit behind the session gate (RLS scoping depends on the user token)."""
import supa
from fastapi.testclient import TestClient

import app as app_module

client = TestClient(app_module.app)


def test_search_requires_session():
    assert client.get("/api/search", params={"q": "founders"}).status_code == 401


def test_search_query_is_literalized(monkeypatch):
    seen = {}

    def fake_rest(method, path, token, params=None, **kw):
        seen.update(params)
        return []

    monkeypatch.setattr(supa, "_rest", fake_rest)
    supa.search_nodes("tok", 'foo*%(),\\bar', limit=10)
    assert seen["name"] == "ilike.*foobar*"     # metacharacters stripped, term intact
    assert seen["limit"] == "10"


def test_search_empty_query_short_circuits(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not hit PostgREST for an empty query")
    monkeypatch.setattr(supa, "_rest", boom)
    assert supa.search_nodes("tok", "***") == []
    assert supa.search_nodes("tok", "  ") == []
