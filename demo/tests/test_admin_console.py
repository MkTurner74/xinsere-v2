"""Tests for the admin console's read-only endpoints (audit log + platform
config) added with the console IA redesign. Both sit behind the same
require_admin gate as every other /api/admin route; the config endpoint must
never leak a secret value."""
import authn
import supa
from fastapi.testclient import TestClient

import admin as admin_module
import app as app_module

client = TestClient(app_module.app)

FAKE_ADMIN = {"user_id": "uid-admin", "profile": {"email": "admin@xinsere.com", "name": "Admin"}}


def _as_admin():
    app_module.app.dependency_overrides[authn.require_admin] = lambda: FAKE_ADMIN


def _reset():
    app_module.app.dependency_overrides.pop(authn.require_admin, None)


# --- gate -----------------------------------------------------------------------

def test_audit_log_requires_admin():
    r = client.get("/api/admin/audit-log")
    assert r.status_code in (401, 403)


def test_config_requires_admin():
    r = client.get("/api/admin/config")
    assert r.status_code in (401, 403)


# --- audit log ------------------------------------------------------------------

def test_audit_log_resolves_actors_and_anchors(monkeypatch):
    rows = [{"ts": "2026-07-14T10:00:00Z", "day": "2026-07-14", "org_id": "org-1",
             "actor_id": "uid-1", "actor_type": "user", "key_id": None,
             "action": "file.read", "file_id": "f-1", "bytes": 42, "entry_hash": "aa"}]

    def fake_rest(method, path, token, params=None, **kw):
        if path == "/access_log":
            return rows
        if path == "/profiles":
            assert "uid-1" in params["id"]
            return [{"id": "uid-1", "email": "user@acme.com", "name": "User"}]
        if path == "/access_log_anchors":
            return [{"day": "2026-07-14", "tx_hash": "0xabc", "anchored_at": "2026-07-15T00:01:00Z"}]
        if path == "/access_log_anchor_periods":   # hourly seals (0018)
            return [{"period": "2026-07-14T10", "tx_hash": "0xhourly",
                     "anchored_at": "2026-07-14T11:05:00Z"}]
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(supa, "_rest", fake_rest)
    monkeypatch.setattr(admin_module.orgs, "list_orgs", lambda: [{"id": "org-1", "name": "Acme"}])
    _as_admin()
    try:
        r = client.get("/api/admin/audit-log")
        assert r.status_code == 200
        body = r.json()
        assert body["rows"][0]["actor_email"] == "user@acme.com"
        assert body["rows"][0]["org_name"] == "Acme"
        assert body["anchors"]["2026-07-14"]["tx_hash"] == "0xabc"
        # hourly seal exposed alongside the daily one (UI prefers the hour key)
        assert body["anchors"]["2026-07-14T10"]["tx_hash"] == "0xhourly"
    finally:
        _reset()


def test_audit_log_actor_filter_and_empty_on_supabase_error(monkeypatch):
    def fake_rest(method, path, token, params=None, **kw):
        raise supa.SupabaseError(500, "down")

    monkeypatch.setattr(supa, "_rest", fake_rest)
    monkeypatch.setattr(admin_module.orgs, "list_orgs", lambda: [])
    _as_admin()
    try:
        r = client.get("/api/admin/audit-log", params={"actor": "nobody"})
        assert r.status_code == 200
        assert r.json()["rows"] == []
    finally:
        _reset()


def test_audit_log_limit_is_clamped(monkeypatch):
    seen = {}

    def fake_rest(method, path, token, params=None, **kw):
        if path == "/access_log":
            seen["limit"] = params["limit"]
        return []

    monkeypatch.setattr(supa, "_rest", fake_rest)
    monkeypatch.setattr(admin_module.orgs, "list_orgs", lambda: [])
    _as_admin()
    try:
        client.get("/api/admin/audit-log", params={"limit": 99999})
        assert seen["limit"] == "500"
    finally:
        _reset()


# --- platform config --------------------------------------------------------------

def test_config_reports_flags_without_leaking_secrets(monkeypatch):
    monkeypatch.setenv("XINSERE_EMAIL_FROM", "security@xinsere.com")
    monkeypatch.delenv("XINSERE_RESEND_API_KEY", raising=False)
    monkeypatch.setenv("XINSERE_REQUIRE_EMAIL_VERIFIED", "true")
    monkeypatch.setenv("XINSERE_CONTRACT_ADDRESS", "0xec2aFB350000000000000000000000000000dead")
    monkeypatch.setenv("XINSERE_RPC_URL", "https://rpc.example.com/supersecrettoken")
    _as_admin()
    try:
        r = client.get("/api/admin/config")
        assert r.status_code == 200
        body = r.json()
        assert body["email"]["transport"] == "AWS SES"
        assert body["email"]["sender"] == "security@xinsere.com"
        assert body["security"]["require_email_verified"] is True
        assert body["blockchain"]["rpc_configured"] is True
        # never the value itself — only presence
        assert "supersecrettoken" not in r.text
    finally:
        _reset()
