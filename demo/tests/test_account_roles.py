"""Tests for the account-security + roles system: change password (with re-auth),
forced-change flag, 2FA endpoints, Super-Admin registry management, and the login
security posture. GoTrue + Supabase are faked."""
import account
import admin as admin_mod
import app as app_module
import authn
import orgs
import pytest
import supa
from fastapi.testclient import TestClient

client = TestClient(app_module.app)

SESS = {"access_token": "tok", "user_id": "u-1"}


@pytest.fixture
def as_admin():
    """Override the require_admin dependency (captured at route definition, so a
    plain monkeypatch wouldn't take)."""
    app_module.app.dependency_overrides[authn.require_admin] = \
        lambda: {**SESS, "profile": {"email": "mark@xinsere.com"}}
    yield
    app_module.app.dependency_overrides.pop(authn.require_admin, None)


def _auth(monkeypatch, user_id="u-1"):
    monkeypatch.setattr(authn, "session", lambda req: {**SESS, "user_id": user_id})
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "svc")


# --- change password --------------------------------------------------------

def test_change_password_rejects_short(monkeypatch):
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "get_profile", lambda t, u: {"id": u, "email": "a@b.com"})
    r = client.post("/api/account/change-password",
                    data={"current_password": "oldpass1", "new_password": "short"})
    assert r.status_code == 400


def test_change_password_wrong_current(monkeypatch):
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "get_profile", lambda t, u: {"id": u, "email": "a@b.com"})
    def _bad_signin(email, pw): raise supa.SupabaseError(400, "bad")
    monkeypatch.setattr(supa, "sign_in", _bad_signin)
    r = client.post("/api/account/change-password",
                    data={"current_password": "wrong", "new_password": "newlongpassword"})
    assert r.status_code == 401


def test_change_password_success_clears_flag(monkeypatch):
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "get_profile", lambda t, u: {"id": u, "email": "a@b.com"})
    monkeypatch.setattr(supa, "sign_in", lambda e, p: {"access_token": "x"})
    monkeypatch.setattr(supa, "update_password", lambda tok, pw: {"id": "u-1"})
    cleared = {}
    monkeypatch.setattr(supa, "set_account_security",
                        lambda tok, uid, fields: cleared.update(fields))
    r = client.post("/api/account/change-password",
                    data={"current_password": "oldpass1", "new_password": "newlongpassword"})
    assert r.status_code == 200
    assert cleared.get("must_change_password") is False


# --- 2FA --------------------------------------------------------------------

def test_mfa_enroll_returns_qr(monkeypatch):
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "mfa_list_factors", lambda tok: [])   # nothing to clean up
    monkeypatch.setattr(supa, "mfa_enroll",
                        lambda tok, name: {"id": "f1", "totp": {"qr_code": "<svg/>", "secret": "ABC", "uri": "otpauth://"}})
    r = client.post("/api/account/mfa/enroll", data={"name": "Phone"})
    assert r.status_code == 200
    b = r.json()
    # We render our own QR from the otpauth URI (segno) — a real SVG, not GoTrue's.
    assert b["factor_id"] == "f1" and b["secret"] == "ABC"
    assert "svg" in (b["qr_code"] or "").lower()


def test_make_qr_svg_generates_scannable_svg():
    svg = account._make_qr_svg("otpauth://totp/Xinsere:m@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Xinsere")
    assert svg and "<svg" in svg and "<path" in svg     # real QR markup
    assert account._make_qr_svg("") is None             # nothing to encode


def test_mfa_enroll_clears_stale_unverified_factor(monkeypatch):
    """A prior abandoned enrollment leaves an unverified factor; enroll must remove
    it first so the retry isn't blocked by a name collision."""
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "mfa_list_factors",
                        lambda tok: [{"id": "stale", "status": "unverified"},
                                     {"id": "good", "status": "verified"}])
    removed = []
    monkeypatch.setattr(supa, "mfa_unenroll", lambda tok, fid: removed.append(fid))
    monkeypatch.setattr(supa, "mfa_enroll",
                        lambda tok, name: {"id": "f2", "totp": {"qr_code": "<svg/>", "secret": "X"}})
    r = client.post("/api/account/mfa/enroll", data={"name": "Authenticator"})
    assert r.status_code == 200
    assert removed == ["stale"]        # unverified cleared, verified left alone


def test_mfa_verify_sets_enabled(monkeypatch):
    _auth(monkeypatch)
    monkeypatch.setattr(supa, "mfa_challenge", lambda tok, fid: {"id": "c1"})
    monkeypatch.setattr(supa, "mfa_verify",
                        lambda tok, fid, cid, code: {"access_token": "a2", "refresh_token": "r2", "expires_in": 3600, "user": {"id": "u-1"}})
    state = {}
    monkeypatch.setattr(supa, "set_account_security", lambda tok, uid, f: state.update(f))
    r = client.post("/api/account/mfa/verify", data={"factor_id": "f1", "code": "123456"})
    assert r.status_code == 200 and state.get("mfa_enabled") is True


# --- Super-Admin registry (admin console) -----------------------------------

def test_add_super_admin_requires_existing_account(as_admin, monkeypatch):
    monkeypatch.setattr(orgs, "get_profile_by_email", lambda e: None)
    r = client.post("/api/admin/platform-admins", data={"email": "nobody@x.com"})
    assert r.status_code == 404


def test_add_super_admin_promotes_existing(as_admin, monkeypatch):
    monkeypatch.setattr(orgs, "get_profile_by_email", lambda e: {"id": "u-9", "name": "Jo"})
    added = {}
    monkeypatch.setattr(supa, "add_platform_admin", lambda tok, uid, by: added.update({"uid": uid}))
    r = client.post("/api/admin/platform-admins", data={"email": "jo@xinsere.com"})
    assert r.status_code == 200 and added["uid"] == "u-9"


def test_cannot_remove_last_super_admin(as_admin, monkeypatch):
    monkeypatch.setattr(supa, "list_platform_admins", lambda tok: [{"user_id": "u-1"}])
    r = client.post("/api/admin/platform-admins/u-1/remove")
    assert r.status_code == 400


def test_force_password_change_sets_flag(as_admin, monkeypatch):
    state = {}
    monkeypatch.setattr(supa, "set_account_security", lambda tok, uid, f: state.update({uid: f}))
    r = client.post("/api/admin/users/u-7/force-password-change")
    assert r.status_code == 200 and state["u-7"]["must_change_password"] is True
