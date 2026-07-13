"""Regression tests for the platform-admin gate hardening (migration 0009 +
authn/app changes). Guards security audit finding 1 (CRITICAL admin takeover via
self-set profiles.email) and finding 5 (public signup disabled in code).

The DB-level protections (email-immutability trigger, unique index, service-role
RLS on platform_admins) live in SQL and are exercised against a real Supabase;
here we test the application decision logic that consumes them.
"""
import authn
import supa
from fastapi.testclient import TestClient

import app as app_module

client = TestClient(app_module.app)

ADMIN_UID = "uid-admin"
PLAIN_UID = "uid-plain"
BOOTSTRAP_EMAIL = next(iter(authn.ADMIN_EMAILS))  # an email in the env bootstrap list


def test_registry_admin_is_admin_even_without_env_email(monkeypatch):
    """A user in the durable registry is admin regardless of their email — the
    decision no longer hinges on a (formerly mutable) email string."""
    monkeypatch.setattr(supa, "is_platform_admin", lambda uid: uid == ADMIN_UID)
    prof = {"id": ADMIN_UID, "email": "someone@example.com"}
    assert authn.is_platform_admin(ADMIN_UID, prof) is True


def test_non_registry_non_bootstrap_is_not_admin(monkeypatch):
    """A normal user not in the registry and not in the bootstrap list is denied —
    they can no longer self-promote by editing their email (0009 makes email
    immutable to the authenticated role)."""
    monkeypatch.setattr(supa, "is_platform_admin", lambda uid: False)
    prof = {"id": PLAIN_UID, "email": "attacker@example.com"}
    assert authn.is_platform_admin(PLAIN_UID, prof) is False


def test_env_bootstrap_fallback_still_works(monkeypatch):
    """Before the registry is seeded, the env bootstrap list still grants the
    first admin — safe now because email is DB-immutable to users."""
    monkeypatch.setattr(supa, "is_platform_admin", lambda uid: False)
    prof = {"id": PLAIN_UID, "email": BOOTSTRAP_EMAIL}
    assert authn.is_platform_admin(PLAIN_UID, prof) is True


def test_registry_lookup_fails_closed(monkeypatch):
    """If the service-role lookup can't run (no key / error), is_platform_admin in
    supa returns False — the gate must not open on infra failure."""
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "")
    assert supa.is_platform_admin("anyone") is False


def test_public_signup_is_disabled():
    """Finding 5: /api/signup fails closed in code, not via a dashboard toggle."""
    r = client.post("/api/signup", data={"email": "x@y.com", "password": "pw", "name": "X"})
    assert r.status_code == 403
    body = r.json()
    assert "invite-only" in (body.get("error") or body.get("detail") or "").lower()


def test_supa_sign_up_helper_refuses():
    """The underlying helper also fails closed so it can't be silently re-wired."""
    try:
        supa.sign_up("x@y.com", "pw", "X")
    except supa.SupabaseError as exc:
        assert exc.status == 403
    else:  # pragma: no cover
        raise AssertionError("sign_up should have raised")
