"""Session authentication helpers shared by the app, admin and docs routes.

The interactive planes all authenticate the same way: a signed session cookie
holding Supabase tokens (see app.py module docstring).

Platform-admin (Super-Admin tier) status is decided by the durable
`platform_admins` registry (service-role-only table, migration 0009).
XINSERE_ADMIN_EMAILS is now only a BOOTSTRAP fallback for the very first admin
before the registry is seeded — safe because profiles.email became immutable to
the authenticated role in 0009, so it can no longer be self-set to an admin
address (security audit finding 1). Org-level roles (Tenant Admin / member) live
in org_members and are managed from the admin console.
"""
from __future__ import annotations

import os
import time

from fastapi import HTTPException, Request

import supa

ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get(
    "XINSERE_ADMIN_EMAILS",
    "mark.turner@entertainmenttechnologists.com,mark.turner@xinsere.com").split(",") if e.strip()}


def session(request: Request) -> dict:
    """Return the live Supabase session, refreshing the token if near expiry."""
    s = request.session.get("sb")
    if not s:
        raise HTTPException(status_code=401, detail="Not signed in")
    if s["expires_at"] - time.time() < 60:
        try:
            s = supa.session_from_grant(supa.refresh(s["refresh_token"]))
            request.session["sb"] = s
        except supa.SupabaseError:
            request.session.clear()
            raise HTTPException(status_code=401, detail="Session expired — sign in again")
    return s


def _email_bootstrap_admin(profile: dict | None) -> bool:
    """Bootstrap fallback ONLY: email in the env admin list. Safe now that
    profiles.email is immutable to the authenticated role (migration 0009)."""
    return bool(profile) and (profile.get("email") or "").lower() in ADMIN_EMAILS


def is_platform_admin(user_id: str, profile: dict | None) -> bool:
    """Authoritative platform-admin decision: durable registry first, env
    bootstrap fallback second."""
    if user_id and supa.is_platform_admin(user_id):
        return True
    return _email_bootstrap_admin(profile)


# Back-compat alias for callers that only render an "is this user an admin?" flag.
def is_admin(profile: dict | None, user_id: str | None = None) -> bool:
    if user_id and supa.is_platform_admin(user_id):
        return True
    return _email_bootstrap_admin(profile)


def require_admin(request: Request) -> dict:
    """FastAPI dependency: a signed-in platform admin. Returns the session dict
    with the admin's profile attached."""
    s = session(request)
    prof = supa.get_profile(s["access_token"], s["user_id"]) or {}
    if not is_platform_admin(s["user_id"], prof):
        raise HTTPException(status_code=403, detail="Admin only")
    return {**s, "profile": prof}


def require_signed_in(request: Request) -> dict:
    """FastAPI dependency: any signed-in user (docs site gate)."""
    return session(request)
