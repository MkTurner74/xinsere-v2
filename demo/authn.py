"""Session authentication helpers shared by the app, admin and docs routes.

The interactive planes all authenticate the same way: a signed session cookie
holding Supabase tokens (see app.py module docstring). Platform-admin status is
decided by XINSERE_ADMIN_EMAILS — the bootstrap identity list; org-level roles
live in org_members and are managed from the admin console.
"""
from __future__ import annotations

import os
import time

from fastapi import HTTPException, Request

import supa

ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get(
    "XINSERE_ADMIN_EMAILS", "mark.turner@entertainmenttechnologists.com").split(",") if e.strip()}


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


def is_admin(profile: dict | None) -> bool:
    return bool(profile) and (profile.get("email") or "").lower() in ADMIN_EMAILS


def require_admin(request: Request) -> dict:
    """FastAPI dependency: a signed-in platform admin. Returns the session dict
    with the admin's profile attached."""
    s = session(request)
    prof = supa.get_profile(s["access_token"], s["user_id"]) or {}
    if not is_admin(prof):
        raise HTTPException(status_code=403, detail="Admin only")
    return {**s, "profile": prof}


def require_signed_in(request: Request) -> dict:
    """FastAPI dependency: any signed-in user (docs site gate)."""
    return session(request)
