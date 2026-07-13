"""Account security API — the standard user-account controls for a secure service.

Self-serve for the signed-in user:
  * change password (re-auth with current password, clears any admin force-flag)
  * request a password-reset email (public)
  * enroll / verify / disable TOTP two-factor (via Supabase GoTrue MFA)
  * read own security status (drives the Security settings UI)

Admin-forced password change and the platform-admin (Super-Admin) registry live in
admin.py. Email verification is enforced at login (app.py).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Form, HTTPException, Request

import authn
import supa

_log = logging.getLogger("xinsere.account")
router = APIRouter(prefix="/api/account", include_in_schema=False)

MIN_PASSWORD_LEN = 8


def _svc() -> str:
    if not supa.SERVICE_ROLE_KEY:
        raise HTTPException(status_code=501, detail="Service role key not configured")
    return supa.SERVICE_ROLE_KEY


@router.get("/security-status")
def security_status(request: Request):
    """Everything the Security UI needs: forced-change flag, 2FA state, email
    verification. Fail-soft — never blocks the app if a sub-lookup hiccups."""
    s = authn.session(request)
    token, uid = s["access_token"], s["user_id"]
    sec = {}
    try:
        sec = supa.get_account_security(_svc(), uid)
    except Exception:
        pass
    email_verified, factors = True, []
    try:
        au = supa.get_auth_user(token)
        email_verified = bool(au.get("email_confirmed_at") or au.get("confirmed_at"))
    except Exception:
        pass
    try:
        factors = [{"id": f.get("id"), "type": f.get("factor_type"),
                    "status": f.get("status"), "name": f.get("friendly_name")}
                   for f in supa.mfa_list_factors(token)]
    except Exception:
        pass
    mfa_on = any(f.get("status") == "verified" for f in factors)
    return {"must_change_password": bool(sec.get("must_change_password")),
            "mfa_enabled": mfa_on, "email_verified": email_verified,
            "factors": factors}


@router.post("/change-password")
def change_password(request: Request, current_password: str = Form(...),
                    new_password: str = Form(...)):
    """Change the signed-in user's password. Re-authenticates with the current
    password first, then clears any admin-forced-change flag."""
    s = authn.session(request)
    token, uid = s["access_token"], s["user_id"]
    if len(new_password) < MIN_PASSWORD_LEN:
        raise HTTPException(status_code=400,
                            detail=f"New password must be at least {MIN_PASSWORD_LEN} characters")
    prof = supa.get_profile(token, uid) or {}
    email = (prof.get("email") or "").lower()
    # Re-auth: proves the current holder of the session knows the current password
    # (defends against a hijacked-but-idle session silently rotating the credential).
    try:
        supa.sign_in(email, current_password)
    except supa.SupabaseError:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    try:
        supa.update_password(token, new_password)
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail or "Could not change password")
    try:
        supa.set_account_security(_svc(), uid,
                                  {"must_change_password": False,
                                   "password_changed_at": supa._now_iso()})
    except Exception:
        pass  # the password DID change; the flag clear is best-effort
    return {"ok": True}


@router.post("/request-reset")
def request_reset(email: str = Form(...)):
    """Public: email a password-reset link. Always returns ok (never reveals whether
    the address exists). Requires SMTP configured in Supabase to actually send."""
    try:
        supa.request_password_reset(email)
    except supa.SupabaseError as exc:
        _log.warning("password reset request failed for %s: %s", email, exc)
    return {"ok": True, "message": "If that email has an account, a reset link is on its way."}


# --- two-factor (TOTP) ------------------------------------------------------

@router.post("/mfa/enroll")
def mfa_enroll(request: Request, name: str = Form("Authenticator")):
    """Begin TOTP enrollment. Returns the QR code (SVG) + secret to display; the
    factor is 'unverified' until the user confirms a code via /mfa/verify."""
    s = authn.session(request)
    try:
        res = supa.mfa_enroll(s["access_token"], name.strip() or "Authenticator")
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail or "Could not start 2FA setup")
    totp = res.get("totp") or {}
    return {"ok": True, "factor_id": res.get("id"),
            "qr_code": totp.get("qr_code"), "secret": totp.get("secret"),
            "uri": totp.get("uri")}


@router.post("/mfa/verify")
def mfa_verify(request: Request, factor_id: str = Form(...), code: str = Form(...),
               challenge_id: str = Form(None)):
    """Confirm a TOTP code. Used BOTH to finish enrollment and to step up an
    existing factor at login. On success the session is upgraded to AAL2 and the
    2FA mirror is set on. Creates the challenge itself if one wasn't supplied."""
    s = authn.session(request)
    token, uid = s["access_token"], s["user_id"]
    try:
        if not challenge_id:
            challenge_id = (supa.mfa_challenge(token, factor_id) or {}).get("id")
        grant = supa.mfa_verify(token, factor_id, challenge_id, code.strip())
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=401, detail=exc.detail or "Invalid or expired code")
    # GoTrue returns fresh AAL2 tokens — persist them so the session is now MFA-satisfied.
    if grant and grant.get("access_token"):
        request.session["sb"] = supa.session_from_grant(
            {**grant, "user": grant.get("user") or {"id": uid}})
    try:
        supa.set_account_security(_svc(), uid, {"mfa_enabled": True})
    except Exception:
        pass
    return {"ok": True}


@router.post("/mfa/challenge")
def mfa_challenge(request: Request, factor_id: str = Form(...)):
    """Create a login step-up challenge for an enrolled factor."""
    s = authn.session(request)
    try:
        ch = supa.mfa_challenge(s["access_token"], factor_id)
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail or "Could not start 2FA challenge")
    return {"ok": True, "challenge_id": (ch or {}).get("id")}


@router.post("/mfa/disable")
def mfa_disable(request: Request):
    """Turn off 2FA: unenroll every factor and clear the mirror."""
    s = authn.session(request)
    token, uid = s["access_token"], s["user_id"]
    removed = 0
    try:
        for f in supa.mfa_list_factors(token):
            try:
                supa.mfa_unenroll(token, f.get("id"))
                removed += 1
            except supa.SupabaseError:
                pass
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail or "Could not disable 2FA")
    try:
        supa.set_account_security(_svc(), uid, {"mfa_enabled": False})
    except Exception:
        pass
    return {"ok": True, "removed": removed}
