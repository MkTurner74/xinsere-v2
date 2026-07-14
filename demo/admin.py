"""Admin console API — platform-admin only (session + XINSERE_ADMIN_EMAILS).

Backs demo/frontend/admin.html. All data access goes through orgs.py on the
service-role plane AFTER the admin gate; none of these routes appear in the
public API docs (include_in_schema=False on the router).
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException

import authn
import orgs
import supa

router = APIRouter(prefix="/api/admin", include_in_schema=False)


@router.get("/whoami")
def whoami(s: dict = Depends(authn.require_admin)):
    return {"ok": True, "admin": True,
            "email": s["profile"].get("email"), "name": s["profile"].get("name")}


# --- imports (migration dashboard) ------------------------------------------

@router.get("/imports")
def list_imports(s: dict = Depends(authn.require_admin)):
    """Migration runs + the on-chain permission batches, for the import dashboard.
    Reads on the service-role plane after the admin gate. Empty (not an error) if the
    telemetry tables (migrations 0007/0008) aren't applied yet."""
    key = supa.SERVICE_ROLE_KEY
    try:
        runs = supa.list_migration_runs(key)
    except supa.SupabaseError:
        runs = []
    try:
        batches = supa.list_permission_batches(key)
    except supa.SupabaseError:
        batches = []
    live = sum(1 for b in batches if b.get("status") == "live")
    return {"runs": runs, "batches": batches,
            "batch_summary": {"total": len(batches), "live": live}}


@router.get("/imports/{run_id}")
def import_detail(run_id: str, s: dict = Depends(authn.require_admin)):
    run = supa.get_migration_run(supa.SERVICE_ROLE_KEY, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"run": run}


# --- organizations -----------------------------------------------------------

@router.get("/orgs")
def list_orgs(s: dict = Depends(authn.require_admin)):
    out = []
    for o in orgs.list_orgs():
        members = orgs.org_members(o["id"])
        keys = orgs.org_keys(o["id"])
        out.append({**o, "member_count": len(members),
                    "active_keys": sum(1 for k in keys if not k.get("revoked_at"))})
    return {"orgs": out}


@router.post("/orgs")
def create_org(s: dict = Depends(authn.require_admin), name: str = Form(...)):
    try:
        org = orgs.create_org(name.strip(), s["user_id"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    return {"ok": True, "org": org}


@router.get("/orgs/{org_id}")
def org_detail(org_id: str, s: dict = Depends(authn.require_admin)):
    org = orgs.get_org(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    members = [{"user_id": m["user_id"], "role": m["role"], "created_at": m["created_at"],
                "email": (m.get("profiles") or {}).get("email"),
                "name": (m.get("profiles") or {}).get("name")}
               for m in orgs.org_members(org_id)]
    return {"org": org, "members": members, "keys": orgs.org_keys(org_id)}


@router.post("/orgs/{org_id}/status")
def org_status(org_id: str, s: dict = Depends(authn.require_admin), status: str = Form(...)):
    if status not in ("active", "suspended"):
        raise HTTPException(status_code=400, detail="Status must be active or suspended")
    return {"ok": True, "org": orgs.set_org_status(org_id, status)}


# --- members -------------------------------------------------------------------

@router.post("/orgs/{org_id}/members")
def add_member(org_id: str, s: dict = Depends(authn.require_admin),
               email: str = Form(...), name: str = Form(""), role: str = Form("member")):
    """Add a user to an org. If no account exists for the email, one is
    provisioned (confirmed) with a generated password returned ONCE — forward
    it privately; the user should change it on first sign-in."""
    if role not in ("org_admin", "member"):
        raise HTTPException(status_code=400, detail="Role must be org_admin or member")
    if not orgs.get_org(org_id):
        raise HTTPException(status_code=404, detail="Organization not found")
    email = email.strip().lower()
    existing = orgs.get_profile_by_email(email)
    password = None
    if existing:
        user_id = existing["id"]
    else:
        if not name.strip():
            raise HTTPException(status_code=400, detail="Name is required for a new user")
        password = secrets.token_urlsafe(12)
        try:
            user = supa.admin_create_user(email, password, name.strip())
        except supa.SupabaseError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail or "User creation failed")
        user_id = user["id"]
    orgs.add_member(org_id, user_id, role)
    return {"ok": True, "user_id": user_id, "email": email, "role": role,
            "created": password is not None, "password": password}


@router.post("/orgs/{org_id}/members/{user_id}/role")
def member_role(org_id: str, user_id: str, s: dict = Depends(authn.require_admin),
                role: str = Form(...)):
    if role not in ("org_admin", "member"):
        raise HTTPException(status_code=400, detail="Role must be org_admin or member")
    orgs.set_member_role(org_id, user_id, role)
    return {"ok": True}


@router.post("/orgs/{org_id}/members/{user_id}/remove")
def member_remove(org_id: str, user_id: str, s: dict = Depends(authn.require_admin)):
    orgs.remove_member(org_id, user_id)
    return {"ok": True}


# --- API keys --------------------------------------------------------------------

@router.post("/orgs/{org_id}/keys")
def mint_key(org_id: str, s: dict = Depends(authn.require_admin), name: str = Form(...),
             scopes: str = Form("")):
    """Mint an API key for the org. The plaintext key is returned ONCE and is
    unrecoverable afterwards — only its hash is stored.

    `scopes` is an optional comma-separated subset of orgs.ALL_SCOPES. Omit it for
    the least-privilege default (read + verify only) — write/grant management must
    be requested explicitly so a leaked key is not a blanket exfiltration tool."""
    if not orgs.get_org(org_id):
        raise HTTPException(status_code=404, detail="Organization not found")
    requested = [x.strip() for x in scopes.split(",") if x.strip()] or None
    try:
        key, row = orgs.mint_key(org_id, name.strip() or "unnamed", s["user_id"],
                                 scopes=requested)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "key": key, "record": row, "scopes": row.get("scopes")}


@router.post("/keys/{key_id}/revoke")
def revoke_key(key_id: str, s: dict = Depends(authn.require_admin)):
    orgs.revoke_key(key_id)
    return {"ok": True}


# --- Super-Admins (platform_admins — Xinsere staff only) --------------------------

@router.get("/platform-admins")
def list_super_admins(s: dict = Depends(authn.require_admin)):
    """The Super-Admin tier: Xinsere staff who operate the platform. Distinct from
    org (Tenant) Admins, who administer a single customer org."""
    rows = supa.list_platform_admins(supa.SERVICE_ROLE_KEY)
    out = [{"user_id": r["user_id"],
            "email": (r.get("profiles") or {}).get("email"),
            "name": (r.get("profiles") or {}).get("name"),
            "created_at": r.get("created_at")} for r in rows]
    return {"super_admins": out}


@router.post("/platform-admins")
def add_super_admin(s: dict = Depends(authn.require_admin), email: str = Form(...)):
    """Promote an existing user to Super-Admin by email. The account must already
    exist (invite them first) — we never mint an admin from a bare email."""
    email = email.strip().lower()
    prof = orgs.get_profile_by_email(email)
    if not prof:
        raise HTTPException(status_code=404,
                            detail="No account with that email — invite the user first, then promote them.")
    supa.add_platform_admin(supa.SERVICE_ROLE_KEY, prof["id"], s["user_id"])
    return {"ok": True, "user_id": prof["id"], "email": email, "name": prof.get("name")}


@router.post("/platform-admins/{user_id}/remove")
def remove_super_admin(user_id: str, s: dict = Depends(authn.require_admin)):
    """Demote a Super-Admin. Guard against removing the last one (lockout)."""
    current = supa.list_platform_admins(supa.SERVICE_ROLE_KEY)
    if len(current) <= 1 and any(r["user_id"] == user_id for r in current):
        raise HTTPException(status_code=400,
                            detail="Can't remove the last Super-Admin — promote another first.")
    if user_id == s["user_id"]:
        raise HTTPException(status_code=400, detail="You can't remove your own Super-Admin access here.")
    supa.remove_platform_admin(supa.SERVICE_ROLE_KEY, user_id)
    return {"ok": True}


# --- force a user password change -------------------------------------------------

@router.post("/users/{user_id}/force-password-change")
def force_password_change(user_id: str, s: dict = Depends(authn.require_admin)):
    """Flag a user to change their password on next sign-in (e.g. after a shared or
    compromised credential). Cleared automatically when they change it."""
    supa.set_account_security(supa.SERVICE_ROLE_KEY, user_id, {"must_change_password": True})
    return {"ok": True}


@router.post("/users/{user_id}/clear-force-password-change")
def clear_force_password_change(user_id: str, s: dict = Depends(authn.require_admin)):
    supa.set_account_security(supa.SERVICE_ROLE_KEY, user_id, {"must_change_password": False})
    return {"ok": True}


# --- user directory ---------------------------------------------------------------

@router.get("/users")
def users(s: dict = Depends(authn.require_admin)):
    """All users + their org memberships + security state (2FA, forced-change) so the
    console can show role and account posture at a glance."""
    users = orgs.list_all_users()
    try:
        sec = {r["user_id"]: r for r in (supa._rest(
            "GET", "/account_security", supa.SERVICE_ROLE_KEY,
            params={"select": "user_id,must_change_password,mfa_enabled"}) or [])}
    except Exception:
        sec = {}
    try:
        admins = {r["user_id"] for r in supa.list_platform_admins(supa.SERVICE_ROLE_KEY)}
    except Exception:
        admins = set()
    for u in users:
        srow = sec.get(u["id"], {})
        u["mfa_enabled"] = bool(srow.get("mfa_enabled"))
        u["must_change_password"] = bool(srow.get("must_change_password"))
        u["super_admin"] = u["id"] in admins
    return {"users": users}
