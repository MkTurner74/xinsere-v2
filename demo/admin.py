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
def mint_key(org_id: str, s: dict = Depends(authn.require_admin), name: str = Form(...)):
    """Mint an API key for the org. The plaintext key is returned ONCE and is
    unrecoverable afterwards — only its hash is stored."""
    if not orgs.get_org(org_id):
        raise HTTPException(status_code=404, detail="Organization not found")
    key, row = orgs.mint_key(org_id, name.strip() or "unnamed", s["user_id"])
    return {"ok": True, "key": key, "record": row}


@router.post("/keys/{key_id}/revoke")
def revoke_key(key_id: str, s: dict = Depends(authn.require_admin)):
    orgs.revoke_key(key_id)
    return {"ok": True}


# --- user directory ---------------------------------------------------------------

@router.get("/users")
def users(s: dict = Depends(authn.require_admin)):
    return {"users": orgs.list_all_users()}
