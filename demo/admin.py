"""Admin console API — platform-admin only (session + XINSERE_ADMIN_EMAILS).

Backs demo/frontend/admin.html. All data access goes through orgs.py on the
service-role plane AFTER the admin gate; none of these routes appear in the
public API docs (include_in_schema=False on the router).
"""
from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

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


# --- audit log ---------------------------------------------------------------------

@router.get("/audit-log")
def audit_log(s: dict = Depends(authn.require_admin), limit: int = 100,
              day: str = "", action: str = "", actor: str = ""):
    """Recent access_log rows for the console's Audit log view, newest first,
    with actor emails and per-day anchor status resolved. Read-only; the log
    itself is append-only (0014) and anchored on-chain daily (0005/0014)."""
    limit = max(1, min(int(limit or 100), 500))
    params = {"select": "ts,day,org_id,actor_id,actor_type,key_id,action,file_id,bytes,entry_hash",
              "order": "ts.desc", "limit": str(limit)}
    if day.strip():
        params["day"] = f"eq.{day.strip()}"
    if action.strip():
        params["action"] = f"eq.{action.strip()}"
    try:
        rows = supa._rest("GET", "/access_log", supa.SERVICE_ROLE_KEY, params=params) or []
    except supa.SupabaseError:
        rows = []

    # Resolve actor ids -> email/name (service plane; profiles are RLS-locked to self).
    ids = sorted({r["actor_id"] for r in rows if r.get("actor_id")})
    profs = {}
    if ids:
        try:
            got = supa._rest("GET", "/profiles", supa.SERVICE_ROLE_KEY,
                             params={"id": f"in.({','.join(ids)})", "select": "id,email,name"}) or []
            profs = {p["id"]: p for p in got}
        except supa.SupabaseError:
            pass
    org_names = {}
    try:
        org_names = {o["id"]: o["name"] for o in orgs.list_orgs()}
    except Exception:
        pass
    for r in rows:
        p = profs.get(r.get("actor_id"), {})
        r["actor_email"] = p.get("email")
        r["actor_name"] = p.get("name")
        r["org_name"] = org_names.get(r.get("org_id"))

    # Anchor status for the days present, so the UI can badge tamper-evident rows.
    days = sorted({str(r["day"]) for r in rows if r.get("day")})
    anchors = {}
    if days:
        try:
            got = supa._rest("GET", "/access_log_anchors", supa.SERVICE_ROLE_KEY,
                             params={"day": f"in.({','.join(days)})", "select": "day,tx_hash,anchored_at"}) or []
            anchors = {str(a["day"]): a for a in got}
        except supa.SupabaseError:
            pass
    if actor.strip():  # post-filter on resolved email (substring, case-insensitive)
        needle = actor.strip().lower()
        rows = [r for r in rows if needle in (r.get("actor_email") or "").lower()]
    return {"rows": rows, "anchors": anchors}


# --- forensic audit: trace a found file back to who accessed it --------------------

@router.post("/audit-file")
async def audit_file(s: dict = Depends(authn.require_admin), file: UploadFile = File(...)):
    """Upload a suspect file; extract embedded forensic marks (XIN-FWM-<16hex of
    an access_log entry_hash>) and resolve each to the tamper-evident access
    record — who, what, when, and whether that day is sealed on-chain."""
    import watermark
    content = await file.read()
    marks = watermark.extract(content)
    matches = []
    for m in marks:
        hexid = m.rsplit("-", 1)[-1]
        try:
            rows = supa._rest("GET", "/access_log", supa.SERVICE_ROLE_KEY, params={
                "entry_hash": f"like.{hexid}*",
                "select": "ts,day,actor_id,actor_type,action,file_id,node_id,bytes,entry_hash",
                "limit": "3"}) or []
        except supa.SupabaseError:
            rows = []
        for r in rows:
            prof = {}
            try:
                got = supa._rest("GET", "/profiles", supa.SERVICE_ROLE_KEY,
                                 params={"id": f"eq.{r['actor_id']}", "select": "email,name"})
                prof = got[0] if got else {}
            except supa.SupabaseError:
                pass
            node = {}
            if r.get("node_id"):
                try:
                    got = supa._rest("GET", "/nodes", supa.SERVICE_ROLE_KEY,
                                     params={"id": f"eq.{r['node_id']}", "select": "name,owner"})
                    node = got[0] if got else {}
                except supa.SupabaseError:
                    pass
            anchor = None
            try:
                got = supa._rest("GET", "/access_log_anchors", supa.SERVICE_ROLE_KEY,
                                 params={"day": f"eq.{r['day']}", "select": "tx_hash,anchored_at"})
                anchor = got[0] if got else None
            except supa.SupabaseError:
                pass
            matches.append({"mark": m, "ts": r["ts"], "action": r["action"],
                            "actor_email": prof.get("email"), "actor_name": prof.get("name"),
                            "actor_type": r["actor_type"], "file_name": node.get("name"),
                            "file_id": r.get("file_id"), "entry_hash": r["entry_hash"],
                            "anchor_tx": (anchor or {}).get("tx_hash"),
                            "sealed": bool((anchor or {}).get("tx_hash"))})
    return {"filename": file.filename, "marks_found": marks, "matches": matches}


# --- platform config (read-only summary for Settings) -------------------------------

@router.get("/config")
def platform_config(s: dict = Depends(authn.require_admin)):
    """Read-only platform configuration for the Settings section. Values are
    env-managed (change via deploy) — this endpoint NEVER returns a secret,
    only presence flags and non-sensitive values."""
    env = os.environ.get
    email_transport = ("Resend" if env("XINSERE_RESEND_API_KEY")
                       else ("AWS SES" if env("XINSERE_EMAIL_FROM") else "logged no-op"))
    return {
        "general": {
            "app_name": env("XINSERE_APP_NAME", "Xinsere"),
            "backend": env("XINSERE_BACKEND", "local"),
            "https_only": env("XINSERE_HTTPS_ONLY", "auto"),
        },
        "security": {
            "require_email_verified": env("XINSERE_REQUIRE_EMAIL_VERIFIED", "") in ("1", "true", "yes"),
            "password_policy": "≥12 chars, upper + lower + digit + symbol",
            "rate_per_min": env("XINSERE_RATE_PER_MIN", "default"),
            "org_ingest_bytes_per_day": env("XINSERE_INGEST_BYTES_PER_DAY_ORG", "default"),
            "org_egress_bytes_per_day": env("XINSERE_EGRESS_BYTES_PER_DAY_ORG", "default"),
        },
        "email": {
            "transport": email_transport,
            "sender": env("XINSERE_EMAIL_FROM", "(not set)"),
        },
        "blockchain": {
            "network": "Polygon Amoy" if env("XINSERE_CHAIN_ID", "80002") == "80002" else env("XINSERE_CHAIN_ID"),
            "chain_id": env("XINSERE_CHAIN_ID", "80002"),
            "contract": env("XINSERE_CONTRACT_ADDRESS", "(not set)"),
            "rpc_configured": bool(env("XINSERE_RPC_URL")),
        },
    }


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
