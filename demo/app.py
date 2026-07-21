"""Xinsere hosted app — a real, wired file explorer over the DPD pipeline.

Stateless by design (deployable to serverless):
  - Auth + folder tree + shares live in Supabase (supa.py), RLS-scoped by the
    signed-in user's JWT.
  - File bytes go through the real pipeline (store.py) — fragmented, AES-256-GCM
    encrypted, scattered across S3, keys wrapped by KMS, index in DynamoDB.
  - Download access is decided by the on-chain contract verify() (chain.py), never
    the database.

The only server-side state is the signed session cookie (the Supabase tokens).
"""
from __future__ import annotations

import io
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.datastructures import UploadFile
from starlette.middleware.sessions import SessionMiddleware

import config
import share_grants
import share_quota
import supa
from authn import session as _session, is_platform_admin
from chain import CHAIN
from store import (get_pipeline, XinsereIntegrityError, presign_put, staged_size,
                   read_staged, delete_staged, MAX_INLINE_BYTES, MAX_STAGED_BYTES)

_HERE = os.path.dirname(os.path.abspath(__file__))
# Fail-closed: refuse to boot in production with a default session secret or a
# default/absent HMAC tenant salt (security audit findings 1 & 2). No-op in dev.
config.validate_production_config()
# Public docs are OFF — the gated docs site (docs_site.py) re-exposes /docs,
# /docs/guide and /openapi.json to signed-in users only.
app = FastAPI(title="Xinsere", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=config.session_secret(),
                   max_age=60 * 60 * 8, same_site="lax", https_only=config.https_only())

_GRADS = [
    ("#8A6BFF", "#5B3DF5"), ("#4FE3C1", "#2E9E8A"), ("#FF8B7A", "#B4503F"),
    ("#9277FF", "#5B3DF5"), ("#5BC8FF", "#2E6FF5"), ("#F5A15B", "#B4703F"),
    ("#C15BFF", "#7A2EF5"), ("#5BFF9E", "#2E9E5A"),
]


def _initials(name: str) -> str:
    parts = [p for p in (name or "").strip().split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _public(profile: dict) -> dict:
    """A profile row -> fields safe/needed for the client."""
    uid = profile.get("id", "")
    idx = int(uid[-4:], 16) % len(_GRADS) if uid[-4:].isalnum() else 0
    return {"id": uid, "name": profile.get("name") or profile.get("email", ""),
            "email": profile.get("email", ""), "initials": _initials(profile.get("name", "")),
            "grad": list(_GRADS[idx])}


# --- session (see authn.py — shared with the admin console and docs site) ----

def _profiles_map(token: str) -> dict:
    return {p["id"]: p for p in supa.list_profiles(token)}


def node_view(node: dict, viewer: str, token: str, pmap: dict) -> dict:
    owner = pmap.get(node["owner"])
    v = {
        "id": node["id"], "type": node["type"], "name": node["name"],
        "parent": node.get("parent"),
        "owner": node["owner"], "owner_name": owner["name"] if owner else node["owner"],
        "created_at": node.get("created_at"),
    }
    if node["type"] == "file":
        v.update(size=node.get("size", 0), frags=node.get("frags", 7),
                 content_type=node.get("content_type", "application/octet-stream"),
                 sha256=node.get("sha", ""))
    if node["owner"] == viewer:
        shares = supa.shares_for_node(token, node["id"])
        v["shared_with"] = [
            {**_public(pmap[s["grantee"]]), "tx": s["tx"],
             "share_type": s.get("share_type", "download")}
            for s in shares if s["grantee"] in pmap
        ]
    return v


def _best_access(a: str | None, b: str | None) -> str | None:
    order = {None: 0, "view": 1, "download": 2, "co-owner": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _viewer_share_map(token: str, uid: str) -> dict:
    """{node_id: share_type} for every share granted to the viewer (RLS lets a
    grantee read their own share rows)."""
    try:
        return {s["node_id"]: s.get("share_type", "download")
                for s in supa.shares_for_grantee(token, uid)}
    except Exception:
        return {}


# --- pages ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    with open(os.path.join(_HERE, "frontend", "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/xinsere-client.js")
def client_js() -> HTMLResponse:
    with open(os.path.join(_HERE, "frontend", "xinsere-client.js"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), media_type="application/javascript")


@app.get("/mfa", response_class=HTMLResponse)
def mfa_page() -> HTMLResponse:
    """Dedicated, non-dismissible two-factor challenge shown at login when a
    verified factor exists. The session stays MFA-pending (no data access) until
    the code is verified here."""
    with open(os.path.join(_HERE, "frontend", "mfa.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/recover", response_class=HTMLResponse)
def recover_page() -> HTMLResponse:
    """Public account-recovery page: request a Xinsere-branded reset link with
    instructions on what happens next."""
    with open(os.path.join(_HERE, "frontend", "recover.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/security", response_class=HTMLResponse)
def security_page() -> HTMLResponse:
    """Self-contained account-security page (change password, 2FA, login step-ups).
    Gated client-side against /api/account/security-status (redirects to sign-in)."""
    with open(os.path.join(_HERE, "frontend", "security.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request) -> HTMLResponse:
    """Admin console shell. The page itself checks /api/admin/whoami and shows a
    sign-in prompt if the session isn't a platform admin — every data route is
    server-gated regardless."""
    with open(os.path.join(_HERE, "frontend", "admin.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/warm")
async def warm():
    """Pre-build the heavy singletons (S3/KMS/DynamoDB clients + the web3 signer)
    so a real user request doesn't pay cold-init latency. Hit by a scheduled ping;
    intentionally unauthenticated — it touches no user data, only warms clients."""
    warmed = {}
    try:
        get_pipeline()
        warmed["pipeline"] = "ok"
    except Exception as exc:
        warmed["pipeline"] = f"err: {type(exc).__name__}"
    try:
        _ = CHAIN.wallet
        warmed["chain"] = "ok"
    except Exception as exc:
        warmed["chain"] = f"err: {type(exc).__name__}"
    return {"ok": True, "warmed": warmed}


# --- auth -------------------------------------------------------------------

@app.post("/api/login")
async def login(request: Request, identifier: str = Form(...), password: str = Form(...)):
    try:
        grant = supa.sign_in(identifier.strip().lower(), password)
    except supa.SupabaseError:
        raise HTTPException(status_code=401, detail="Wrong email or password")
    user = grant.get("user") or {}
    email_verified = bool(user.get("email_confirmed_at") or user.get("confirmed_at"))
    # Email-verification gate (opt-in hard block via env so no one is locked out
    # before every account is confirmed; the flag is surfaced to the client either way).
    if not email_verified and os.environ.get("XINSERE_REQUIRE_EMAIL_VERIFIED", "").lower() == "true":
        raise HTTPException(status_code=403,
                            detail="Please verify your email before signing in — check your inbox.")
    sess = supa.session_from_grant(grant)
    request.session["sb"] = sess
    supa.ensure_root(sess["access_token"], sess["user_id"])
    prof = supa.get_profile(sess["access_token"], sess["user_id"]) or {"id": sess["user_id"]}
    _reconcile_pending(sess["user_id"], (prof or {}).get("email") or identifier.strip().lower())
    # Security posture for the client: forced rotation, 2FA step-up, email status.
    must_change, mfa_factor = False, None
    try:
        must_change = bool(supa.get_account_security(
            supa.SERVICE_ROLE_KEY, sess["user_id"]).get("must_change_password"))
    except Exception:
        pass
    try:
        verified = [f for f in supa.mfa_list_factors(sess["access_token"])
                    if f.get("status") == "verified"]
        mfa_factor = verified[0].get("id") if verified else None
    except Exception:
        pass
    # Hard MFA gate: mark the session pending until the TOTP challenge is met.
    # authn.session() blocks all data routes while pending, so the challenge
    # can't be skipped by dismissing a page.
    request.session["mfa_pending"] = bool(mfa_factor)
    request.session["mfa_factor_id"] = mfa_factor or ""
    return {"ok": True, "user": _public(prof),
            "must_change_password": must_change,
            "email_verified": email_verified,
            "mfa_required": bool(mfa_factor),
            "mfa_factor_id": mfa_factor}


@app.post("/api/signup")
async def signup(request: Request):
    """Public self-service signup is DISABLED and the invariant is enforced HERE,
    in code — not by an out-of-band Supabase dashboard toggle (security audit
    finding 5). Xinsere is invite-only: accounts are provisioned by a platform
    admin (POST /api/admin/invite) or a tenant admin (org member add). Until the
    self-serve onboarding flow ships with its own hardening (findings 1/3/8/9
    closed), this route fails closed."""
    raise HTTPException(
        status_code=403,
        detail="Public signup is disabled. Xinsere is invite-only — ask an administrator for an invitation.")


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


def _wallet_guard() -> None:
    """Low-balance pre-flight for the shared gas wallet (Finding 2 alarm). If the
    signer clearly can't afford a batch-anchor tx, fail fast with a clear 503 (and
    a log line ops can alarm on) instead of letting the on-chain send die mid-share.
    Best-effort: a status-check error is NOT fatal (fail-open) — the anchor itself
    surfaces any real problem — but a KNOWN-empty wallet is rejected up front."""
    try:
        st = CHAIN.status()
    except Exception as exc:
        logging.getLogger("xinsere.app").warning("wallet status check failed (fail-open): %s", exc)
        return
    if not st.get("wallet_ok", True):
        logging.getLogger("xinsere.app").error(
            "GAS WALLET LOW balance_pol=%s est_grants_remaining=%s — shares blocked until top-up",
            st.get("balance_pol"), st.get("est_grants_remaining"))
        raise HTTPException(
            status_code=503,
            detail="The grant wallet is low on gas — sharing is paused until it's topped up. "
                   "Try again shortly. [wallet_low]")


def _grant_inherited(token: str, node_id: str, file_id: str) -> int:
    """Grant-on-add: a file added to an already-shared folder must be readable by
    that folder's grantees. Batched (Finding 2) — one flat-gas Merkle root per
    covering share, recorded under that share so a later unshare revokes it too,
    instead of one on-chain tx per grantee. Best-effort: a chain failure must not
    fail the upload (RLS still lets grantees SEE the file; the grant governs
    download, and a re-share repairs it)."""
    svc = supa.SERVICE_ROLE_KEY
    if not svc:
        return 0
    granted = 0
    file_node = {"file_id": file_id}
    try:
        for sh in supa.shares_covering(token, node_id):
            try:
                share_grants.grant_share(svc, [file_node], sh["grantee"], sh["node_id"],
                                         "grant-on-add", sh.get("share_type", "download"))
                granted += 1
            except Exception as exc:
                logging.getLogger("xinsere.app").warning(
                    "grant-on-add failed node=%s grantee=%s: %s", node_id, sh["grantee"], exc)
    except Exception:
        pass
    return granted


import re as _re

_SEARCH_ALLOWED = _re.compile(r"[^a-zA-Z0-9 @._+-]")


def clean_search_query(q: str) -> str:
    """Strip anything that could break the PostgREST or() filter grouping (commas,
    parentheses, wildcards, ...). Keeps letters, digits, spaces, and email chars."""
    return _SEARCH_ALLOWED.sub("", (q or "").strip())[:64]


def _reconcile_pending(user_id: str, email: str) -> dict:
    """First-login materialization of external-email invites: for every pending
    share to this email, grant the invitee on-chain (per file) and insert the real
    share row, then drop the stub. Best-effort — a chain hiccup must not block
    login (RLS lets them SEE shared items; the grant governs download and a re-share
    repairs it). Runs with the service-role key."""
    if not email:
        return {"materialized": 0}
    svc = supa.SERVICE_ROLE_KEY
    done = 0
    try:
        pending = supa.pending_shares_for_email(svc, email)
    except Exception:
        return {"materialized": 0}
    for p in pending:
        node_id = p["node_id"]
        stype = p.get("share_type", "download")
        try:
            files = supa.files_under(svc, node_id)
            last_tx = None
            try:
                res = share_grants.grant_share(svc, files, user_id, node_id,
                                               "reconcile-invite", stype)
                last_tx = res.tx_hashes[-1] if res and res.tx_hashes else None
            except Exception as exc:
                logging.getLogger("xinsere.app").warning(
                    "pending-share grant failed node=%s grantee=%s: %s", node_id, user_id, exc)
            supa.insert_share(svc, node_id, user_id, last_tx, stype)
            supa.delete_pending_share(svc, p["id"])
            done += 1
        except Exception as exc:
            logging.getLogger("xinsere.app").warning(
                "pending-share reconcile failed node=%s email=%s: %s", node_id, email, exc)
    return {"materialized": done}


@app.get("/api/search")
async def search_nodes(request: Request, q: str = "", limit: int = 60):
    """Global as-you-type search over the caller's visible tree (own + shared —
    RLS enforces the scope because the query runs on the USER token)."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    try:
        rows = supa.search_nodes(token, q, limit=max(1, min(int(limit or 60), 200)))
    except supa.SupabaseError as exc:   # never blank the search UI with a 500
        logging.getLogger("xinsere.app").warning("search failed q=%r: %s", q, exc)
        return {"query": q, "results": []}
    pmap = _profiles_map(token)
    out = []
    for n in rows:
        owner = pmap.get(n["owner"]) or {}
        out.append({"id": n["id"], "name": n["name"], "type": n["type"],
                    "parent": n.get("parent"), "mine": n["owner"] == uid,
                    "owner": n["owner"], "owner_name": owner.get("name") or "",
                    "size": n.get("size"), "frags": n.get("frags"),
                    "sha256": n.get("sha") or "", "content_type": n.get("content_type"),
                    "created_at": n.get("created_at")})
    return {"query": q, "results": out}


@app.get("/api/users/search")
async def users_search(request: Request, q: str = ""):
    """Typeahead for sharing — matches name/username/email, excludes self."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    cq = clean_search_query(q)
    if not cq:
        return {"results": []}
    return {"results": [_public(r) for r in supa.search_profiles(token, cq, uid, limit=8)]}


@app.post("/api/admin/invite")
async def admin_invite(request: Request, email: str = Form(...), name: str = Form(...)):
    """Invite a user (public signup is disabled). Platform-admin only, decided by
    the durable platform_admins registry (migration 0009), NOT a mutable email
    match. Generates a strong password and returns it ONCE — forward it privately."""
    import secrets as _secrets
    s = _session(request)
    prof = supa.get_profile(s["access_token"], s["user_id"]) or {}
    if not is_platform_admin(s["user_id"], prof):
        raise HTTPException(status_code=403, detail="Admin only")
    password = _secrets.token_urlsafe(12)
    try:
        user = supa.admin_create_user(email.strip().lower(), password, name.strip())
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail or "Invite failed")
    # (invitee's root folder is created lazily on their first login)
    return {"ok": True, "email": email.strip().lower(), "name": name.strip(),
            "password": password, "user_id": user.get("id")}


@app.get("/api/me")
async def me(request: Request):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    prof = supa.get_profile(token, uid) or {"id": uid}
    others = [_public(o) for o in supa.list_others(token, uid)]
    # Forced-rotation must bite MID-SESSION too, not only at the next login —
    # an admin flipping the flag expects the next page load to enforce it.
    must_change = False
    try:
        must_change = bool(supa.get_account_security(
            supa.SERVICE_ROLE_KEY, uid).get("must_change_password"))
    except Exception:
        pass
    return {"user": _public(prof), "others": others,
            "must_change_password": must_change,
            "mfa_required": bool(request.session.get("mfa_pending")),
            "mfa_factor_id": request.session.get("mfa_factor_id", ""),
            "admin": is_platform_admin(uid, prof)}


# --- tree -------------------------------------------------------------------

@app.get("/api/tree")
async def tree(request: Request, folder: str = ""):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    folder_id = folder or supa.ensure_root(token, uid)
    return await _tree_impl(token, uid, folder_id)


@app.get("/api/folders")
async def all_folders(request: Request):
    """The caller's whole folder tree, flat, in one round-trip — feeds the Move
    picker. root = the user's root folder id (its row has no parent)."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    root = supa.ensure_root(token, uid)
    return {"root": root, "folders": supa.folders_by_owner(token, uid)}


async def _tree_impl(token: str, uid: str, folder_id: str):
    node = supa.get_node(token, folder_id)  # RLS: None if not accessible
    if not node or node["type"] != "folder":
        raise HTTPException(status_code=404, detail="Folder not found")

    pmap = _profiles_map(token)
    crumbs, cur = [], node
    while cur:
        crumbs.append({"id": cur["id"], "name": cur["name"]})
        cur = supa.get_node(token, cur["parent"]) if cur.get("parent") else None
    crumbs.reverse()

    kids = [node_view(c, uid, token, pmap) for c in supa.children(token, folder_id)]
    fv = node_view(node, uid, token, pmap)

    # Viewer's effective access level (0016) so the UI can offer the right verbs.
    # Owner => owner. Otherwise the best share on the folder or any ancestor
    # (crumbs already walk the chain), with a direct share on a child able to
    # raise (never lower) that child's level. Display-only — the download and
    # preview gates re-verify on-chain regardless.
    if node["owner"] == uid:
        folder_access = "owner"
    else:
        smap = _viewer_share_map(token, uid)
        inherited = None
        for c in crumbs:
            inherited = _best_access(inherited, smap.get(c["id"]))
        folder_access = inherited or "view"   # RLS said visible; default to least
        for k in kids:
            k["access"] = (
                "owner" if k["owner"] == uid
                else _best_access(folder_access, smap.get(k["id"])))
    fv["access"] = folder_access
    for k in kids:
        k.setdefault("access", "owner" if k["owner"] == uid else folder_access)
    return {"folder": fv, "breadcrumbs": crumbs, "children": kids}


@app.get("/api/shared")
async def shared(request: Request):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    pmap = _profiles_map(token)
    items = []
    for n in supa.shared_with(token, uid):
        v = node_view(n, uid, token, pmap)
        v["access"] = n.get("share_type", "download")   # the viewer's level (0016)
        items.append(v)
    return {"children": items}


@app.get("/api/shared-by-me")
async def shared_by_me(request: Request):
    """Every node the caller OWNS that has at least one active share — the
    manage-your-shares view (find + revoke/change in one place)."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    pmap = _profiles_map(token)
    seen, items = set(), []
    for row in supa.shares_by_owner(token, uid):
        nid = row["node_id"]
        if nid in seen:
            continue
        seen.add(nid)
        n = supa.get_node(token, nid)
        if n and not n.get("deleted_at") and n["owner"] == uid:
            items.append(node_view(n, uid, token, pmap))
    return {"children": items}


@app.post("/api/folder")
async def make_folder(request: Request, name: str = Form(...), parent: str = Form(...),
                      on_conflict: str = Form(None)):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    parent_node = supa.get_node(token, parent)
    if not parent_node or parent_node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only add folders to your own files")
    clean = name.strip() or "New folder"
    clean = _resolve_name(token, parent, clean, is_file=False,
                          exclude_id=None, on_conflict=on_conflict)
    node = supa.insert_folder(token, clean, parent, uid)
    return node_view(node, uid, token, _profiles_map(token))


@app.post("/api/upload")
async def upload(request: Request):
    """One or more files. For folder uploads, a parallel `paths` field carries each
    file's relative path so the tree is rebuilt."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    form = await request.form()
    parent = form.get("parent") or supa.ensure_root(token, uid)
    parent_node = supa.get_node(token, parent)
    if not parent_node or parent_node["owner"] != uid:
        raise HTTPException(status_code=403, detail="Upload only into your own folders")

    files = form.getlist("files")
    paths = form.getlist("paths")
    pmap = _profiles_map(token)
    created = []
    for i, f in enumerate(files):
        if not isinstance(f, UploadFile):
            continue
        content = await f.read()
        rel = (paths[i] if i < len(paths) and paths[i] else (f.filename or "file")).replace("\\", "/")
        subdir = os.path.dirname(rel)
        name = os.path.basename(rel) or (f.filename or "file")
        target = supa.ensure_path(token, subdir, parent, uid) if subdir else parent
        res = get_pipeline().store(content, f.content_type or "application/octet-stream", label=name)
        node = supa.insert_file(token, name, target, uid, file_id=res.file_id,
                                sha256=res.file_sha256, size=len(content),
                                frags=res.fragment_count,
                                content_type=f.content_type or "application/octet-stream")
        _grant_inherited(token, node["id"], res.file_id)
        created.append(node_view(node, uid, token, pmap))
    return {"created": created, "count": len(created)}


# --- direct-to-S3 upload (no 4.5 MB function cap) ---------------------------

@app.post("/api/upload-url")
async def upload_url(request: Request, parent: str = Form(...)):
    """Issue a presigned PUT so the browser uploads the raw file straight to the
    staging bucket. Only this tiny request touches the function."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    parent_node = supa.get_node(token, parent)
    if not parent_node or parent_node["owner"] != uid:
        raise HTTPException(status_code=403, detail="Upload only into your own folders")
    key, url = presign_put(uid)
    return {"key": key, "url": url, "method": "PUT"}


@app.post("/api/finalize-upload")
async def finalize_upload(request: Request, key: str = Form(...), name: str = Form(...),
                          parent: str = Form(...), path: str = Form(""),
                          content_type: str = Form("application/octet-stream")):
    """Pull the staged file, run it through the pipeline, index it, drop the staging
    copy. `path` (optional) carries a relative path for folder uploads."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    if not key.startswith(f"staging/{uid}/"):
        raise HTTPException(status_code=403, detail="Not your staged upload")
    parent_node = supa.get_node(token, parent)
    if not parent_node or parent_node["owner"] != uid:
        raise HTTPException(status_code=403, detail="Upload only into your own folders")
    try:
        size = staged_size(key)
    except Exception:
        raise HTTPException(status_code=404, detail="Staged file not found — the upload may have failed")
    if size > MAX_STAGED_BYTES:
        delete_staged(key)
        raise HTTPException(status_code=413,
                            detail=f"File too large to process here ({size} bytes); limit is {MAX_STAGED_BYTES}")
    rel = (path or name).replace("\\", "/")
    subdir = os.path.dirname(rel)
    fname = os.path.basename(rel) or name
    target = supa.ensure_path(token, subdir, parent, uid) if subdir else parent
    content = read_staged(key)
    res = get_pipeline().store(content, content_type, label=fname)
    node = supa.insert_file(token, fname, target, uid, file_id=res.file_id,
                            sha256=res.file_sha256, size=len(content),
                            frags=res.fragment_count, content_type=content_type)
    delete_staged(key)
    _grant_inherited(token, node["id"], res.file_id)  # folder already shared? grant new file too
    return node_view(node, uid, token, _profiles_map(token))


# --- file management (rename / move / delete) --------------------------------

def _suffix_name(name: str, is_file: bool, taken: set[str]) -> str:
    """First ' (n)' variant of `name` not in `taken` (lowercased). For a file the
    counter goes BEFORE the extension ('report.pdf' -> 'report (2).pdf'); a folder
    suffixes at the end ('Docs' -> 'Docs (2)'). Mirrors Drive/OneDrive 'Keep both'."""
    import re as _r
    m = _r.search(r"\.([A-Za-z0-9]{1,6})$", name) if is_file else None
    base = name[: m.start()] if m else name
    ext = m.group(0) if m else ""
    n = 2
    while f"{base} ({n}){ext}".lower() in taken:
        n += 1
    return f"{base} ({n}){ext}"


def _sibling_names(token: str, parent_id: str, exclude_id: str | None = None) -> set[str]:
    """Lowercased names of the live children of `parent_id` (excluding `exclude_id`).
    Case-insensitive so 'Report.PDF' and 'report.pdf' collide, matching how the
    desktop file managers users know behave."""
    return {(c["name"] or "").lower() for c in supa.children(token, parent_id)
            if c["id"] != exclude_id}


def _resolve_name(token: str, parent_id: str, name: str, *, is_file: bool,
                  exclude_id: str | None, on_conflict: str | None) -> str:
    """Return the name to actually use in `parent_id`, or raise 409 on a collision the
    caller didn't ask to resolve. `on_conflict='keep-both'` auto-suffixes; otherwise a
    409 carries a `suggestion` the UI offers as 'Keep both'. Cancel is the client
    simply not retrying — there's no destructive 'replace' path (Mark 2026-07-20)."""
    taken = _sibling_names(token, parent_id, exclude_id)
    if name.lower() not in taken:
        return name
    if on_conflict == "keep-both":
        return _suffix_name(name, is_file, taken)
    raise HTTPException(status_code=409, detail={
        "conflict": True, "item": name, "message": f"“{name}” already exists here",
        "suggestion": _suffix_name(name, is_file, taken)})


@app.post("/api/rename")
async def rename(request: Request, node_id: str = Form(...), name: str = Form(...),
                 on_conflict: str = Form(None)):
    """Display-name only — fragment names carry no filename linkage, so this
    never touches storage or the chain. A name already used by a sibling returns
    409 (with a 'Keep both' suggestion) unless on_conflict='keep-both'."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only rename your own items")
    clean = name.strip()
    if not clean:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if node.get("parent"):
        clean = _resolve_name(token, node["parent"], clean, is_file=node["type"] == "file",
                              exclude_id=node_id, on_conflict=on_conflict)
    updated = supa.rename_node(token, node_id, clean)
    return node_view(updated, uid, token, _profiles_map(token))


@app.post("/api/move")
async def move(request: Request, node_id: str = Form(...), new_parent: str = Form(...),
               on_conflict: str = Form(None)):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    target = supa.get_node(token, new_parent)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only move your own items")
    if not node.get("parent"):
        raise HTTPException(status_code=400, detail="The root folder cannot be moved")
    if not target or target["type"] != "folder" or target["owner"] != uid:
        raise HTTPException(status_code=403, detail="Destination must be your own folder")
    # A folder cannot be moved into itself or its own subtree.
    if node["type"] == "folder":
        if new_parent == node_id or any(a["id"] == node_id for a in supa.ancestors(token, new_parent)):
            raise HTTPException(status_code=400, detail="Cannot move a folder into itself")
    # No-op guard: already in the destination — nothing to move (and the name check
    # below would false-positive against the item's own current row).
    if node.get("parent") == new_parent:
        raise HTTPException(status_code=400, detail="Item is already in that folder")
    # Name collision in the destination (move keeps the item's name): 409 unless the
    # client opted into 'keep-both', in which case we move then suffix to a free name.
    final_name = _resolve_name(token, new_parent, node["name"], is_file=node["type"] == "file",
                               exclude_id=node_id, on_conflict=on_conflict)

    # Inherited-share reconciliation: moving between differently-shared folders
    # changes which ancestor folder-shares cover this subtree. Batched (Finding 2):
    # instead of a per-file grant/revoke storm, we RE-ANCHOR each affected ancestor
    # share over its CURRENT subtree — after the move, files_under(share_node)
    # naturally includes (gained) or excludes (lost) the moved subtree, so a single
    # revoke+re-grant per (share_node, grantee) restores the correct grant set.
    # Tracked as (share_node, grantee) pairs so we reanchor the right root.
    before_rows = supa.shares_covering(token, node_id)
    before = {(sh["node_id"], sh["grantee"]) for sh in before_rows}
    updated = supa.move_node(token, node_id, new_parent)
    if final_name != node["name"]:      # 'keep both' — de-collide after the re-parent
        updated = supa.rename_node(token, node_id, final_name)
    after_rows = supa.shares_covering(token, node_id)
    after = {(sh["node_id"], sh["grantee"]) for sh in after_rows}
    # Re-anchor at each share's own level (0016) — a view-only share stays view-only.
    stype = {(sh["node_id"], sh["grantee"]): sh.get("share_type", "download")
             for sh in [*before_rows, *after_rows]}
    rec = {"reanchored": 0, "revoked": 0, "errors": 0}
    changed = before ^ after   # shares this subtree gained or lost by moving
    svc = supa.SERVICE_ROLE_KEY
    if changed and svc:
        for share_node, g in changed:
            try:
                files = supa.files_under(svc, share_node)
                r = share_grants.reanchor_share(svc, share_node, g, files, "move",
                                                stype.get((share_node, g), "download"))
                rec["reanchored"] += 1
                rec["revoked"] += r.get("revoked", 0)
                rec["errors"] += r.get("revoke_errors", 0)
            except Exception:
                rec["errors"] += 1   # surfaced to the UI; owner can retry the move
    view = node_view(updated, uid, token, _profiles_map(token))
    view["reconciliation"] = rec
    return view


def _erase_subtree(token: str, node_id: str) -> dict:
    """Permanent cryptographic erasure of a node (and descendants). For every
    file: revoke outstanding on-chain grants, then pipeline erasure (fragments +
    index removed — leftover ciphertext is unrecoverable), then remove the
    metadata node (descendants cascade). token may be a user token or the
    service-role key (auto-purge cron)."""
    files = supa.files_under(token, node_id)
    revoked, revoke_errors = 0, 0
    # Batch-granted interactive shares (Finding 2): revoke the recorded root(s) for
    # direct shares on this node. Best-effort — the crypto-erasure below destroys the
    # bytes regardless, so this is on-chain hygiene, not the access gate.
    svc = supa.SERVICE_ROLE_KEY
    if svc:
        try:
            for sh in supa.shares_for_node(token, node_id):
                r = share_grants.revoke_share(svc, node_id, sh["grantee"])
                revoked += r["revoked"]
                revoke_errors += r["errors"]
        except Exception:
            revoke_errors += 1
    for f in files:
        try:
            for sh in supa.shares_covering(token, f["id"]):
                try:
                    if CHAIN.revoke(f["file_id"], sh["grantee"]):  # None = no active grant (skip)
                        revoked += 1
                except Exception:
                    revoke_errors += 1  # erasure below kills access regardless
        except Exception:
            revoke_errors += 1
        try:
            get_pipeline().delete(f["file_id"])  # cryptographic erasure
        except Exception:
            pass  # already-gone pipeline records shouldn't block metadata cleanup
    supa.delete_node(token, node_id)
    return {"erased_files": len(files), "grants_revoked": revoked, "revoke_errors": revoke_errors}


@app.post("/api/delete")
async def delete_item(request: Request, node_id: str = Form(...)):
    """Move to Trash (soft delete) — metadata only, no chain writes, no erasure.
    Reversible via /api/restore; auto-purged 30 days later, or Erased on demand."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only delete your own items")
    if not node.get("parent"):
        raise HTTPException(status_code=400, detail="The root folder cannot be deleted")
    supa.soft_delete(token, node_id, datetime.now(timezone.utc).isoformat())
    return {"ok": True, "trashed": True}


@app.post("/api/restore")
async def restore_item(request: Request, node_id: str = Form(...)):
    """Bring an item back out of the Trash to its original location."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only restore your own items")
    supa.restore_node(token, node_id)
    return {"ok": True}


@app.get("/api/trash")
async def list_trash(request: Request):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    pmap = _profiles_map(token)
    items = [node_view(n, uid, token, pmap) for n in supa.trashed(token, uid)]
    return {"children": items}


@app.post("/api/erase")
async def erase_item(request: Request, node_id: str = Form(...)):
    """Permanent, irreversible cryptographic erasure (from Trash or directly)."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only erase your own items")
    if not node.get("parent"):
        raise HTTPException(status_code=400, detail="The root folder cannot be erased")
    return {"ok": True, **_erase_subtree(token, node_id)}


@app.post("/api/empty-trash")
async def empty_trash(request: Request):
    """Erase everything in the caller's Trash."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    total = {"erased_files": 0, "grants_revoked": 0, "revoke_errors": 0, "items": 0}
    for n in supa.trashed(token, uid):
        r = _erase_subtree(token, n["id"])
        for k in ("erased_files", "grants_revoked", "revoke_errors"):
            total[k] += r[k]
        total["items"] += 1
    return {"ok": True, **total}


@app.get("/api/purge-expired")
async def purge_expired(request: Request):
    """Auto-purge Trash items older than 30 days. BOUNDED per call (processes at
    most PURGE_BATCH items, oldest first) so it can never exceed the function
    timeout no matter how much is queued — a daily Vercel cron calls it.

    NOTE (scale): this single-endpoint scan+erase is a DEMO-scale design. At
    production volume the purge is a queue fan-out — scheduler enqueues expired
    ids to SQS, worker Lambdas erase in parallel with retries/DLQ, and on-chain
    revokes are batched/decoupled (erasure already kills access). See PRD
    "Trash auto-purge at scale".

    Auth: Vercel cron (Authorization: Bearer $CRON_SECRET) or a manual
    X-Purge-Secret header."""
    cron_secret = os.environ.get("CRON_SECRET")
    manual_secret = os.environ.get("XINSERE_PURGE_SECRET")
    authed = ((cron_secret and request.headers.get("authorization") == f"Bearer {cron_secret}")
              or (manual_secret and request.headers.get("x-purge-secret") == manual_secret))
    if not authed:
        raise HTTPException(status_code=403, detail="Forbidden")
    svc = supa.SERVICE_ROLE_KEY
    if not svc:
        raise HTTPException(status_code=501, detail="Service role key not configured")
    limit = int(os.environ.get("XINSERE_PURGE_BATCH", "100"))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    rows = supa._rest("GET", "/nodes", svc, params={
        "deleted_at": f"lt.{cutoff}", "select": "id",
        "order": "deleted_at.asc", "limit": str(limit)}) or []
    erased = 0
    for r in rows:
        try:
            _erase_subtree(svc, r["id"])
            erased += 1
        except Exception:
            pass
    return {"ok": True, "purged": erased, "batch_limit": limit, "more_likely": len(rows) == limit}


@app.get("/api/anchor-access-log")
async def anchor_access_log(request: Request):
    """Daily on-chain Merkle anchor of the access log (Finding 6) — makes the
    'tamper-evident' claim real: once a day's root is anchored, no row from that
    day can be altered/deleted without breaking the immutable on-chain root.

    Auth: same cron/manual-secret gate as purge-expired. An hourly Vercel cron
    calls it; seals the PREVIOUS full hour (UTC) per-org (0018) by default.
    ?period=YYYY-MM-DDTHH backfills a specific hour; ?day=YYYY-MM-DD runs the
    legacy daily commingled anchor (pre-0018 backfill only)."""
    cron_secret = os.environ.get("CRON_SECRET")
    manual_secret = os.environ.get("XINSERE_PURGE_SECRET")
    authed = ((cron_secret and request.headers.get("authorization") == f"Bearer {cron_secret}")
              or (manual_secret and request.headers.get("x-purge-secret") == manual_secret))
    if not authed:
        raise HTTPException(status_code=403, detail="Forbidden")
    svc = supa.SERVICE_ROLE_KEY
    if not svc:
        raise HTTPException(status_code=501, detail="Service role key not configured")
    import access_log
    try:
        day = request.query_params.get("day")
        if day:   # legacy daily backfill
            return {"ok": True, **access_log.anchor_day(svc, day)}
        period = request.query_params.get("period") or \
            access_log.period_of((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        return {"ok": True, **access_log.anchor_period(svc, period)}
    except Exception as exc:
        logging.getLogger("xinsere.app").error("access-log anchor failed: %s", exc)
        raise HTTPException(status_code=502, detail="Anchor failed — retry")


@app.post("/api/unshare")
async def unshare(request: Request, node_id: str = Form(...), grantee: str = Form(...)):
    """Revoke a share: on-chain revocation per file under the node, then remove
    the share row. The contract is authoritative — downloads fail immediately."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only manage shares on your own items")
    files = supa.files_under(token, node_id)
    svc = supa.SERVICE_ROLE_KEY
    last_tx, revoked, errors = None, 0, 0
    # Batch-granted interactive shares (Finding 2): revoke the recorded root(s) —
    # one revokeBatchRoot per root, exact because interactive roots are single-grantee.
    if svc:
        br = share_grants.revoke_share(svc, node_id, grantee)
        revoked += br["revoked"]
        errors += br["errors"]
    # Legacy per-file grants (pre-batch shares / v1 API grants) — verify-first revoke,
    # a no-op for files that carry only a batch grant. The verify() reads run in
    # parallel (one RPC per file; a big folder done sequentially eats the request
    # budget); the rare active grants then revoke sequentially (nonce safety).
    def _has_legacy(f):
        return CHAIN.verify(f["file_id"], grantee)[0]
    needs: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for f, fut in [(f, ex.submit(_has_legacy, f)) for f in files]:
            try:
                if fut.result():
                    needs.append(f)
            except Exception:
                errors += 1
    for f in needs:
        try:
            tx = CHAIN.revoke(f["file_id"], grantee)  # None = already inactive (retry-safe skip)
            if tx:
                last_tx, revoked = tx, revoked + 1
        except Exception:
            errors += 1
    if errors:
        # Fail closed: keep the share row (and any un-revoked batch mapping) so the
        # owner can see it and retry. Batch roots already revoked and per-file grants
        # already inactive are skipped on retry — it can never brick on prior successes.
        raise HTTPException(status_code=502,
                            detail=f"On-chain revoke failed ({errors} error(s)) — share kept; retry")
    supa.delete_share(token, node_id, grantee)
    return {"ok": True, "files_revoked": revoked, "files_covered": len(files), "tx": last_tx}


# --- share / download -------------------------------------------------------

def _parse_window(starts_at: str | None, expires_at: str | None) -> tuple[int, int]:
    """Parse the share dialog's start/expiry (unix-second strings; blank = unbounded)
    into (not_before, not_after) for the on-chain window. Rejects a non-positive or
    ill-ordered window, and an expiry already in the past (which would anchor a grant
    that can never verify). The frontend sends epoch seconds computed from the local
    datetime-local value, so no server-side timezone guessing."""
    def _one(v: str | None) -> int:
        if v is None or str(v).strip() == "":
            return 0
        try:
            n = int(float(v))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid start/expiry time")
        if n < 0:
            raise HTTPException(status_code=400, detail="Start/expiry time cannot be negative")
        return n
    nb, na = _one(starts_at), _one(expires_at)
    if nb and na and nb >= na:
        raise HTTPException(status_code=400, detail="The start time must be before the expiry")
    if na and na <= int(time.time()):
        raise HTTPException(status_code=400, detail="The expiry time is already in the past")
    return nb, na


@app.post("/api/share")
async def share(request: Request, node_id: str = Form(...),
                grantee: str = Form(None), email: str = Form(None),
                share_type: str = Form("download"),
                starts_at: str = Form(None), expires_at: str = Form(None)):
    """Share an item. Provide either `grantee` (a user id picked from typeahead) or
    `email`. An email that already has a Xinsere account resolves to an internal
    share (granted now); an email with no account yet becomes a pending invite that
    materializes when they join — external sharing + viral onboarding.

    `share_type` (0016): `download` = view + download (default, today's behavior);
    `view` = browser preview only — the download endpoints refuse, and the typed
    Merkle leaf binds the level on-chain. `co-owner` is reserved, not yet accepted.

    `starts_at`/`expires_at` (0020, unix seconds; blank = unbounded) anchor a validity
    WINDOW on-chain (grantBatchWindowed). Start defaults to immediate, expiry to
    perpetual; the contract's verifyBatch fails closed outside the window, so an
    end-dated share ends with no revoke tx."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    if share_type not in ("view", "download", "co-owner"):
        raise HTTPException(status_code=400, detail="share_type must be view, download or co-owner")
    not_before, not_after = _parse_window(starts_at, expires_at)
    node = supa.get_node(token, node_id)
    if not node:
        raise HTTPException(status_code=403, detail="You can only share items you can access")
    if node["owner"] != uid:
        # Co-owners may re-share (0016): a co-owner grant on the node or any ancestor.
        covering = supa.shares_covering(token, node_id)
        if not any(sh["grantee"] == uid and sh.get("share_type") == "co-owner"
                   for sh in covering):
            raise HTTPException(status_code=403,
                                detail="Only the owner or a co-owner can share this")

    if not grantee and email:
        addr = email.strip().lower()
        prof = supa.get_profile(token, uid) or {}
        if addr == (prof.get("email") or "").lower():
            raise HTTPException(status_code=400, detail="You can't share with yourself")
        target = supa.profile_by_email(token, addr)
        if target:
            grantee = target["id"]          # existing account -> grant now (below)
        else:
            # pending_shares is RLS deny-by-default (service-role only, per 0006);
            # the caller is already authorized (owner check above), so the stub
            # write must use the service-role key, not the user's token.
            if not supa.SERVICE_ROLE_KEY:
                raise HTTPException(status_code=500, detail="Service role key not configured")
            supa.insert_pending_share(supa.SERVICE_ROLE_KEY, node_id, addr, uid,
                                      share_type)  # no gas
            return {"ok": True, "invited": True, "email": addr, "share_type": share_type,
                    "message": "Invitation created — they'll get access as soon as they join Xinsere."}

    if not grantee:
        raise HTTPException(status_code=400, detail="Pick a person or enter an email")
    # Multi-grantee shares (comma-separated): one request, one wait — the chain
    # still anchors per-grantee roots so unshare stays exact per person.
    targets = [g.strip() for g in grantee.split(",") if g.strip()]
    for t in targets:
        # Existence check on the SERVICE plane: profiles SELECT is self-only
        # since 0010, so reading another user's row with the caller's token
        # always comes back empty — which made every typeahead-picked recipient
        # "unknown". Nothing from the row is returned to the caller; the
        # typeahead RPC already scoped who they can find.
        if t == uid or supa.get_profile(supa.SERVICE_ROLE_KEY or token, t) is None:
            raise HTTPException(status_code=400, detail="Unknown recipient")

    # Finding 2 defense-in-depth before spending gas: cap the per-user share rate
    # (stops a drain loop) and refuse up front if the shared wallet is depleted.
    share_quota.enforce_share_rate(uid)
    _wallet_guard()

    # Batched on-chain grant (Finding 2): one flat-gas Merkle root per <=1,000 files
    # instead of one tx per file — a folder share can no longer drain the shared gas
    # wallet. The root(s) are recorded under (node, grantee) so unshare revokes them.
    svc = supa.SERVICE_ROLE_KEY
    if not svc:
        raise HTTPException(status_code=500, detail="Service role key not configured")
    files = supa.files_under(token, node_id)
    existing = {sh["grantee"]: (sh.get("share_type") or "download")
                for sh in supa.shares_for_node(token, node_id)}
    pmap = _profiles_map(token)
    results, granted_ok = [], 0
    for t in targets:
        # Level change on an existing share (0016): revoke the OLD level's grants
        # before the new ones anchor — fail closed per person, keep processing rest.
        try:
            if t in existing and existing[t] != share_type:
                rev = share_grants.revoke_share(svc, node_id, t)
                errors = rev["errors"]
                for f in files:   # legacy per-file grants (pre-batch shares)
                    try:
                        CHAIN.revoke(f["file_id"], t)
                    except Exception:
                        errors += 1
                if errors:
                    raise RuntimeError("previous level revoke failed")
            res = share_grants.grant_share(svc, files, t, node_id, "share", share_type,
                                           not_before=not_before, not_after=not_after)
            last_tx = res.tx_hashes[-1] if res and res.tx_hashes else None
            supa.insert_share(svc, node_id, t, last_tx, share_type,
                              not_before=not_before, not_after=not_after)
            granted_ok += 1
            results.append({"ok": True, "grantee": _public(pmap.get(t, {"id": t})), "tx": last_tx})
        except Exception as exc:
            logging.getLogger("xinsere.app").warning(
                "share grant failed node=%s grantee=%s: %s", node_id, t, exc)
            results.append({"ok": False, "grantee": _public(pmap.get(t, {"id": t})),
                            "error": "on-chain grant failed — retry"})
    if not granted_ok:
        raise HTTPException(status_code=502,
                            detail="On-chain grant failed [chain_grant_failed] — retry")
    first = next(r for r in results if r["ok"])
    return {"ok": True, "grantee": first["grantee"], "tx": first["tx"],
            "results": results, "granted": granted_ok, "failed": len(results) - granted_ok,
            "files_granted": len(files), "share_type": share_type,
            "not_before": not_before, "not_after": not_after,
            "cascade": node["type"] == "folder"}


_LEVEL_RANK = {"view": 1, "download": 2, "co-owner": 2}


def _has_access(file_id: str, uid: str) -> tuple[bool, str, str]:
    """Authoritative, FAIL-CLOSED access gate. Returns (allowed, source, level)
    where level is 'download' or 'view' (0016).

    1. Per-file on-chain grant (interactive shares, owner self-grants) —
       CHAIN.verify(). Untyped by construction => download level.
    2. Merkle batch fallback — replay a cached proof through the contract's
       verifyBatch. The LEVEL is bound into the leaf: we recompute the expected
       leaf from the row's CLAIMED grant_type before replaying, so a DB-flipped
       type can never verify. A download-typed hit wins immediately; a view-typed
       hit is kept in case no download grant exists.

    Any error or miss returns False — corruption or an outage can only ever block a
    legitimate user, never expose a file."""
    try:
        has, _ = CHAIN.verify(file_id, uid)
        if has:
            return True, "amoy-contract", "download"
    except Exception:
        logging.getLogger("xinsere.app").warning("per-file verify() failed file=%s uid=%s", file_id, uid)
    # Batch fallback: try recent cached proofs; the chain check is what actually grants.
    view_hit = None
    try:
        import chain as _chain
        import merkle as _merkle
        fh, gh = _chain.file_hash(file_id), _chain.grantee_hash(uid)
        for bg in supa.batch_grants_for(supa.SERVICE_ROLE_KEY, file_id, uid):
            gtype = bg.get("grant_type") or "download"
            expected = _merkle.leaf_typed(fh, gh, gtype)
            if bg["leaf"].lower() != _merkle.hx(expected).lower():
                continue   # cached row inconsistent with its claimed type — ignore it
            leaf = bytes.fromhex(bg["leaf"][2:])
            root = bytes.fromhex(bg["merkle_root"][2:])
            proof = [bytes.fromhex(p[2:]) for p in bg["proof"]]
            if CHAIN.verify_batch(leaf, root, proof):
                if gtype != "view":
                    return True, "amoy-batch", "download"
                view_hit = (True, "amoy-batch", "view")
    except Exception:
        logging.getLogger("xinsere.app").warning("batch verify failed file=%s uid=%s", file_id, uid)
    if view_hit:
        return view_hit
    return False, "none", "none"


def _authorize(node: dict, uid: str, need: str = "download") -> tuple[bool, str, str]:
    """Access decision for a file node at the required level ('download' or 'view').
    Brand promise: EVERYONE is verified on-chain — the owner is NOT bypassed; they
    hold an on-chain self-grant like any grantee. The owner is only ever let through
    as a logged FALLBACK if no grant has been anchored yet (e.g. a fresh upload
    before its grant lands), so an owner is never locked out of their own file, but
    the default, expected path is an on-chain verify even for them."""
    allowed, source, level = _has_access(node["file_id"], uid)
    if allowed and _LEVEL_RANK.get(level, 0) >= _LEVEL_RANK.get(need, 2):
        return True, source, level
    if node["owner"] == uid:
        logging.getLogger("xinsere.app").info(
            "owner on-chain grant missing — allowing via fallback file=%s", node["file_id"])
        return True, "owner-fallback", "download"
    if allowed:   # has SOME access, just not at the required level (view-only)
        return False, source, level
    return False, "none", "none"


def _wm_enabled(owner_uid: str) -> bool:
    """Org override for forensic watermarking (0017). Keyed off the FILE OWNER's
    org membership; multi-org users mark if ANY org requires it; users with no
    org (or any lookup failure, or pre-0017) FAIL TOWARD MARKING — the override
    can only ever relax, never silently disable by accident."""
    svc = supa.SERVICE_ROLE_KEY
    if not svc:
        return True
    try:
        mems = supa._rest("GET", "/org_members", svc,
                          params={"user_id": f"eq.{owner_uid}", "select": "org_id"}) or []
        ids = [m["org_id"] for m in mems]
        if not ids:
            return True
        orgs_rows = supa._rest("GET", "/organizations", svc,
                               params={"id": f"in.({','.join(ids)})",
                                       "select": "watermark_downloads"}) or []
        if not orgs_rows:
            return True
        return any(o.get("watermark_downloads", True) for o in orgs_rows)
    except Exception:
        return True


def _record_access(node: dict, uid: str, action: str) -> dict | None:
    """Interactive-plane access telemetry into the tamper-evident access_log
    (0005/0014) — same ground truth the machine API writes. Fail-open by design.
    Returns the entry (its entry_hash seeds the forensic watermark)."""
    try:
        import access_log
        return access_log.record(org_id=None, actor_id=uid, actor_type="user",
                                 action=action, file_id=node.get("file_id"),
                                 node_id=node.get("id"), bytes=node.get("size") or 0)
    except Exception:
        return None


# Content types the in-browser viewer will render inline. HTML/SVG are the XSS
# vectors of user-uploaded content: HTML is never rendered (re-served as plain
# text), SVG gets a script-neutering CSP sandbox. Everything else falls back to
# "no preview" rather than guessing.
_PREVIEW_SAFE_PREFIXES = ("image/", "video/", "audio/")
_PREVIEW_TEXT_TYPES = ("text/plain", "text/csv", "text/markdown", "application/json",
                       "text/html", "application/xml", "text/xml")


@app.get("/api/preview/{node_id}")
async def preview(request: Request, node_id: str):
    """Server-mediated in-browser viewer — the ONLY retrieval path a `view`-level
    grant can pass (0016). The file is reassembled server-side and streamed
    inline: the client never receives fragment URLs or data keys, so a view-only
    grantee has no bulk/API download path. (What a browser can display can always
    be screen-captured — `view` prevents key handover and file egress, it is not
    DRM.) Download-level users get the same endpoint for previews."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    allowed, _, level = _authorize(node, uid, need="view")
    if not allowed:
        raise HTTPException(status_code=403, detail="No active on-chain grant for you")

    ctype = (node.get("content_type") or "application/octet-stream").split(";")[0].strip().lower()
    is_svg = ctype == "image/svg+xml"
    if ctype in _PREVIEW_TEXT_TYPES:
        serve_type = "text/plain; charset=utf-8"     # HTML/JSON/XML render as text, never execute
    elif is_svg or any(ctype.startswith(p) for p in _PREVIEW_SAFE_PREFIXES):
        serve_type = ctype
    elif ctype == "application/pdf":
        serve_type = ctype
    else:
        raise HTTPException(status_code=415, detail="No in-browser preview for this file type")

    try:
        r = get_pipeline().retrieve(node["file_id"])
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    entry = _record_access(node, uid, "file.view")

    content = r.content
    # Large raster images: serve a downscaled rendition. A 10 MB camera JPEG is
    # ~30x the bytes a screen needs, and preview buffers fully before first byte —
    # this is why images felt slow next to small PDFs. The ORIGINAL stays
    # bit-perfect for download; only the transient view copy is resized.
    if (ctype.startswith("image/") and not is_svg and ctype != "image/gif"
            and len(content) > 1_000_000):
        try:
            from PIL import Image, ImageOps
            img = Image.open(io.BytesIO(content))
            img = ImageOps.exif_transpose(img)
            img.thumbnail((2048, 2048))
            out = io.BytesIO()
            if img.mode in ("RGBA", "LA", "P"):
                img.save(out, "PNG", optimize=True)
                serve_type = "image/png"
            else:
                img.save(out, "JPEG", quality=82, progressive=True)
                serve_type = "image/jpeg"
            content = out.getvalue()
        except Exception:   # Pillow missing or unreadable image — serve the original
            pass

    # Invisible forensic mark — EVERY view, owners included (Mark, 2026-07-15:
    # "no one escapes — not IT admins, not users, not superadmins"). Creating a
    # file doesn't exempt its creator from the audit trail; an owner-shaped hole
    # is still a hole. The embedded ID is the viewer's tamper-evident access_log
    # entry, so an auditor can trace a leaked copy to who viewed it and when.
    # Design doc: forensic-watermarking-design.
    watermarked = False
    if entry and _wm_enabled(node["owner"]):
        import watermark
        content, serve_type, watermarked = watermark.apply(
            content, serve_type, entry.get("entry_hash", ""))

    headers = {
        "Content-Disposition": f'inline; filename="{node["name"]}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
        "X-Integrity": "verified-bit-perfect",
        "X-Watermarked": "true" if watermarked else "false",
    }
    if is_svg:   # neuter scripts if the SVG is opened as a document
        headers["Content-Security-Policy"] = "sandbox; script-src 'none'"
    return StreamingResponse(io.BytesIO(content), media_type=serve_type, headers=headers)


@app.get("/api/verify/{node_id}")
async def verify_access(request: Request, node_id: str):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    allowed, source, level = _authorize(node, uid, need="view")
    return {"allowed": allowed, "source": source, "level": level,
            "can_download": allowed and level == "download",
            "contract": __import__("chain").CONTRACT}


@app.get("/api/download-plan/{node_id}")
async def download_plan(request: Request, node_id: str):
    """Client-side reassembly: return per-fragment presigned GET URLs + unwrapped
    data keys/nonces so the browser fetches fragments straight from S3 and
    decrypts locally — the plaintext never exists on this server. Same permission
    gate as /api/download; keys are per-fragment data keys only (never KMS/CMK),
    URLs are single-object with a short TTL. 501 if the backend can't presign
    (local dev) — the client falls back to server-side download."""
    import base64
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    allowed, _, level = _authorize(node, uid, need="download")
    if not allowed:
        raise HTTPException(status_code=403,
                            detail="Your access is view-only — ask the owner for download access"
                            if level == "view" else "No active on-chain grant for you")
    if _wm_enabled(node["owner"]):
        # Watermarked downloads are universal — owners included (Mark, 2026-07-15).
        # The forensic mark can only be embedded server-side, and client-side
        # reassembly delivers the bit-perfect original, so issuing a plan would be
        # an unmarked, untraceable copy for anyone. 501 makes the client fall back
        # to /api/download. Orgs that explicitly opted out of marking (0017) keep
        # the fast in-browser path — for every role equally.
        raise HTTPException(status_code=501, detail="Server-mediated download (forensic marking)")
    _record_access(node, uid, "file.download_plan")
    try:
        # 30 min TTL: a retried/slow transfer must not see its fragment URLs
        # expire mid-download (an expired URL 403s on the Range resume).
        plan = get_pipeline().retrieval_plan(node["file_id"], url_ttl=1800)
    except NotImplementedError:
        raise HTTPException(status_code=501, detail="Client-side reassembly unavailable")
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    return {
        "name": node["name"],
        "content_type": plan["content_type"],
        "size": plan["size"],
        "sha256": plan["file_sha256"],
        "fragments": [
            {"sequence": f["sequence"], "url": f["url"],
             "key": base64.b64encode(f["key"]).decode(),
             "nonce": base64.b64encode(f["nonce"]).decode()}
            for f in plan["fragments"]
        ],
    }


@app.post("/api/client-log")
async def client_log(request: Request):
    """Client-side transfer diagnostics sink. Fragment fetches go browser->S3
    directly, so the server never sees their failures — the client reports them
    here and they land in the platform logs for diagnosis. Auth required; body
    truncated; nothing sensitive is logged (no keys, no URLs with signatures)."""
    s = _session(request)
    body = (await request.body())[:4000]
    import logging
    logging.getLogger("xinsere.client").warning(
        "client-diag user=%s %s", s["user_id"], body.decode("utf-8", "replace"))
    return {"ok": True}


@app.get("/api/download/{node_id}")
async def download(request: Request, node_id: str):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    # Authoritative permission check reads the BLOCKCHAIN for EVERYONE (owner included).
    allowed, _, level = _authorize(node, uid, need="download")
    if not allowed:
        raise HTTPException(status_code=403,
                            detail="Your access is view-only — ask the owner for download access"
                            if level == "view" else "No active on-chain grant for you")
    entry = _record_access(node, uid, "file.download")
    try:
        r = get_pipeline().retrieve(node["file_id"])
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")

    # Forensic mark on EVERY download, owners included (Mark, 2026-07-15: universal
    # audit is the brand promise — no role escapes, or the audit trail has a
    # creator-shaped blank). The delivered copy embeds this access's on-chain-logged
    # ID, so a leaked file traces to whoever pulled it. The response hash is the
    # DELIVERED copy's hash — attribution over frozen-hash. Bit-perfect originals
    # remain retrievable only for platform audit via the stored fragments.
    content, marked = r.content, False
    if entry and _wm_enabled(node["owner"]):
        import watermark
        content, _, marked = watermark.apply(
            content, r.content_type or "application/octet-stream",
            entry.get("entry_hash", ""))
    import hashlib as _hashlib
    delivered_sha = _hashlib.sha256(content).hexdigest() if marked else node.get("sha", "")

    t = r.timings or {}
    # Compact per-stage breakdown, visible in the browser Network tab (and logged
    # server-side in full). Handy for the perf pass: shows S3-vs-KMS split.
    timing_hdr = (f"total={t.get('total_ms')}ms index={t.get('index_ms')}ms "
                  f"fetch+decrypt={t.get('fetch_decrypt_ms')}ms "
                  f"s3max={t.get('s3_get', {}).get('max')}ms "
                  f"kmsmax={t.get('kms_decrypt', {}).get('max')}ms "
                  f"verify={t.get('verify_sha_ms')}ms workers={t.get('workers')}")
    return StreamingResponse(
        io.BytesIO(content),
        media_type=r.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            "X-Content-SHA256": delivered_sha,
            "X-Watermarked": "true" if marked else "false",
            "X-Integrity": "forensically-marked" if marked else "verified-bit-perfect",
            "X-Retrieve-Timing": timing_hdr,
            "Access-Control-Expose-Headers": "X-Content-SHA256, X-Integrity, X-Retrieve-Timing",
        },
    )


@app.get("/api/download-folder/{node_id}")
async def download_folder(request: Request, node_id: str):
    """ZIP a folder. Each file passes the same on-chain download gate; files the
    caller can't download (view-only) are skipped, not leaked. Non-owner copies
    carry the per-access forensic mark, same as single-file downloads."""
    import hashlib as _hashlib
    import zipfile
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "folder":
        raise HTTPException(status_code=404, detail="Folder not found")
    # Path-aware walk so the ZIP preserves the folder structure (a flat namelist
    # collides on duplicate names in different subfolders).
    files: list[tuple[str, dict]] = []

    def _walk(fid: str, rel: str) -> None:
        for c in supa.children(token, fid):
            if c["type"] == "folder":
                _walk(c["id"], f"{rel}{c['name']}/")
            elif c.get("file_id"):
                files.append((rel + c["name"], c))

    _walk(node_id, "")
    if not files:
        raise HTTPException(status_code=404, detail="Folder is empty")
    buf = io.BytesIO()
    added = skipped = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for relpath, f in files:
            allowed, _, _ = _authorize(f, uid, need="download")
            if not allowed:
                skipped += 1
                continue
            try:
                r = get_pipeline().retrieve(f["file_id"])
            except Exception:
                skipped += 1
                continue
            content = r.content
            # Universal forensic mark (Mark, 2026-07-15) — owners' copies in a
            # folder ZIP are marked exactly like everyone else's.
            entry = _record_access(f, uid, "file.download")
            if entry and _wm_enabled(f["owner"]):
                import watermark
                content, _, _ = watermark.apply(
                    content, f.get("content_type") or "application/octet-stream",
                    entry.get("entry_hash", ""))
            z.writestr(relpath, content)
            added += 1
    if not added:
        raise HTTPException(status_code=403, detail="No downloadable files in this folder")
    data = buf.getvalue()
    return StreamingResponse(io.BytesIO(data), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{node["name"]}.zip"',
        "X-Files-Included": str(added), "X-Files-Skipped": str(skipped),
        "X-Content-SHA256": _hashlib.sha256(data).hexdigest(),
    })


# --- routers: machine API, admin console, gated docs -------------------------
# Imported here (not at the top) because v1.py's delete path reuses
# _erase_subtree from this module — importing after it is defined keeps the
# dependency one-way at import time.
import v1 as _v1            # noqa: E402
import admin as _admin      # noqa: E402
import account as _account  # noqa: E402
import docs_site as _docs   # noqa: E402

app.include_router(_v1.router)
app.include_router(_admin.router)
app.include_router(_account.router)
app.include_router(_docs.router)


@app.exception_handler(HTTPException)
async def http_exc(_request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exc(_request: Request, exc: RequestValidationError):
    """Unify the error contract: FastAPI's default 422 body is {detail:[…]}, which
    breaks clients that expect our {error} shape everywhere else (audit finding 5 /
    integrator feedback #4). Return a single readable message + the structured list."""
    errs = exc.errors()
    first = errs[0] if errs else {}
    loc = ".".join(str(p) for p in first.get("loc", []) if p not in ("body", "query"))
    msg = f"{loc}: {first.get('msg')}" if loc else (first.get("msg") or "Invalid request")
    return JSONResponse(status_code=422, content={"error": msg, "errors": errs})


@app.exception_handler(supa.SupabaseError)
async def supabase_exc(request: Request, exc: supa.SupabaseError):
    """A database call failed mid-request (e.g. a missing table/column from an
    unapplied migration — the 2026-07-15 unshare 500). Every write path here is
    fail-closed, so nothing was half-committed the user must worry about; give
    them a readable, retryable message instead of a raw 500. Detail goes to the
    log only — schema internals never leave the server."""
    import logging
    logging.getLogger("xinsere.app").error(
        "supabase error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=502, content={
        "error": "A database step failed, so the action was not completed — "
                 "nothing was changed. Retry in a moment. [db_error]"})


@app.exception_handler(supa.PathTooDeepError)
async def path_too_deep(_request: Request, exc: supa.PathTooDeepError):
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(Exception)
async def all_exc(_request: Request, exc: Exception):
    # Always log the real error server-side.
    import logging
    import traceback
    logging.getLogger("xinsere.app").error("unhandled: %s", traceback.format_exc()[-2000:])
    # Debug traces are a diagnostic aid only — never leak them from production
    # unless explicitly forced (audit finding 4).
    debug = os.environ.get("XINSERE_DEBUG_ERRORS") == "1" and (
        not config.is_production() or os.environ.get("XINSERE_DEBUG_ERRORS_FORCE") == "1")
    if debug:
        return JSONResponse(status_code=500, content={
            "error": str(exc), "type": type(exc).__name__,
            "trace": traceback.format_exc()[-1800:]})
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
