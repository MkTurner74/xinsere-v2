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
            {**_public(pmap[s["grantee"]]), "tx": s["tx"]}
            for s in shares if s["grantee"] in pmap
        ]
    return v


# --- pages ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    with open(os.path.join(_HERE, "frontend", "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/xinsere-client.js")
def client_js() -> HTMLResponse:
    with open(os.path.join(_HERE, "frontend", "xinsere-client.js"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), media_type="application/javascript")


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
    sess = supa.session_from_grant(grant)
    request.session["sb"] = sess
    supa.ensure_root(sess["access_token"], sess["user_id"])
    prof = supa.get_profile(sess["access_token"], sess["user_id"]) or {"id": sess["user_id"]}
    _reconcile_pending(sess["user_id"], (prof or {}).get("email") or identifier.strip().lower())
    return {"ok": True, "user": _public(prof)}


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
                share_grants.grant_share(svc, [file_node], sh["grantee"], sh["node_id"], "grant-on-add")
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
        try:
            files = supa.files_under(svc, node_id)
            last_tx = None
            try:
                res = share_grants.grant_share(svc, files, user_id, node_id, "reconcile-invite")
                last_tx = res.tx_hashes[-1] if res and res.tx_hashes else None
            except Exception as exc:
                logging.getLogger("xinsere.app").warning(
                    "pending-share grant failed node=%s grantee=%s: %s", node_id, user_id, exc)
            supa.insert_share(svc, node_id, user_id, last_tx)
            supa.delete_pending_share(svc, p["id"])
            done += 1
        except Exception as exc:
            logging.getLogger("xinsere.app").warning(
                "pending-share reconcile failed node=%s email=%s: %s", node_id, email, exc)
    return {"materialized": done}


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
    return {"user": _public(prof), "others": others,
            "admin": is_platform_admin(uid, prof)}


# --- tree -------------------------------------------------------------------

@app.get("/api/tree")
async def tree(request: Request, folder: str = ""):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    folder_id = folder or supa.ensure_root(token, uid)
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
    return {"folder": node_view(node, uid, token, pmap), "breadcrumbs": crumbs, "children": kids}


@app.get("/api/shared")
async def shared(request: Request):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    pmap = _profiles_map(token)
    items = [node_view(n, uid, token, pmap) for n in supa.shared_with(token, uid)]
    return {"children": items}


@app.post("/api/folder")
async def make_folder(request: Request, name: str = Form(...), parent: str = Form(...)):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    parent_node = supa.get_node(token, parent)
    if not parent_node or parent_node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only add folders to your own files")
    node = supa.insert_folder(token, name.strip() or "New folder", parent, uid)
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

@app.post("/api/rename")
async def rename(request: Request, node_id: str = Form(...), name: str = Form(...)):
    """Display-name only — fragment names carry no filename linkage, so this
    never touches storage or the chain."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only rename your own items")
    clean = name.strip()
    if not clean:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    updated = supa.rename_node(token, node_id, clean)
    return node_view(updated, uid, token, _profiles_map(token))


@app.post("/api/move")
async def move(request: Request, node_id: str = Form(...), new_parent: str = Form(...)):
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

    # Inherited-share reconciliation: moving between differently-shared folders
    # changes which ancestor folder-shares cover this subtree. Batched (Finding 2):
    # instead of a per-file grant/revoke storm, we RE-ANCHOR each affected ancestor
    # share over its CURRENT subtree — after the move, files_under(share_node)
    # naturally includes (gained) or excludes (lost) the moved subtree, so a single
    # revoke+re-grant per (share_node, grantee) restores the correct grant set.
    # Tracked as (share_node, grantee) pairs so we reanchor the right root.
    before = {(sh["node_id"], sh["grantee"]) for sh in supa.shares_covering(token, node_id)}
    updated = supa.move_node(token, node_id, new_parent)
    after = {(sh["node_id"], sh["grantee"]) for sh in supa.shares_covering(token, node_id)}
    rec = {"reanchored": 0, "revoked": 0, "errors": 0}
    changed = before ^ after   # shares this subtree gained or lost by moving
    svc = supa.SERVICE_ROLE_KEY
    if changed and svc:
        for share_node, g in changed:
            try:
                files = supa.files_under(svc, share_node)
                r = share_grants.reanchor_share(svc, share_node, g, files, "move")
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
    # a no-op for files that carry only a batch grant.
    for f in files:
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

@app.post("/api/share")
async def share(request: Request, node_id: str = Form(...),
                grantee: str = Form(None), email: str = Form(None)):
    """Share an item. Provide either `grantee` (a user id picked from typeahead) or
    `email`. An email that already has a Xinsere account resolves to an internal
    share (granted now); an email with no account yet becomes a pending invite that
    materializes when they join — external sharing + viral onboarding."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only share your own items")

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
            supa.insert_pending_share(supa.SERVICE_ROLE_KEY, node_id, addr, uid)  # no gas
            return {"ok": True, "invited": True, "email": addr,
                    "message": "Invitation created — they'll get access as soon as they join Xinsere."}

    if not grantee:
        raise HTTPException(status_code=400, detail="Pick a person or enter an email")
    if grantee == uid or supa.get_profile(token, grantee) is None:
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
    last_tx = None
    try:
        res = share_grants.grant_share(svc, files, grantee, node_id, "share")
        last_tx = res.tx_hashes[-1] if res and res.tx_hashes else None
    except Exception as exc:
        logging.getLogger("xinsere.app").warning(
            "share on-chain grant failed node=%s grantee=%s: %s", node_id, grantee, exc)
        raise HTTPException(status_code=502,
                            detail="On-chain grant failed [chain_grant_failed] — retry")

    rec = supa.insert_share(token, node_id, grantee, last_tx)
    pmap = _profiles_map(token)
    return {"ok": True, "grantee": _public(pmap.get(grantee, {"id": grantee})),
            "tx": rec.get("tx"), "files_granted": len(files),
            "cascade": node["type"] == "folder"}


def _has_access(file_id: str, uid: str) -> tuple[bool, str]:
    """Authoritative, FAIL-CLOSED download gate. Returns (allowed, source).

    1. Per-file on-chain grant (interactive shares) — CHAIN.verify().
    2. Merkle batch fallback (bulk-migrated permissions) — replay a cached proof
       through the contract's verifyBatch. The on-chain root is the authority; the
       cache is only a hint, and an unanchored/revoked root fails closed there.

    Any error or miss returns False — corruption or an outage can only ever block a
    legitimate user, never expose a file."""
    try:
        has, _ = CHAIN.verify(file_id, uid)
        if has:
            return True, "amoy-contract"
    except Exception:
        logging.getLogger("xinsere.app").warning("per-file verify() failed file=%s uid=%s", file_id, uid)
    # Batch fallback: try recent cached proofs; the chain check is what actually grants.
    try:
        for bg in supa.batch_grants_for(supa.SERVICE_ROLE_KEY, file_id, uid):
            leaf = bytes.fromhex(bg["leaf"][2:])
            root = bytes.fromhex(bg["merkle_root"][2:])
            proof = [bytes.fromhex(p[2:]) for p in bg["proof"]]
            if CHAIN.verify_batch(leaf, root, proof):
                return True, "amoy-batch"
    except Exception:
        logging.getLogger("xinsere.app").warning("batch verify failed file=%s uid=%s", file_id, uid)
    return False, "none"


def _authorize(node: dict, uid: str) -> tuple[bool, str]:
    """Access decision for a file node. Brand promise: EVERYONE is verified on-chain —
    the owner is NOT bypassed; they hold an on-chain self-grant like any grantee. The
    owner is only ever let through as a logged FALLBACK if no grant has been anchored yet
    (e.g. a fresh upload before its grant lands), so an owner is never locked out of their
    own file, but the default, expected path is an on-chain verify even for them."""
    allowed, source = _has_access(node["file_id"], uid)
    if allowed:
        return True, source
    if node["owner"] == uid:
        logging.getLogger("xinsere.app").info(
            "owner on-chain grant missing — allowing via fallback file=%s", node["file_id"])
        return True, "owner-fallback"
    return False, "none"


@app.get("/api/verify/{node_id}")
async def verify_access(request: Request, node_id: str):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    allowed, source = _authorize(node, uid)  # owner verified on-chain too (no bypass)
    import chain as _chain
    return {"allowed": allowed, "source": source, "contract": _chain.CONTRACT}


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
    allowed, _ = _authorize(node, uid)   # owner verified on-chain too (no bypass)
    if not allowed:
        raise HTTPException(status_code=403, detail="No active on-chain grant for you")
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
    allowed, _ = _authorize(node, uid)
    if not allowed:
        raise HTTPException(status_code=403, detail="No active on-chain grant for you")
    try:
        r = get_pipeline().retrieve(node["file_id"])
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    t = r.timings or {}
    # Compact per-stage breakdown, visible in the browser Network tab (and logged
    # server-side in full). Handy for the perf pass: shows S3-vs-KMS split.
    timing_hdr = (f"total={t.get('total_ms')}ms index={t.get('index_ms')}ms "
                  f"fetch+decrypt={t.get('fetch_decrypt_ms')}ms "
                  f"s3max={t.get('s3_get', {}).get('max')}ms "
                  f"kmsmax={t.get('kms_decrypt', {}).get('max')}ms "
                  f"verify={t.get('verify_sha_ms')}ms workers={t.get('workers')}")
    return StreamingResponse(
        io.BytesIO(r.content),
        media_type=r.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            "X-Content-SHA256": node.get("sha", ""),
            "X-Integrity": "verified-bit-perfect",
            "X-Retrieve-Timing": timing_hdr,
            "Access-Control-Expose-Headers": "X-Content-SHA256, X-Integrity, X-Retrieve-Timing",
        },
    )


# --- routers: machine API, admin console, gated docs -------------------------
# Imported here (not at the top) because v1.py's delete path reuses
# _erase_subtree from this module — importing after it is defined keeps the
# dependency one-way at import time.
import v1 as _v1            # noqa: E402
import admin as _admin      # noqa: E402
import docs_site as _docs   # noqa: E402

app.include_router(_v1.router)
app.include_router(_admin.router)
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
