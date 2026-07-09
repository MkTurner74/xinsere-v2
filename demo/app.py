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
import os
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.datastructures import UploadFile
from starlette.middleware.sessions import SessionMiddleware

import supa
from authn import session as _session, ADMIN_EMAILS
from chain import CHAIN
from store import (get_pipeline, XinsereIntegrityError, presign_put, staged_size,
                   read_staged, delete_staged, MAX_INLINE_BYTES)

_HERE = os.path.dirname(os.path.abspath(__file__))
SESSION_SECRET = os.environ.get("XINSERE_SESSION_SECRET", "xinsere-demo-dev-secret")
# Public docs are OFF — the gated docs site (docs_site.py) re-exposes /docs,
# /docs/guide and /openapi.json to signed-in users only.
app = FastAPI(title="Xinsere", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=60 * 60 * 8,
                   https_only=os.environ.get("XINSERE_HTTPS_ONLY", "").lower() == "true")

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
    return {"ok": True, "user": _public(prof)}


@app.post("/api/signup")
async def signup(request: Request, email: str = Form(...), password: str = Form(...),
                 name: str = Form(...)):
    try:
        res = supa.sign_up(email.strip().lower(), password, name.strip())
    except supa.SupabaseError as exc:
        raise HTTPException(status_code=400, detail=exc.detail or "Sign-up failed")
    # With email confirmation on, no session is returned until the user confirms.
    if res.get("access_token"):
        sess = supa.session_from_grant(res)
        request.session["sb"] = sess
        supa.ensure_root(sess["access_token"], sess["user_id"])
        prof = supa.get_profile(sess["access_token"], sess["user_id"]) or {"id": sess["user_id"]}
        return {"ok": True, "user": _public(prof)}
    return {"ok": True, "needs_confirmation": True,
            "message": "Check your email to confirm your account, then sign in."}


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


def _grant_inherited(token: str, node_id: str, file_id: str) -> int:
    """Grant-on-add: a file added to a folder that is already shared must be
    readable by the existing grantees — the on-chain contract is per-file, so
    each inherited share needs its own grant tx. Best-effort: a chain failure
    must not fail the upload (RLS already lets grantees SEE the file; the grant
    governs download, and a re-share repairs it)."""
    granted = 0
    try:
        grantees = {sh["grantee"] for sh in supa.shares_covering(token, node_id)}
        for g in grantees:
            try:
                CHAIN.grant(file_id, g, "read")
                granted += 1
            except Exception as exc:
                import logging
                logging.getLogger("xinsere.app").warning(
                    "grant-on-add failed node=%s grantee=%s: %s", node_id, g, exc)
    except Exception:
        pass
    return granted


@app.post("/api/admin/invite")
async def admin_invite(request: Request, email: str = Form(...), name: str = Form(...)):
    """Invite a user (public signup is disabled). Admin-only: the signed-in
    caller's profile email must be in XINSERE_ADMIN_EMAILS. Generates a strong
    password and returns it ONCE — forward it privately."""
    import secrets as _secrets
    s = _session(request)
    prof = supa.get_profile(s["access_token"], s["user_id"]) or {}
    if (prof.get("email") or "").lower() not in ADMIN_EMAILS:
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
    return {"user": _public(prof), "others": others}


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
    if size > MAX_INLINE_BYTES:
        delete_staged(key)
        raise HTTPException(status_code=413,
                            detail=f"File too large to process here ({size} bytes); limit is {MAX_INLINE_BYTES}")
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

    # Inherited-share reconciliation: the contract is per-file, so moving between
    # differently-shared folders must revoke grants the file leaves behind and
    # add the ones it gains (direct shares on the node itself always survive).
    before = {sh["grantee"] for sh in supa.shares_covering(token, node_id)}
    updated = supa.move_node(token, node_id, new_parent)
    after = {sh["grantee"] for sh in supa.shares_covering(token, node_id)}
    rec = {"granted": 0, "revoked": 0, "errors": 0}
    if before != after:
        files = supa.files_under(token, node_id)
        for f in files:
            for g in after - before:
                try:
                    CHAIN.grant(f["file_id"], g, "read")
                    rec["granted"] += 1
                except Exception:
                    rec["errors"] += 1   # fail-closed: no grant -> no download for them
            for g in before - after:
                try:
                    if CHAIN.revoke(f["file_id"], g):   # None = nothing active to revoke
                        rec["revoked"] += 1
                except Exception:
                    rec["errors"] += 1   # surfaced to the UI; lingering grant is RLS-blocked but must be retried
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
    last_tx, revoked, errors = None, 0, 0
    for f in files:
        try:
            tx = CHAIN.revoke(f["file_id"], grantee)  # None = already inactive (retry-safe skip)
            if tx:
                last_tx, revoked = tx, revoked + 1
        except Exception:
            errors += 1
    if errors:
        # Fail closed: keep the share row so the owner can see it and retry.
        # Already-revoked files are skipped on retry (verify-first), so a retry
        # only re-attempts the failures — it can never brick on prior successes.
        raise HTTPException(status_code=502,
                            detail=f"On-chain revoke failed for {errors}/{len(files)} files — share kept; retry")
    supa.delete_share(token, node_id, grantee)
    return {"ok": True, "files_revoked": revoked, "files_covered": len(files), "tx": last_tx}


# --- share / download -------------------------------------------------------

@app.post("/api/share")
async def share(request: Request, node_id: str = Form(...), grantee: str = Form(...)):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["owner"] != uid:
        raise HTTPException(status_code=403, detail="You can only share your own items")
    if grantee == uid or supa.get_profile(token, grantee) is None:
        raise HTTPException(status_code=400, detail="Unknown recipient")

    # Real on-chain grant per file (permission is enforced per-file by the contract).
    files = supa.files_under(token, node_id)
    last_tx = None
    try:
        for f in files:
            last_tx = CHAIN.grant(f["file_id"], grantee, "read")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"On-chain grant failed: {exc}")

    rec = supa.insert_share(token, node_id, grantee, last_tx)
    pmap = _profiles_map(token)
    return {"ok": True, "grantee": _public(pmap.get(grantee, {"id": grantee})),
            "tx": rec.get("tx"), "files_granted": len(files),
            "cascade": node["type"] == "folder"}


@app.get("/api/verify/{node_id}")
async def verify_access(request: Request, node_id: str):
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    if node["owner"] == uid:
        return {"allowed": True, "source": "owner", "wallet": CHAIN.wallet}
    has, granted_at = CHAIN.verify(node["file_id"], uid)
    return {"allowed": has, "granted_at": granted_at, "source": "amoy-contract",
            "contract": "0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD"}


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
    if node["owner"] != uid:
        has, _ = CHAIN.verify(node["file_id"], uid)
        if not has:
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
    # Authoritative permission check reads the BLOCKCHAIN (owner bypass).
    if node["owner"] != uid:
        has, _ = CHAIN.verify(node["file_id"], uid)
        if not has:
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


@app.exception_handler(Exception)
async def all_exc(_request: Request, exc: Exception):
    # TEMP debug: surface the real error to diagnose the deployed runtime. Revert.
    import traceback
    if os.environ.get("XINSERE_DEBUG_ERRORS") == "1":
        return JSONResponse(status_code=500, content={
            "error": str(exc), "type": type(exc).__name__,
            "trace": traceback.format_exc()[-1800:]})
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
