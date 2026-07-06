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
import time

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.datastructures import UploadFile
from starlette.middleware.sessions import SessionMiddleware

import supa
from chain import CHAIN
from store import (get_pipeline, XinsereIntegrityError, presign_put, staged_size,
                   read_staged, delete_staged, MAX_INLINE_BYTES)

_HERE = os.path.dirname(os.path.abspath(__file__))
SESSION_SECRET = os.environ.get("XINSERE_SESSION_SECRET", "xinsere-demo-dev-secret")
app = FastAPI(title="Xinsere")
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


# --- session ----------------------------------------------------------------

def _session(request: Request) -> dict:
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


def _profiles_map(token: str) -> dict:
    return {p["id"]: p for p in supa.list_profiles(token)}


def node_view(node: dict, viewer: str, token: str, pmap: dict) -> dict:
    owner = pmap.get(node["owner"])
    v = {
        "id": node["id"], "type": node["type"], "name": node["name"],
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
    return node_view(node, uid, token, _profiles_map(token))


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
    return StreamingResponse(
        io.BytesIO(r.content),
        media_type=r.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            "X-Content-SHA256": node.get("sha", ""),
            "X-Integrity": "verified-bit-perfect",
            "Access-Control-Expose-Headers": "X-Content-SHA256, X-Integrity",
        },
    )


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
