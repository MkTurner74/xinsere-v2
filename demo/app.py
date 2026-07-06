"""Xinsere demo API — a real, wired file explorer over the DPD pipeline.

Upload a file (or a whole folder) -> it's fragmented, encrypted, and scattered by
the pipeline. Browse a folder tree, share a file or folder with another user, and
download it back (permission-checked, reassembled, SHA-256 verified).

Basic session auth only — enough to demo the flow to J & J.
"""
from __future__ import annotations

import io
import json
import os

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.datastructures import UploadFile
from starlette.middleware.sessions import SessionMiddleware

from demo_store import STORE  # sets up the pipeline import path
from auth import USERS_DB
from chain import CHAIN
from xinsere_pipeline import XinsereIntegrityError

_HERE = os.path.dirname(os.path.abspath(__file__))
SESSION_SECRET = os.environ.get("XINSERE_SESSION_SECRET", "xinsere-demo-dev-secret")
app = FastAPI(title="Xinsere Demo")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=60 * 60 * 8)


# --- helpers ----------------------------------------------------------------

def current_user(request: Request) -> str:
    """Return the signed-in user's id, or 401."""
    uid = request.session.get("user")
    if not uid or USERS_DB.get(uid) is None:
        raise HTTPException(status_code=401, detail="Not signed in")
    return uid


def user_public(user_id: str) -> dict:
    u = USERS_DB.get(user_id)
    if u:
        return USERS_DB.public(u)
    return {"id": user_id, "name": user_id, "email": "", "initials": "?",
            "grad": ["#8A6BFF", "#5B3DF5"]}


def node_view(node: dict, viewer: str) -> dict:
    """Serialize a node with viewer-relevant share/ownership info."""
    owner = USERS_DB.get(node["owner"])
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
        shares = STORE.shares_for_node(node["id"])
        v["shared_with"] = [
            {**user_public(s["grantee"]), "tx": s["tx"]}
            for s in shares if USERS_DB.get(s["grantee"])
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
    u = USERS_DB.verify(identifier, password)
    if not u:
        raise HTTPException(status_code=401, detail="Wrong email/username or password")
    request.session["user"] = u["id"]
    STORE.ensure_root(u["id"])
    return {"ok": True, "user": USERS_DB.public(u)}


@app.post("/api/signup")
async def signup(request: Request, email: str = Form(...), password: str = Form(...),
                 name: str = Form(...)):
    try:
        u = USERS_DB.create_user(email, password, name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    request.session["user"] = u["id"]
    STORE.ensure_root(u["id"])
    return {"ok": True, "user": USERS_DB.public(u)}


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
async def me(request: Request):
    user = current_user(request)
    others = [USERS_DB.public(o) for o in USERS_DB.all_except(user)]
    return {"user": user_public(user), "others": others}


# --- tree -------------------------------------------------------------------

@app.get("/api/tree")
async def tree(request: Request, folder: str = ""):
    user = current_user(request)
    folder_id = folder or STORE.root_id(user)
    node = STORE.node(folder_id)
    if not node or node["type"] != "folder":
        raise HTTPException(status_code=404, detail="Folder not found")
    if not STORE.can_access(user, folder_id):
        raise HTTPException(status_code=403, detail="No access to this folder")

    # breadcrumbs up to a root the viewer can see
    crumbs, cur = [], node
    while cur:
        crumbs.append({"id": cur["id"], "name": cur["name"]})
        cur = STORE.node(cur["parent"]) if cur.get("parent") else None
    crumbs.reverse()

    children = [node_view(c, user) for c in STORE.children(folder_id)
                if STORE.can_access(user, c["id"])]
    return {"folder": node_view(node, user), "breadcrumbs": crumbs, "children": children}


@app.get("/api/shared")
async def shared(request: Request):
    user = current_user(request)
    items = [node_view(n, user) for n in STORE.shared_with(user)]
    return {"children": items}


@app.post("/api/folder")
async def make_folder(request: Request, name: str = Form(...), parent: str = Form(...)):
    user = current_user(request)
    if not STORE.can_access(user, parent):
        raise HTTPException(status_code=403, detail="No access")
    parent_node = STORE.node(parent)
    if not parent_node or parent_node["owner"] != user:
        raise HTTPException(status_code=403, detail="You can only add folders to your own files")
    node = STORE.create_folder(name.strip() or "New folder", parent, user)
    return node_view(node, user)


@app.post("/api/upload")
async def upload(request: Request):
    """Accepts one or more files. For folder uploads, a parallel `paths` field
    carries each file's relative path so the folder tree is rebuilt."""
    user = current_user(request)
    form = await request.form()
    parent = form.get("parent") or STORE.root_id(user)
    if STORE.node(parent) is None or STORE.node(parent)["owner"] != user:
        raise HTTPException(status_code=403, detail="Upload only into your own folders")

    files = form.getlist("files")
    paths = form.getlist("paths")  # relative paths aligned with files (folder upload)
    created = []
    for i, f in enumerate(files):
        if not isinstance(f, UploadFile):
            continue
        content = await f.read()
        rel = paths[i] if i < len(paths) and paths[i] else (f.filename or "file")
        rel = rel.replace("\\", "/")
        subdir = os.path.dirname(rel)
        name = os.path.basename(rel) or (f.filename or "file")
        target = STORE.ensure_path(subdir, parent, user) if subdir else parent
        node = STORE.add_file(name, target, user, content,
                              f.content_type or "application/octet-stream")
        created.append(node_view(node, user))
    return {"created": created, "count": len(created)}


# --- share / download -------------------------------------------------------

@app.post("/api/share")
async def share(request: Request, node_id: str = Form(...), grantee: str = Form(...)):
    user = current_user(request)
    node = STORE.node(node_id)
    if not node or node["owner"] != user:
        raise HTTPException(status_code=403, detail="You can only share your own items")
    if USERS_DB.get(grantee) is None or grantee == user:
        raise HTTPException(status_code=400, detail="Unknown recipient")

    # Real on-chain grant. Sharing a folder writes a grant for every file under it,
    # because permission is enforced per-file by the contract. The tx hash returned
    # is genuine and viewable on PolygonScan — this is what makes the permission
    # blockchain-backed, not a local flag.
    files = STORE.files_under(node_id)
    last_tx = None
    try:
        for f in files:
            last_tx = CHAIN.grant(f["file_id"], grantee, "read")
    except Exception as exc:  # surface — do NOT silently fall back to a DB-only grant
        raise HTTPException(status_code=502, detail=f"On-chain grant failed: {exc}")

    rec = STORE.share(node_id, grantee, last_tx)  # DB mirror for UI listing only
    return {"ok": True, "grantee": user_public(grantee), "tx": rec["tx"],
            "files_granted": len(files), "cascade": node["type"] == "folder"}


@app.get("/api/verify/{node_id}")
async def verify_access(request: Request, node_id: str):
    """Read the contract directly: does the current user have on-chain permission?"""
    user = current_user(request)
    node = STORE.node(node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    if node["owner"] == user:
        return {"allowed": True, "source": "owner", "wallet": CHAIN.wallet}
    has, granted_at = CHAIN.verify(node["file_id"], user)
    return {"allowed": has, "granted_at": granted_at, "source": "amoy-contract",
            "contract": CHAIN.wallet and "0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD"}


@app.get("/api/download/{node_id}")
async def download(request: Request, node_id: str):
    user = current_user(request)
    node = STORE.node(node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    # Authoritative permission check reads the BLOCKCHAIN (owner bypass). The demo
    # DB is never consulted for the access decision — only the contract's verify().
    if node["owner"] != user:
        has, _granted_at = CHAIN.verify(node["file_id"], user)
        if not has:
            raise HTTPException(status_code=403, detail="No active on-chain grant for you")
    # retrieve() recomputes the whole-file SHA-256 and raises if the reassembled
    # bytes are not bit-perfect. We surface that as a clean 422 instead of a 500,
    # and expose the verified hash so the client can display the guarantee.
    try:
        content, content_type = STORE.retrieve(node)
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    return StreamingResponse(
        io.BytesIO(content),
        media_type=content_type,
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
