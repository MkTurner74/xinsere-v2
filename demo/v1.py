"""Xinsere API v1 — machine access for organizations (server-to-server).

Auth: `Authorization: Bearer xin_...` (an organization API key minted in the
admin console). The key acts as the org's *service identity* — every stored
file is owned by that identity, and on-chain grants are made from/to profile
uuids exactly as in the interactive app. The on-chain contract remains the
authoritative download gate; Postgres metadata is defense-in-depth + listing.

All Supabase access here uses the service-role plane, so EVERY query must be
scoped to the caller's service identity in code — nothing in this module may
return a node without an owner check or an on-chain verify.
"""
from __future__ import annotations

import base64
import io
import logging
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import orgs
import supa
from chain import CHAIN
from store import (get_pipeline, XinsereIntegrityError, presign_put, staged_size,
                   read_staged, delete_staged, MAX_INLINE_BYTES, MAX_STAGED_BYTES)

router = APIRouter(prefix="/v1", tags=["v1"])
_log = logging.getLogger("xinsere.v1")


# --- auth ---------------------------------------------------------------------

def api_key_auth(authorization: str = Header(None, description="Bearer xin_...")) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer API key")
    try:
        ctx = orgs.resolve_key(authorization[7:].strip())
    except Exception:
        # Auth-store trouble must read as "try again", never as a generic 500.
        raise HTTPException(status_code=503, detail="Authentication backend unavailable — retry")
    if not ctx:
        raise HTTPException(status_code=401, detail="Invalid, revoked or suspended API key")
    return ctx


def need(ctx: dict, scope: str) -> None:
    if scope not in ctx["scopes"]:
        raise HTTPException(status_code=403, detail=f"API key lacks the '{scope}' scope")


def _svc() -> str:
    return supa.SERVICE_ROLE_KEY


def _own_node(ctx: dict, node_id: str) -> dict:
    """The node, if it exists and is owned by the caller's service identity.
    Uses a DB-level owner filter (get_owned_node) as a hard backstop on the
    RLS-bypassed service-role plane — see security audit finding 6."""
    node = supa.get_owned_node(_svc(), node_id, ctx["service_user"])
    if not node:
        raise HTTPException(status_code=404, detail="File not found")
    return node


def _readable_file(ctx: dict, node_id: str) -> dict:
    """A FILE node the caller may read: owned by the service identity, or
    covered by an active on-chain grant to it (the contract decides)."""
    node = supa.get_node(_svc(), node_id)
    if not node or node["type"] != "file" or node.get("deleted_at"):
        raise HTTPException(status_code=404, detail="File not found")
    if node["owner"] != ctx["service_user"]:
        has, _ = CHAIN.verify(node["file_id"], ctx["service_user"])
        if not has:
            raise HTTPException(status_code=404, detail="File not found")
    return node


def _file_view(node: dict) -> dict:
    return {"id": node["id"], "name": node["name"], "parent": node.get("parent"),
            "size": node.get("size"), "content_type": node.get("content_type"),
            "sha256": node.get("sha"), "fragments": node.get("frags"),
            "created_at": node.get("created_at")}


# --- models (OpenAPI) -----------------------------------------------------------

class FileRecord(BaseModel):
    id: str = Field(description="Xinsere file id — use in every subsequent call")
    name: str
    parent: str | None = None
    size: int | None = None
    content_type: str | None = None
    sha256: str | None = Field(None, description="SHA-256 of the original bytes; verify after download")
    fragments: int | None = Field(None, description="Number of encrypted fragments the file was scattered into")
    created_at: str | None = None


class GrantResult(BaseModel):
    ok: bool
    party_id: str
    tx: str | None = Field(None, description="On-chain grant transaction hash (PolygonScan-verifiable)")


class VerifyResult(BaseModel):
    allowed: bool
    party_id: str
    granted_at: int | None = Field(None, description="Unix timestamp of the active on-chain grant")
    source: str = Field(description="'owner' or the on-chain contract address")


class UploadTicket(BaseModel):
    key: str = Field(description="Staging key — pass back to POST /v1/files/finalize")
    url: str = Field(description="Presigned PUT URL — upload the raw bytes here")
    method: str = "PUT"
    max_bytes: int


# --- endpoints -------------------------------------------------------------------

@router.get("/ping", summary="Check your API key")
def ping(ctx: dict = Depends(api_key_auth)):
    """Returns the organization context your key resolves to, plus the effective
    inline-upload cap so clients switch to staged uploads without guessing
    (integrator feedback #1). Bodies larger than `max_inline_bytes` must use the
    two-step staged upload (POST /v1/uploads then POST /v1/files/finalize)."""
    return {"ok": True, "organization": ctx["org_name"], "slug": ctx["org_slug"],
            "party_id": ctx["service_user"], "scopes": ctx["scopes"],
            "max_inline_bytes": MAX_INLINE_BYTES, "max_staged_bytes": MAX_STAGED_BYTES}


@router.get("/parties", summary="Resolve a counterparty org's party_id by slug")
def resolve_party(ctx: dict = Depends(api_key_auth),
                  slug: str = Query(..., description="The other organization's slug, e.g. 'samsyn'")):
    """Machine-to-machine discovery: turn a known organization slug into the
    party_id you grant to — so workflow-bound grants need no human to read a uuid
    out of the console (integrator feedback #3). Returns only {slug, name,
    party_id} for ACTIVE orgs; 404 otherwise. Requires the grants:manage scope."""
    need(ctx, "grants:manage")
    party = orgs.resolve_party_by_slug(slug)
    if not party:
        raise HTTPException(status_code=404, detail="No active organization with that slug")
    return party


@router.get("/chain/status", summary="Wallet + gas capacity (pre-flight for grants)")
def chain_status(ctx: dict = Depends(api_key_auth)):
    """Read-only signer health — spends NO gas. Warn *before* a grant dies for lack
    of dust (integrator feedback #2): `wallet_ok` false or a low
    `est_grants_remaining` means top up before the next grant/revoke. All fields
    are public on-chain data (the signer address already appears in every grant tx)."""
    try:
        return {"ok": True, **CHAIN.status()}
    except Exception as exc:
        _log.warning("chain status unavailable: %s", exc)
        raise HTTPException(status_code=503,
                            detail="Chain status unavailable [chain_status_unavailable] — retry")


@router.get("/files", response_model=list[FileRecord], summary="List stored files")
def list_files(ctx: dict = Depends(api_key_auth),
               folder: str = Query("", description="Folder path e.g. 'campaigns/2026'; empty = root, recursive")):
    need(ctx, "files:read")
    root = supa.ensure_root(_svc(), ctx["service_user"])
    if folder:
        target = supa.ensure_path(_svc(), folder, root, ctx["service_user"])
        nodes = [n for n in supa.children(_svc(), target) if n["type"] == "file"]
    else:
        nodes = supa.files_under(_svc(), root)
    return [_file_view(n) for n in nodes if n["owner"] == ctx["service_user"]]


@router.post("/files", response_model=FileRecord, summary="Store a file (inline body)")
async def store_file(ctx: dict = Depends(api_key_auth),
                     file: UploadFile = File(..., description="The bytes to secure"),
                     path: str = Form("", description="Optional folder path, e.g. 'productions/rai'")):
    """Fragments, encrypts (AES-256-GCM, per-fragment KMS-wrapped keys) and
    scatters the file. This inline path reads the whole body into memory, so it is
    capped at `max_inline_bytes` (see GET /v1/ping). For larger files use the
    two-step staged upload (`POST /v1/uploads` then `POST /v1/files/finalize`)."""
    need(ctx, "files:write")
    content = await file.read()
    if len(content) > MAX_INLINE_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"Inline body limit is {MAX_INLINE_BYTES} bytes "
                                   f"(see max_inline_bytes in /v1/ping) — use POST /v1/uploads")
    uid = ctx["service_user"]
    root = supa.ensure_root(_svc(), uid)
    target = supa.ensure_path(_svc(), path, root, uid) if path else root
    name = file.filename or "file"
    ctype = file.content_type or "application/octet-stream"
    res = get_pipeline().store(content, ctype, label=name)
    node = supa.insert_file(_svc(), name, target, uid, file_id=res.file_id,
                            sha256=res.file_sha256, size=len(content),
                            frags=res.fragment_count, content_type=ctype)
    return _file_view(node)


@router.post("/uploads", response_model=UploadTicket, summary="Start a staged upload (large files)")
def start_upload(ctx: dict = Depends(api_key_auth)):
    """Returns a presigned PUT URL. Upload the raw bytes there, then call
    `POST /v1/files/finalize` with the returned key."""
    need(ctx, "files:write")
    key, url = presign_put(ctx["service_user"])
    return {"key": key, "url": url, "method": "PUT", "max_bytes": MAX_STAGED_BYTES}


@router.post("/files/finalize", response_model=FileRecord, summary="Finalize a staged upload")
def finalize_upload(ctx: dict = Depends(api_key_auth),
                    key: str = Form(...), name: str = Form(...),
                    path: str = Form(""), content_type: str = Form("application/octet-stream")):
    need(ctx, "files:write")
    uid = ctx["service_user"]
    if not key.startswith(f"staging/{uid}/"):
        raise HTTPException(status_code=403, detail="Not your staged upload")
    try:
        size = staged_size(key)
    except Exception:
        raise HTTPException(status_code=404, detail="Staged file not found — the upload may have failed")
    if size > MAX_STAGED_BYTES:
        delete_staged(key)
        raise HTTPException(status_code=413,
                            detail=f"File too large ({size} bytes); staged limit is {MAX_STAGED_BYTES}")
    root = supa.ensure_root(_svc(), uid)
    target = supa.ensure_path(_svc(), path, root, uid) if path else root
    content = read_staged(key)
    res = get_pipeline().store(content, content_type, label=name)
    node = supa.insert_file(_svc(), name, target, uid, file_id=res.file_id,
                            sha256=res.file_sha256, size=len(content),
                            frags=res.fragment_count, content_type=content_type)
    delete_staged(key)
    return _file_view(node)


@router.get("/files/{node_id}", response_model=FileRecord, summary="File metadata")
def file_meta(node_id: str, ctx: dict = Depends(api_key_auth)):
    need(ctx, "files:read")
    return _file_view(_readable_file(ctx, node_id))


@router.get("/files/{node_id}/content", summary="Download (server-side reassembly)")
def file_content(node_id: str, ctx: dict = Depends(api_key_auth)):
    """Reassembles, decrypts and integrity-verifies the file, then streams it.
    Permission is decided by ownership or the on-chain contract — never the DB."""
    need(ctx, "files:read")
    node = _readable_file(ctx, node_id)
    try:
        r = get_pipeline().retrieve(node["file_id"])
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    return StreamingResponse(io.BytesIO(r.content), media_type=r.content_type, headers={
        "Content-Disposition": f'attachment; filename="{node["name"]}"',
        "X-Content-SHA256": node.get("sha", ""),
        "X-Integrity": "verified-bit-perfect"})


@router.get("/files/{node_id}/plan", summary="Retrieval plan (client-side reassembly)")
def file_plan(node_id: str, ctx: dict = Depends(api_key_auth)):
    """Per-fragment presigned URLs + unwrapped data keys/nonces so YOUR
    infrastructure fetches fragments straight from storage and decrypts locally —
    the plaintext never transits Xinsere. Keys are per-fragment data keys only."""
    need(ctx, "files:read")
    node = _readable_file(ctx, node_id)
    try:
        plan = get_pipeline().retrieval_plan(node["file_id"], url_ttl=1800)
    except NotImplementedError:
        raise HTTPException(status_code=501, detail="Client-side reassembly unavailable")
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=422, detail=f"Integrity check failed — {exc}")
    return {"name": node["name"], "content_type": plan["content_type"],
            "size": plan["size"], "sha256": plan["file_sha256"],
            "fragments": [{"sequence": f["sequence"], "url": f["url"],
                           "key": base64.b64encode(f["key"]).decode(),
                           "nonce": base64.b64encode(f["nonce"]).decode()}
                          for f in plan["fragments"]]}


@router.delete("/files/{node_id}", summary="Delete (trash by default; permanent erasure on request)")
def delete_file(node_id: str, ctx: dict = Depends(api_key_auth),
                permanent: bool = Query(False, description="true = immediate cryptographic erasure + on-chain revokes")):
    need(ctx, "files:write")
    node = _own_node(ctx, node_id)
    if not node.get("parent"):
        raise HTTPException(status_code=400, detail="The root folder cannot be deleted")
    if permanent:
        from app import _erase_subtree
        return {"ok": True, "erased": True, **_erase_subtree(_svc(), node_id)}
    from datetime import datetime, timezone
    supa.soft_delete(_svc(), node_id, datetime.now(timezone.utc).isoformat())
    return {"ok": True, "trashed": True, "auto_erase_days": 30}


# --- grants / verification --------------------------------------------------------

@router.post("/files/{node_id}/grants", response_model=GrantResult, summary="Grant read access on-chain")
def grant(node_id: str, ctx: dict = Depends(api_key_auth),
          party_id: str = Form(..., description="Profile uuid of the grantee (user or another org's party_id)")):
    """Writes an immutable grant to the Polygon contract, then records the share.
    The grantee downloads via their own credentials (app or API)."""
    need(ctx, "grants:manage")
    node = _own_node(ctx, node_id)
    if node["type"] != "file":
        raise HTTPException(status_code=400, detail="Grants are per-file — pass a file id")
    if party_id == ctx["service_user"]:
        raise HTTPException(status_code=400, detail="Cannot grant to yourself")
    if supa.get_profile(_svc(), party_id) is None:
        raise HTTPException(status_code=400, detail="Unknown party_id")
    try:
        tx = CHAIN.grant(node["file_id"], party_id, "read")
    except Exception as exc:
        # Log the real cause server-side; return a stable, non-leaky message.
        _log.warning("chain grant failed node=%s grantee=%s: %s", node_id, party_id, exc)
        raise HTTPException(status_code=502,
                            detail="On-chain grant failed [chain_grant_failed] — retry; "
                                   "check GET /v1/chain/status for wallet capacity")
    supa.insert_share(_svc(), node_id, party_id, tx)
    return {"ok": True, "party_id": party_id, "tx": tx}


@router.delete("/files/{node_id}/grants/{party_id}", summary="Revoke access on-chain")
def revoke(node_id: str, party_id: str, ctx: dict = Depends(api_key_auth)):
    """Writes a revoke transaction — the revocation itself becomes part of the
    permanent audit history. Downloads fail immediately."""
    need(ctx, "grants:manage")
    node = _own_node(ctx, node_id)
    try:
        tx = CHAIN.revoke(node["file_id"], party_id)  # None = nothing active
    except Exception as exc:
        _log.warning("chain revoke failed node=%s grantee=%s: %s", node_id, party_id, exc)
        raise HTTPException(status_code=502,
                            detail="On-chain revoke failed [chain_revoke_failed] — retry")
    supa.delete_share(_svc(), node_id, party_id)
    return {"ok": True, "party_id": party_id, "tx": tx, "was_active": tx is not None}


@router.get("/files/{node_id}/grants", summary="List current shares (with tx hashes)")
def list_grants(node_id: str, ctx: dict = Depends(api_key_auth)):
    need(ctx, "grants:manage")
    _own_node(ctx, node_id)
    return {"grants": supa.shares_for_node(_svc(), node_id)}


@router.get("/files/{node_id}/verify", response_model=VerifyResult, summary="Verify access on-chain")
def verify(node_id: str, ctx: dict = Depends(api_key_auth),
           party_id: str = Query("", description="Party to check; empty = your own service identity")):
    """Third-party verification: is there an active on-chain grant for this party?
    Answers without touching the file content."""
    need(ctx, "verify:read")
    node = supa.get_node(_svc(), node_id)
    if not node or node["type"] != "file":
        raise HTTPException(status_code=404, detail="File not found")
    # Verification is allowed for files you own OR files shared to you.
    if node["owner"] != ctx["service_user"]:
        has_self, _ = CHAIN.verify(node["file_id"], ctx["service_user"])
        if not has_self:
            raise HTTPException(status_code=404, detail="File not found")
    party = party_id or ctx["service_user"]
    if node["owner"] == party:
        return {"allowed": True, "party_id": party, "granted_at": None, "source": "owner"}
    has, granted_at = CHAIN.verify(node["file_id"], party)
    return {"allowed": has, "party_id": party, "granted_at": granted_at or None,
            "source": os.environ.get("XINSERE_CONTRACT", "amoy-contract")}
