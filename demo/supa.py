"""Thin Supabase client for the Xinsere hosted app (auth + app metadata).

No SDK — just HTTP (keeps the serverless bundle small). Two planes:
  - Auth (GoTrue): signup / login / refresh, backed by Supabase Auth.
  - Data (PostgREST): profiles / nodes / shares, called with the USER's access
    token so Row-Level Security enforces isolation as that user.

The pipeline (S3/KMS/DynamoDB) and the on-chain layer live elsewhere; this module
only touches Supabase. Blockchain verify() remains the authoritative download gate.
"""
from __future__ import annotations

import os
import time
from typing import Any

import requests

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
_TIMEOUT = 15


class SupabaseError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"supabase {status}: {detail}")
        self.status = status
        self.detail = detail


# --- Auth (GoTrue) ----------------------------------------------------------

def _auth(path: str, body: dict, params: dict | None = None) -> dict:
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1{path}",
        headers={"apikey": ANON_KEY, "Content-Type": "application/json"},
        params=params or {}, json=body, timeout=_TIMEOUT,
    )
    if r.status_code >= 400:
        raise SupabaseError(r.status_code, r.json().get("msg") or r.json().get("error_description") or r.text)
    return r.json()


def sign_up(email: str, password: str, name: str, username: str | None = None) -> dict:
    """Create an account. With email confirmation ON, no session is returned
    until the user confirms — the caller should prompt them to check their inbox."""
    data = {"name": name}
    if username:
        data["username"] = username
    return _auth("/signup", {"email": email, "password": password, "data": data})


def admin_create_user(email: str, password: str, name: str) -> dict:
    """Provision a confirmed account (invite flow — public signup is disabled).
    Uses the service-role key; the on_auth_user_created trigger builds the
    profile row from the metadata, same as self-serve signup."""
    if not SERVICE_ROLE_KEY:
        raise SupabaseError(501, "Service role key not configured")
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/admin/users",
        headers={"apikey": SERVICE_ROLE_KEY, "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
                 "Content-Type": "application/json"},
        json={"email": email, "password": password, "email_confirm": True,
              "user_metadata": {"name": name}},
        timeout=_TIMEOUT,
    )
    if r.status_code >= 400:
        raise SupabaseError(r.status_code, r.json().get("msg") or r.text)
    return r.json()


def sign_in(email: str, password: str) -> dict:
    """Password login. Returns {access_token, refresh_token, expires_in, user}."""
    return _auth("/token", {"email": email, "password": password}, params={"grant_type": "password"})


def refresh(refresh_token: str) -> dict:
    return _auth("/token", {"refresh_token": refresh_token}, params={"grant_type": "refresh_token"})


def session_from_grant(grant: dict) -> dict:
    """Normalize a GoTrue token response into the cookie session we persist."""
    return {
        "access_token": grant["access_token"],
        "refresh_token": grant["refresh_token"],
        "expires_at": time.time() + int(grant.get("expires_in", 3600)),
        "user_id": grant["user"]["id"],
    }


# --- Data (PostgREST, RLS-scoped by the user's token) -----------------------

def _rest(method: str, path: str, token: str, *, params: dict | None = None,
          json_body: Any = None, prefer: str | None = None) -> Any:
    headers = {"apikey": ANON_KEY, "Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    r = requests.request(method, f"{SUPABASE_URL}/rest/v1{path}", headers=headers,
                         params=params or {}, json=json_body, timeout=_TIMEOUT)
    if r.status_code >= 400:
        raise SupabaseError(r.status_code, r.text)
    if r.status_code == 204 or not r.content:
        return None
    return r.json()


def _node(row: dict) -> dict:
    """DB row -> the node dict shape the app/view layer expects (sha alias)."""
    return {
        "id": row["id"], "type": row["type"], "name": row["name"],
        "parent": row.get("parent"), "owner": row["owner"],
        "created_at": row.get("created_at"),
        "file_id": row.get("file_id"), "sha": row.get("sha256"),
        "size": row.get("size"), "frags": row.get("frags"),
        "content_type": row.get("content_type"),
    }


# profiles ----------------------------------------------------------------

def get_profile(token: str, user_id: str) -> dict | None:
    rows = _rest("GET", "/profiles", token,
                 params={"id": f"eq.{user_id}", "select": "id,email,name,username", "limit": 1})
    return rows[0] if rows else None


def list_others(token: str, user_id: str) -> list[dict]:
    return _rest("GET", "/profiles", token,
                 params={"id": f"neq.{user_id}", "select": "id,email,name,username", "order": "name"})


def list_profiles(token: str) -> list[dict]:
    """All profiles the caller can see (RLS: any authenticated user). For rendering
    owner/grantee display info when listing nodes."""
    return _rest("GET", "/profiles", token, params={"select": "id,email,name,username"})


# nodes -------------------------------------------------------------------

def root_id(user_id: str) -> str:
    return f"root:{user_id}"


def ensure_root(token: str, user_id: str) -> str:
    rid = root_id(user_id)
    existing = _rest("GET", "/nodes", token, params={"id": f"eq.{rid}", "select": "id", "limit": 1})
    if not existing:
        try:
            _rest("POST", "/nodes", token, prefer="return=minimal", json_body={
                "id": rid, "type": "folder", "name": "My Files",
                "parent": None, "owner": user_id})
        except SupabaseError as exc:
            if exc.status not in (409,):  # someone raced us; fine
                raise
    return rid


def get_node(token: str, node_id: str) -> dict | None:
    rows = _rest("GET", "/nodes", token, params={"id": f"eq.{node_id}", "select": "*", "limit": 1})
    return _node(rows[0]) if rows else None


def children(token: str, parent_id: str) -> list[dict]:
    rows = _rest("GET", "/nodes", token, params={"parent": f"eq.{parent_id}", "select": "*"})
    nodes = [_node(r) for r in rows]
    nodes.sort(key=lambda n: (n["type"] != "folder", (n["name"] or "").lower()))
    return nodes


def insert_folder(token: str, name: str, parent_id: str, owner: str) -> dict:
    import uuid
    nid = "fld_" + uuid.uuid4().hex[:12]
    rows = _rest("POST", "/nodes", token, prefer="return=representation", json_body={
        "id": nid, "type": "folder", "name": name, "parent": parent_id, "owner": owner})
    return _node(rows[0])


def insert_file(token: str, name: str, parent_id: str, owner: str, *, file_id: str,
                sha256: str, size: int, frags: int, content_type: str) -> dict:
    import uuid
    nid = "fil_" + uuid.uuid4().hex[:12]
    rows = _rest("POST", "/nodes", token, prefer="return=representation", json_body={
        "id": nid, "type": "file", "name": name, "parent": parent_id, "owner": owner,
        "file_id": file_id, "sha256": sha256, "size": size, "frags": frags,
        "content_type": content_type})
    return _node(rows[0])


def ensure_path(token: str, rel_path: str, root: str, owner: str) -> str:
    """Create nested folders for a relative dir path; return the leaf folder id."""
    parent = root
    for part in [p for p in rel_path.split("/") if p]:
        kids = children(token, parent)
        existing = next((n for n in kids if n["type"] == "folder" and n["name"] == part), None)
        parent = existing["id"] if existing else insert_folder(token, part, parent, owner)["id"]
    return parent


def files_under(token: str, node_id: str) -> list[dict]:
    """All file nodes at or below node_id (app-side recursion; RLS already scopes)."""
    node = get_node(token, node_id)
    if not node:
        return []
    if node["type"] == "file":
        return [node]
    out: list[dict] = []
    for child in children(token, node_id):
        out.extend(files_under(token, child["id"]))
    return out


# shares ------------------------------------------------------------------

def insert_share(token: str, node_id: str, grantee: str, tx: str | None) -> dict:
    rows = _rest("POST", "/shares", token,
                 prefer="return=representation,resolution=merge-duplicates",
                 json_body={"node_id": node_id, "grantee": grantee, "tx": tx})
    return rows[0] if rows else {"node_id": node_id, "grantee": grantee, "tx": tx}


def shares_for_node(token: str, node_id: str) -> list[dict]:
    return _rest("GET", "/shares", token,
                 params={"node_id": f"eq.{node_id}", "select": "grantee,tx"})


def shared_with(token: str, user_id: str) -> list[dict]:
    """Top-level nodes shared directly with the user."""
    rows = _rest("GET", "/shares", token,
                 params={"grantee": f"eq.{user_id}", "select": "node_id"})
    out = []
    for s in rows:
        n = get_node(token, s["node_id"])
        if n:
            out.append(n)
    return out
