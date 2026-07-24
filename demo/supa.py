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
    """DISABLED. Xinsere is invite-only; the public /api/signup route fails closed
    (security audit finding 5). This helper is retained only for the future
    self-serve onboarding flow, which must ship with findings 1/3/8/9 closed. Do
    not wire it into a live route without that hardening."""
    raise SupabaseError(403, "Public signup is disabled — Xinsere is invite-only")


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


# --- Account security (password + MFA) via GoTrue ---------------------------
# These act on the authenticated USER (their access token); the gateway apikey is
# the anon key, the Authorization bearer is the user's token.

def _gotrue(method: str, path: str, token: str, *, body: dict | None = None,
            params: dict | None = None) -> Any:
    r = requests.request(
        method, f"{SUPABASE_URL}/auth/v1{path}",
        headers={"apikey": ANON_KEY, "Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        params=params or {}, json=body, timeout=_TIMEOUT)
    if r.status_code >= 400:
        try:
            j = r.json()
            msg = j.get("msg") or j.get("error_description") or j.get("error") or r.text
        except Exception:
            msg = r.text
        raise SupabaseError(r.status_code, msg)
    return r.json() if r.content else None


def get_auth_user(access_token: str) -> dict:
    """The GoTrue auth user (has email, email_confirmed_at, factors, ...)."""
    return _gotrue("GET", "/user", access_token) or {}


def update_password(access_token: str, new_password: str) -> dict:
    """Self-serve password change (GoTrue PUT /user). Requires the user's token."""
    return _gotrue("PUT", "/user", access_token, body={"password": new_password})


def generate_recovery_link(email: str, redirect_to: str | None = None) -> str | None:
    """Admin API: mint a password-recovery action link WITHOUT sending an email,
    so we can deliver it ourselves (branded, via SES) instead of GoTrue's default
    'powered by Supabase' mailer. Returns the link, or None for an unknown email
    (caller stays quiet either way). Service-role only."""
    if not SERVICE_ROLE_KEY:
        raise SupabaseError(500, "Service role key not configured")
    body = {"type": "recovery", "email": email.strip().lower()}
    if redirect_to:
        body["redirect_to"] = redirect_to
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/admin/generate_link",
        headers={"apikey": SERVICE_ROLE_KEY, "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
                 "Content-Type": "application/json"},
        json=body, timeout=_TIMEOUT)
    if r.status_code == 404 or r.status_code == 422:   # no such user — stay quiet
        return None
    if r.status_code >= 400:
        raise SupabaseError(r.status_code, r.text)
    d = r.json()
    return d.get("action_link") or (d.get("properties") or {}).get("action_link")


def mfa_list_factors(access_token: str) -> list[dict]:
    """A user's MFA factors. GoTrue exposes these on the USER object
    (GET /user -> `factors`), NOT a `/factors` collection — reading the wrong place
    made verified factors invisible (status stuck 'off', stale-factor cleanup and
    disable both no-ops, re-enroll collided on the friendly name)."""
    user = get_auth_user(access_token) or {}
    factors = user.get("factors")
    if factors is None:
        # Fallback for GoTrue variants that do expose a /factors collection.
        data = _gotrue("GET", "/factors", access_token) or {}
        factors = (data.get("all") or data.get("totp") or []) if isinstance(data, dict) else data
    return factors or []


def mfa_enroll(access_token: str, friendly_name: str = "Authenticator") -> dict:
    """Begin TOTP enrollment. Returns {id, type, totp:{qr_code(svg), secret, uri}}."""
    return _gotrue("POST", "/factors", access_token,
                   body={"factor_type": "totp", "friendly_name": friendly_name})


def mfa_challenge(access_token: str, factor_id: str) -> dict:
    """Create a challenge for a factor. Returns {id: challenge_id, ...}."""
    return _gotrue("POST", f"/factors/{factor_id}/challenge", access_token)


def mfa_verify(access_token: str, factor_id: str, challenge_id: str, code: str) -> dict:
    """Verify a TOTP code against a challenge; on success GoTrue returns AAL2 tokens."""
    return _gotrue("POST", f"/factors/{factor_id}/verify", access_token,
                   body={"challenge_id": challenge_id, "code": code})


def mfa_unenroll(access_token: str, factor_id: str) -> dict:
    return _gotrue("DELETE", f"/factors/{factor_id}", access_token)


# --- account_security app state (migration 0013, service-role) --------------

def get_account_security(token: str, user_id: str) -> dict:
    rows = _rest("GET", "/account_security", token,
                 params={"user_id": f"eq.{user_id}", "select": "*", "limit": 1})
    return rows[0] if rows else {"user_id": user_id, "must_change_password": False,
                                 "mfa_enabled": False}


def set_account_security(token: str, user_id: str, fields: dict) -> None:
    """Upsert the user's security state (service-role). Idempotent on user_id."""
    _rest("POST", "/account_security", token,
          prefer="return=minimal,resolution=merge-duplicates",
          json_body={"user_id": user_id, **fields, "updated_at": _now_iso()})


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
        "deleted_at": row.get("deleted_at"),
    }


# profiles ----------------------------------------------------------------

def get_profile(token: str, user_id: str) -> dict | None:
    rows = _rest("GET", "/profiles", token,
                 params={"id": f"eq.{user_id}", "select": "id,email,name,username", "limit": 1})
    return rows[0] if rows else None


# Cross-profile reads go through SECURITY DEFINER RPCs (migration 0010): the base
# profiles SELECT policy is now self-only, so a raw GET can no longer dump the
# directory (Finding 3). Each RPC returns MINIMAL fields for an EXPLICIT, SCOPED
# query and uses auth.uid() internally for the identity scope.

def profiles_visible_to_me(token: str) -> list[dict]:
    """Profiles the caller can legitimately see (self, co-org members, share
    counterparties) — the exact set needed to render owner/grantee names. Never a
    bulk table dump."""
    return _rest("POST", "/rpc/profiles_visible_to_me", token, json_body={}) or []


def list_others(token: str, user_id: str) -> list[dict]:
    """Visible profiles excluding the caller (share-picker fallback; the primary
    picker is the typeahead search)."""
    return [p for p in profiles_visible_to_me(token) if p.get("id") != user_id]


def list_profiles(token: str) -> list[dict]:
    """Visible profiles, for rendering owner/grantee display info when listing
    nodes. Scoped by profiles_visible_to_me (was a whole-table SELECT)."""
    return profiles_visible_to_me(token)


def search_profiles(token: str, q: str, exclude_id: str, limit: int = 8) -> list[dict]:
    """Typeahead: co-org members matching `q`, or an exact full-email match (to
    invite an external party). Scoped + capped by the search_profiles_min RPC —
    no bulk enumeration, and the structural-or() injection surface is gone."""
    if not q:
        return []
    return _rest("POST", "/rpc/search_profiles_min", token,
                 json_body={"q": q, "lim": limit}) or []


def profile_by_email(token: str, email: str) -> dict | None:
    """Resolve one exact email to an existing account (share-by-email flow)."""
    rows = _rest("POST", "/rpc/profile_by_email_min", token,
                 json_body={"addr": email.strip().lower()})
    return rows[0] if rows else None


# platform admins (Super-Admin tier — migration 0009) --------------------
# The durable source of truth for platform-admin status. Read on the service-role
# plane (deny-by-default RLS) so a user cannot influence the answer. Replaces the
# old "email matches XINSERE_ADMIN_EMAILS" check, which was self-promotable
# because profiles.email used to be user-writable (security audit finding 1).

def is_platform_admin(user_id: str) -> bool:
    """True if user_id is in the platform_admins registry. Fails closed on any
    error or missing service-role key (the env-var bootstrap fallback in authn
    covers first-admin provisioning)."""
    if not SERVICE_ROLE_KEY or not user_id:
        return False
    try:
        rows = _rest("GET", "/platform_admins", SERVICE_ROLE_KEY,
                     params={"user_id": f"eq.{user_id}", "select": "user_id", "limit": 1})
    except SupabaseError:
        return False
    return bool(rows)


def list_platform_admins(token: str) -> list[dict]:
    """Super-Admins (Xinsere staff) with their profile info, for the admin console.
    Joins profiles in Python rather than via a PostgREST embed — the embed depends
    on the FK being in PostgREST's schema cache, which isn't guaranteed right after
    the table is created, and a failure there was 500ing the admin console."""
    rows = _rest("GET", "/platform_admins", token,
                 params={"select": "user_id,created_at", "order": "created_at.asc"}) or []
    ids = [r["user_id"] for r in rows if r.get("user_id")]
    profs: dict = {}
    if ids:
        try:
            for p in (_rest("GET", "/profiles", token,
                            params={"id": f"in.({','.join(ids)})",
                                    "select": "id,email,name"}) or []):
                profs[p["id"]] = p
        except SupabaseError:
            pass
    for r in rows:
        r["profiles"] = profs.get(r["user_id"])
    return rows


def add_platform_admin(token: str, user_id: str, added_by: str | None) -> None:
    _rest("POST", "/platform_admins", token,
          prefer="return=minimal,resolution=merge-duplicates",
          json_body={"user_id": user_id, "added_by": added_by})


def remove_platform_admin(token: str, user_id: str) -> None:
    _rest("DELETE", "/platform_admins", token, params={"user_id": f"eq.{user_id}"})


def platform_admins_empty() -> bool:
    """True only if the platform_admins registry has NO rows (genuine first-boot).
    Gates the env-email bootstrap fallback so a stray XINSERE_ADMIN_EMAILS value
    can't shadow the durable registry once it's seeded (Finding 10). If it can't be
    checked, returns False in production (don't trust the fallback blindly) but True
    in local dev (bootstrap convenience)."""
    if not SERVICE_ROLE_KEY:
        return os.environ.get("XINSERE_BACKEND", "local").lower() != "aws"
    try:
        rows = _rest("GET", "/platform_admins", SERVICE_ROLE_KEY,
                     params={"select": "user_id", "limit": 1})
    except SupabaseError:
        return False
    return not rows


# pending share invitations (external-email sharing) ----------------------
# pending_shares.not_before/not_after (0021) — same once-only degrade as the
# shares/permission_batches window flags: a pre-0021 deploy pays one failed
# request, then stores invites windowless (perpetual) until the migration lands.
_PENDING_WINDOW_COLUMNS = True
_PENDING_UNMARKED_COLUMN = True   # pending_shares.serve_unmarked (0023)


def insert_pending_share(token: str, node_id: str, email: str, invited_by: str,
                         share_type: str = "download",
                         not_before: int = 0, not_after: int = 0,
                         serve_unmarked: bool = False) -> dict:
    """Create (or keep) a pending invite for an email with no account yet. Idempotent
    on (node_id, email) via merge-duplicates so re-inviting doesn't error (and a
    re-invite REFRESHES the stored window/type — last invite wins, like a re-share).
    `not_before`/`not_after` (unix seconds, 0 = unbounded) carry the share dialog's
    validity window to first-login materialization; stripped-and-retried if 0021
    isn't applied yet, so the invite degrades to perpetual rather than 500ing.
    `serve_unmarked` (0023) carries the per-share marking override the same way;
    stripped-and-retried if 0023 isn't applied yet."""
    global _PENDING_WINDOW_COLUMNS, _PENDING_UNMARKED_COLUMN
    body = {"node_id": node_id, "email": email.strip().lower(), "invited_by": invited_by}
    if share_type and share_type != "download":   # pre-0016 tolerance
        body["share_type"] = share_type
    # merge-duplicates alone upserts only on the PRIMARY KEY; without on_conflict
    # naming the real unique constraint, a re-invite 409'd on
    # pending_shares_node_id_email_key instead of refreshing the stub (2026-07-21).
    conflict = {"on_conflict": "node_id,email"}

    def _try(extra: dict) -> dict:
        rows = _rest("POST", "/pending_shares", token, params=conflict,
                     prefer="return=representation,resolution=merge-duplicates",
                     json_body={**body, **extra})
        return rows[0] if rows else {"node_id": node_id, "email": email}

    window = ({"not_before": not_before, "not_after": not_after}
             if _PENDING_WINDOW_COLUMNS and (not_before or not_after) else {})
    unmarked = {"serve_unmarked": True} if _PENDING_UNMARKED_COLUMN and serve_unmarked else {}

    if unmarked:
        try:
            return _try({**window, **unmarked})
        except SupabaseError as exc:
            if getattr(exc, "status", None) == 409:
                raise
            _PENDING_UNMARKED_COLUMN = False   # pre-0023 — retry without it
    if window:
        try:
            return _try(window)
        except SupabaseError as exc:
            if getattr(exc, "status", None) == 409:
                raise
            _PENDING_WINDOW_COLUMNS = False   # pre-0021 — windowless fallback below
    return _try({})


def pending_shares_for_email(token: str, email: str) -> list[dict]:
    params = {"email": f"eq.{email.strip().lower()}"}
    selects = ["id,node_id,invited_by,share_type,not_before,not_after,serve_unmarked",  # 0023
               "id,node_id,invited_by,share_type,not_before,not_after",                  # 0021
               "id,node_id,invited_by,share_type",                                      # 0016
               "id,node_id,invited_by"]                                                 # legacy
    rows = []
    for i, sel in enumerate(selects):
        try:
            rows = _rest("GET", "/pending_shares", token,
                         params={**params, "select": sel}) or []
            break
        except SupabaseError:
            if i == len(selects) - 1:
                raise
    for r in rows:
        r.setdefault("share_type", "download")
        r.setdefault("not_before", 0)
        r.setdefault("not_after", 0)
        r.setdefault("serve_unmarked", False)
    return rows


def pending_shares_for_node(token: str, node_id: str) -> list[dict]:
    return _rest("GET", "/pending_shares", token,
                 params={"node_id": f"eq.{node_id}", "select": "email"}) or []


def delete_pending_share(token: str, pending_id: str) -> None:
    _rest("DELETE", "/pending_shares", token, params={"id": f"eq.{pending_id}"})


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


def get_owned_node(token: str, node_id: str, owner: str) -> dict | None:
    """Fetch a node ONLY if it belongs to `owner`. The owner filter is applied at
    the database (PostgREST) layer, so on the service-role plane — where RLS is
    bypassed — this is a hard backstop: a /v1 code path that forgets its Python
    owner check still cannot receive a foreign org's row. (Security audit finding 6.)"""
    rows = _rest("GET", "/nodes", token,
                 params={"id": f"eq.{node_id}", "owner": f"eq.{owner}",
                         "select": "*", "limit": 1})
    return _node(rows[0]) if rows else None


def children(token: str, parent_id: str) -> list[dict]:
    # Hide trashed items from normal navigation (deleted_at IS NULL).
    rows = _rest("GET", "/nodes", token,
                 params={"parent": f"eq.{parent_id}", "deleted_at": "is.null", "select": "*"})
    nodes = [_node(r) for r in rows]
    nodes.sort(key=lambda n: (n["type"] != "folder", (n["name"] or "").lower()))
    return nodes


def folders_by_owner(token: str, owner: str) -> list[dict]:
    """Every live folder the user owns, flat, in ONE query — the Move picker
    builds the tree client-side (a per-folder recursive walk is O(folders)
    round-trips and crawls on big imported trees)."""
    rows = _rest("GET", "/nodes", token,
                 params={"owner": f"eq.{owner}", "type": "eq.folder",
                         "deleted_at": "is.null", "select": "id,name,parent",
                         "order": "name.asc"})
    return rows or []


def trashed(token: str, user_id: str) -> list[dict]:
    """Items the user has moved to Trash (deleted_at set), newest first."""
    rows = _rest("GET", "/nodes", token,
                 params={"owner": f"eq.{user_id}", "deleted_at": "not.is.null",
                         "select": "*", "order": "deleted_at.desc"})
    return [_node(r) for r in rows]


def soft_delete(token: str, node_id: str, when_iso: str) -> None:
    """Move to Trash — metadata only (no chain, no erasure). Reversible."""
    _rest("PATCH", "/nodes", token, params={"id": f"eq.{node_id}"},
          json_body={"deleted_at": when_iso})


def restore_node(token: str, node_id: str) -> None:
    """Bring a node back out of Trash (clears deleted_at; parent is unchanged so
    it returns to its original location)."""
    _rest("PATCH", "/nodes", token, params={"id": f"eq.{node_id}"},
          json_body={"deleted_at": None})


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


# A folder upload's relative path is client-supplied; a pathological or hostile one
# (thousands of segments) would fan out into thousands of folder rows + round-trips.
# 64 levels is deeper than any real drive tree and well under Python's recursion
# limit for the later files_under/ancestors walks over the result.
MAX_PATH_DEPTH = int(os.environ.get("XINSERE_MAX_PATH_DEPTH", "64"))


class PathTooDeepError(RuntimeError):
    """A folder-upload relative path exceeds MAX_PATH_DEPTH segments."""


def ensure_path(token: str, rel_path: str, root: str, owner: str) -> str:
    """Create nested folders for a relative dir path; return the leaf folder id.
    Existing folders at each level are REUSED (idempotent), so re-uploading into the
    same tree adds no duplicates. Rejects an absurdly deep path (PathTooDeepError)."""
    parts = [p for p in rel_path.split("/") if p and p not in (".", "..")]
    if len(parts) > MAX_PATH_DEPTH:
        raise PathTooDeepError(
            f"folder path is {len(parts)} levels deep; the limit is {MAX_PATH_DEPTH}")
    parent = root
    for part in parts:
        kids = children(token, parent)
        existing = next((n for n in kids if n["type"] == "folder" and n["name"] == part), None)
        parent = existing["id"] if existing else insert_folder(token, part, parent, owner)["id"]
    return parent


def rename_node(token: str, node_id: str, name: str) -> dict:
    """Display-name only: fragment ids carry no filename linkage, so renaming
    never touches storage or the chain."""
    rows = _rest("PATCH", "/nodes", token, params={"id": f"eq.{node_id}"},
                 prefer="return=representation", json_body={"name": name})
    return _node(rows[0]) if rows else {}


def move_node(token: str, node_id: str, new_parent: str) -> dict:
    """Re-parent within the tree (RLS restricts to owner)."""
    rows = _rest("PATCH", "/nodes", token, params={"id": f"eq.{node_id}"},
                 prefer="return=representation", json_body={"parent": new_parent})
    return _node(rows[0]) if rows else {}


def delete_node(token: str, node_id: str) -> None:
    """Remove a node; descendants cascade via the FK (metadata only — the caller
    is responsible for pipeline crypto-erasure and on-chain revocations first)."""
    _rest("DELETE", "/nodes", token, params={"id": f"eq.{node_id}"})


def ancestors(token: str, node_id: str) -> list[dict]:
    """Chain from node_id's parent up to the root (nearest first)."""
    out: list[dict] = []
    cur = get_node(token, node_id)
    while cur and cur.get("parent"):
        cur = get_node(token, cur["parent"])
        if cur:
            out.append(cur)
    return out


def shares_covering(token: str, node_id: str) -> list[dict]:
    """Shares on the node itself or ANY ancestor — everyone with inherited access.
    Used for grant-on-add (late-added files) and revoke-on-delete."""
    ids = [node_id] + [a["id"] for a in ancestors(token, node_id)]
    return _shares_select(
        token,
        {"node_id": f"in.({','.join(ids)})", "select": "node_id,grantee,tx,share_type"},
        {"node_id": f"in.({','.join(ids)})", "select": "node_id,grantee,tx"})


_SHARE_UNMARKED_COLUMN = True   # shares.serve_unmarked (0023)


def share_serve_unmarked(token: str, node_id: str, uid: str) -> bool:
    """True if ANY share covering this node (itself or an ancestor) for this
    grantee carries the per-share 'serve unmarked' override (0023) — checked at
    serve time so a legal-hold/internal-transfer share stays bit-perfect
    regardless of the org's marking-policy matrix. Fails toward False (marked):
    a lookup error or a pre-0023 deploy never silently suppresses a mark."""
    global _SHARE_UNMARKED_COLUMN
    if not _SHARE_UNMARKED_COLUMN:
        return False
    ids = [node_id] + [a["id"] for a in ancestors(token, node_id)]
    try:
        rows = _rest("GET", "/shares", token,
                     params={"node_id": f"in.({','.join(ids)})", "grantee": f"eq.{uid}",
                             "select": "serve_unmarked"}) or []
        return any(r.get("serve_unmarked") for r in rows)
    except SupabaseError:
        _SHARE_UNMARKED_COLUMN = False   # pre-0023
        return False


def shares_for_nodes(token: str, node_ids: list[str]) -> list[dict]:
    """Share rows (with windows when 0020 is applied) across a set of nodes in one
    request — feeds inherited-share display: a folder listing passes its breadcrumb
    chain so children can show who has access via an ancestor share."""
    global _SHARE_WINDOW_COLUMNS
    if not node_ids:
        return []
    filt = f"in.({','.join(node_ids)})"
    if _SHARE_WINDOW_COLUMNS:
        try:
            rows = _rest("GET", "/shares", token,
                         params={"node_id": filt,
                                 "select": "node_id,grantee,tx,share_type,not_before,not_after"}) or []
            for r in rows:
                r.setdefault("share_type", "download")
            return rows
        except SupabaseError:
            _SHARE_WINDOW_COLUMNS = False   # pre-0020
    return _shares_select(
        token,
        {"node_id": filt, "select": "node_id,grantee,tx,share_type"},
        {"node_id": filt, "select": "node_id,grantee,tx"})


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


def search_nodes(token: str, q: str, limit: int = 60) -> list[dict]:
    """Name search over every live node the CALLER can see — the user token means
    RLS scopes results to their own tree + shared subtrees. PostgREST filter
    metacharacters and ilike wildcards are stripped so q is always literal."""
    q = "".join(c for c in q if c not in "\\%*,()").strip()[:64]
    if not q:
        return []
    rows = _rest("GET", "/nodes", token, params={
        "name": f"ilike.*{q}*", "deleted_at": "is.null",
        "select": "id,name,type,parent,owner,file_id,size,frags,sha256,content_type,created_at",
        "order": "name.asc", "limit": str(limit)}) or []
    return [_node(r) for r in rows]   # sha256 -> sha alias the view layer expects


# shares ------------------------------------------------------------------
# share_type reads fall back to the legacy column set if migration 0016 hasn't
# been applied yet, so the deploy is safe in either order. The flag avoids
# re-paying the failed request on every call once we know the column is absent.
_SHARE_TYPE_COLUMN = True
# shares.not_before/not_after (0020) — flipped off once seen absent, so a pre-0020
# deploy pays the failed request only once, then inserts perpetual shares.
_SHARE_WINDOW_COLUMNS = True


def _shares_select(token: str, params_with: dict, params_without: dict) -> list[dict]:
    global _SHARE_TYPE_COLUMN
    if _SHARE_TYPE_COLUMN:
        try:
            return _rest("GET", "/shares", token, params=params_with) or []
        except SupabaseError:
            _SHARE_TYPE_COLUMN = False
    rows = _rest("GET", "/shares", token, params=params_without) or []
    for r in rows:
        r.setdefault("share_type", "download")
    return rows


def insert_share(token: str, node_id: str, grantee: str, tx: str | None,
                 share_type: str = "download",
                 not_before: int = 0, not_after: int = 0,
                 serve_unmarked: bool = False) -> dict:
    """Upsert on (node_id, grantee). share_type is always sent when the column
    exists (a re-share must be able to RESET a previous 'view' to 'download');
    pre-0016 the key is retried without so the deploy order can't break shares.
    `not_before`/`not_after` (unix seconds, 0 = unbounded) mirror the on-chain
    validity window for the owner UI; dropped-and-retried if 0020 isn't applied.
    `serve_unmarked` (0023) forces an unmarked serve for this grantee regardless
    of the org's marking-policy matrix; dropped-and-retried if 0023 isn't applied.
    The two optional column groups degrade independently, unmarked first (it's
    the newer migration), so either one being unapplied can't break the other."""
    global _SHARE_TYPE_COLUMN, _SHARE_WINDOW_COLUMNS, _SHARE_UNMARKED_COLUMN
    body = {"node_id": node_id, "grantee": grantee, "tx": tx}

    def _try(extra: dict) -> dict:
        return _insert_share_row(token, {**body, **extra}, share_type)

    window = ({"not_before": not_before, "not_after": not_after}
             if _SHARE_WINDOW_COLUMNS and (not_before or not_after) else {})
    unmarked = {"serve_unmarked": True} if _SHARE_UNMARKED_COLUMN and serve_unmarked else {}

    if unmarked:
        try:
            return _try({**window, **unmarked})
        except SupabaseError:
            _SHARE_UNMARKED_COLUMN = False   # pre-0023 — retry without it
    if window:
        try:
            return _try(window)
        except SupabaseError:
            _SHARE_WINDOW_COLUMNS = False    # pre-0020 — perpetual fallback below
    return _try({})


def _insert_share_row(token: str, body: dict, share_type: str) -> dict:
    """POST a shares upsert, degrading past the share_type column if 0016 is unapplied
    (a download-typed share can still land; a genuinely typed one re-raises)."""
    global _SHARE_TYPE_COLUMN
    if _SHARE_TYPE_COLUMN:
        try:
            rows = _rest("POST", "/shares", token,
                         prefer="return=representation,resolution=merge-duplicates",
                         json_body={**body, "share_type": share_type or "download"})
            return rows[0] if rows else {**body, "share_type": share_type}
        except SupabaseError:
            if share_type and share_type != "download":
                raise                      # typed share genuinely needs 0016
            _SHARE_TYPE_COLUMN = False     # legacy retry below
    rows = _rest("POST", "/shares", token,
                 prefer="return=representation,resolution=merge-duplicates",
                 json_body=body)
    return rows[0] if rows else {**body, "share_type": share_type}


def shares_for_node(token: str, node_id: str) -> list[dict]:
    """Grantee rows for a node, with the validity window (0020) when the columns
    exist — the owner UI shows per-person start/expiry. Falls through the same
    degrade ladder as everything else: windowed -> typed -> legacy."""
    global _SHARE_WINDOW_COLUMNS
    if _SHARE_WINDOW_COLUMNS:
        try:
            rows = _rest("GET", "/shares", token,
                         params={"node_id": f"eq.{node_id}",
                                 "select": "grantee,tx,share_type,not_before,not_after"}) or []
            for r in rows:
                r.setdefault("share_type", "download")
            return rows
        except SupabaseError:
            _SHARE_WINDOW_COLUMNS = False   # pre-0020
    return _shares_select(
        token,
        {"node_id": f"eq.{node_id}", "select": "grantee,tx,share_type"},
        {"node_id": f"eq.{node_id}", "select": "grantee,tx"})


def delete_share(token: str, node_id: str, grantee: str) -> None:
    _rest("DELETE", "/shares", token,
          params={"node_id": f"eq.{node_id}", "grantee": f"eq.{grantee}"})


def shared_with(token: str, user_id: str) -> list[dict]:
    """Top-level nodes shared directly with the user. Each node carries the
    viewer's `share_type` for that share (download unless 0016 says otherwise)."""
    rows = _shares_select(
        token,
        {"grantee": f"eq.{user_id}", "select": "node_id,share_type"},
        {"grantee": f"eq.{user_id}", "select": "node_id"})
    out = []
    for s in rows:
        n = get_node(token, s["node_id"])
        if n and not n.get("deleted_at"):   # a trashed item is hidden from recipients
            n["share_type"] = s.get("share_type", "download")
            out.append(n)
    return out


def shares_by_owner(token: str, owner_id: str) -> list[dict]:
    """All share rows on nodes owned by owner_id. RLS: the shares_select policy
    lets an owner read shares on their own nodes, so the user token suffices.
    We filter by owner via a joined select on nodes."""
    return _rest("GET", "/shares", token, params={
        "select": "node_id,grantee,share_type,nodes!inner(owner)",
        "nodes.owner": f"eq.{owner_id}"}) or []


def shares_for_grantee(token: str, user_id: str) -> list[dict]:
    """Every share row granted to the user — node id + type. Used to resolve the
    viewer's effective access level over a folder subtree."""
    return _shares_select(
        token,
        {"grantee": f"eq.{user_id}", "select": "node_id,share_type"},
        {"grantee": f"eq.{user_id}", "select": "node_id"})


# permission batches (Merkle aggregate batch-grant — ADR-2026-07-13) ---------
# All service-role only (RLS deny-by-default, migration 0007). The proof cache is
# rebuildable from the manifest; the on-chain root is the source of truth.

# permission_batches.not_before/not_after (0016-expiry, migration 0020) are sent
# only when non-zero, and dropped-and-retried if the columns aren't there yet, so
# the deploy is safe in either order (code before migration = perpetual grants).
_BATCH_WINDOW_COLUMNS = True


def insert_permission_batch(token: str, merkle_root: str, leaf_count: int,
                            source: str, scope: str | None,
                            not_before: int = 0, not_after: int = 0) -> dict:
    """Create the batch header (status='pending'). Idempotent on merkle_root so a
    re-run of the same tree resumes rather than duplicating. `not_before`/`not_after`
    (unix seconds, 0 = unbounded) record the on-chain validity window for audit/UI."""
    global _BATCH_WINDOW_COLUMNS
    body = {"merkle_root": merkle_root, "leaf_count": leaf_count,
            "source": source, "scope": scope, "status": "pending"}
    # on_conflict must name the real unique key: merge-duplicates alone only merges
    # on the PK, so re-anchoring a root that already had a row — e.g. re-sharing the
    # same (file, grantee) after a CONTRACT CUTOVER — 409'd on merkle_root and the
    # share failed (Jeremy/Mark, 2026-07-21). The upsert resets the row to 'pending'
    # and preserve() re-anchors on the current contract if the chain says unanchored.
    conflict = {"on_conflict": "merkle_root"}
    if _BATCH_WINDOW_COLUMNS and (not_before or not_after):
        try:
            rows = _rest("POST", "/permission_batches", token, params=conflict,
                         prefer="return=representation,resolution=merge-duplicates",
                         json_body={**body, "not_before": not_before, "not_after": not_after})
            return rows[0] if rows else {"merkle_root": merkle_root}
        except SupabaseError as exc:
            if getattr(exc, "status", None) == 409:
                raise                       # real conflict, not a missing column
            _BATCH_WINDOW_COLUMNS = False   # pre-0020 — fall through to windowless insert
    rows = _rest("POST", "/permission_batches", token, params=conflict,
                 prefer="return=representation,resolution=merge-duplicates",
                 json_body=body)
    return rows[0] if rows else {"merkle_root": merkle_root}


def set_batch_status(token: str, merkle_root: str, status: str, *,
                     tx_hash: str | None = None, anchored_at: str | None = None) -> None:
    body: dict = {"status": status}
    if tx_hash is not None:
        body["tx_hash"] = tx_hash
    if anchored_at is not None:
        body["anchored_at"] = anchored_at
    _rest("PATCH", "/permission_batches", token,
          params={"merkle_root": f"eq.{merkle_root}"}, json_body=body)


def insert_batch_grants(token: str, rows: list[dict]) -> None:
    """Bulk-insert the per-(file,grantee) proof rows for one batch. Idempotent on
    (file_id, grantee_id, merkle_root)."""
    if not rows:
        return
    _rest("POST", "/batch_grants", token,
          params={"on_conflict": "file_id,grantee_id,merkle_root"},
          prefer="return=minimal,resolution=merge-duplicates",
          json_body=rows)


# migration runs (Admin import dashboard — migration 0008) ------------------
# Service-role only. Best-effort telemetry: a write failure must never abort a
# migration, so the connector wraps these in try/except (fail-open).

def create_migration_run(token: str, *, source: str, folder: str, owner: str,
                         target_root: str, workers: int) -> str | None:
    """Insert a 'running' run row; return its id (or None on failure — fail-open)."""
    rows = _rest("POST", "/migration_runs", token, prefer="return=representation",
                 json_body={"source": source, "folder": folder, "owner": owner,
                            "target_root": target_root, "workers": workers,
                            "status": "running"})
    return rows[0]["id"] if rows else None


def update_migration_run(token: str, run_id: str, fields: dict) -> None:
    """Patch counters/metrics/status on a run row (updated_at bumped)."""
    body = {**fields, "updated_at": _now_iso()}
    _rest("PATCH", "/migration_runs", token, params={"id": f"eq.{run_id}"}, json_body=body)


def list_migration_runs(token: str, limit: int = 50) -> list[dict]:
    return _rest("GET", "/migration_runs", token,
                 params={"select": "*", "order": "started_at.desc", "limit": limit}) or []


def get_migration_run(token: str, run_id: str) -> dict | None:
    rows = _rest("GET", "/migration_runs", token,
                 params={"id": f"eq.{run_id}", "select": "*", "limit": 1})
    return rows[0] if rows else None


def list_permission_batches(token: str, limit: int = 200) -> list[dict]:
    """On-chain 1,000-file permission batches for the dashboard's batch panel."""
    return _rest("GET", "/permission_batches", token,
                 params={"select": "merkle_root,leaf_count,tx_hash,status,scope,source,anchored_at,created_at",
                         "order": "created_at.desc", "limit": limit}) or []


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# share_batches — maps an interactive share (node -> grantee) to the batch root(s)
# it anchored, so unshare/erase/move can revoke EXACTLY those roots (Finding 2,
# migration 0011). Service-role only.

def insert_share_batch(token: str, node_id: str, grantee: str, merkle_root: str) -> None:
    """Record that an interactive share of (node_id -> grantee) anchored `merkle_root`.
    Idempotent on (node_id, grantee, merkle_root)."""
    _rest("POST", "/share_batches", token,
          prefer="return=minimal,resolution=merge-duplicates",
          json_body={"node_id": node_id, "grantee": grantee, "merkle_root": merkle_root})


def share_batch_roots(token: str, node_id: str, grantee: str) -> list[str]:
    """The batch root(s) anchored for the (node_id -> grantee) interactive share."""
    rows = _rest("GET", "/share_batches", token,
                 params={"node_id": f"eq.{node_id}", "grantee": f"eq.{grantee}",
                         "select": "merkle_root"}) or []
    return [r["merkle_root"] for r in rows]


# Every source value grant_share/reanchor_share is called with from the app.
# Migration/connector batches (source 'dropbox' etc.) are EXCLUDED: their scope is
# a folder path, not a node id, and their roots can be multi-grantee.
INTERACTIVE_SHARE_SOURCES = ("share", "grant-on-add", "reconcile-invite",
                             "move", "reanchor")


def derived_share_roots(token: str, node_id: str, grantee: str) -> list[str]:
    """Recover an interactive share's batch root(s) from the proof cache
    (batch_grants ⋈ permission_batches) instead of the share_batches mapping.
    Safety net for mappings that were never recorded (2026-07-15 incident: prod ran
    without migration 0011, so insert_share_batch silently failed for every share
    anchored since the batch cutover). Interactive roots are single-grantee and
    node-scoped with scope == share node, so filtering on (scope, grantee,
    interactive source) identifies exactly the roots the mapping would hold —
    revoking them touches no other grantee."""
    rows = _rest("GET", "/batch_grants", token, params={
        "grantee_id": f"eq.{grantee}",
        "select": "merkle_root,permission_batches!inner(scope,source,status)",
        "permission_batches.scope": f"eq.{node_id}",
        "permission_batches.source": f"in.({','.join(INTERACTIVE_SHARE_SOURCES)})",
        "permission_batches.status": "neq.revoked",
    }) or []
    return sorted({r["merkle_root"] for r in rows})


def delete_share_batch(token: str, node_id: str, grantee: str, merkle_root: str) -> None:
    _rest("DELETE", "/share_batches", token,
          params={"node_id": f"eq.{node_id}", "grantee": f"eq.{grantee}",
                  "merkle_root": f"eq.{merkle_root}"})


def batch_grants_for(token: str, file_id: str, grantee_id: str, limit: int = 5) -> list[dict]:
    """Download-gate lookup: recent batch grants (proof + root) for (file, grantee),
    newest first. The caller replays each through the contract's verifyBatch and
    accepts the first that passes — the ON-CHAIN check is the authority (an
    unanchored, pending, or revoked root fails closed there), so we deliberately
    do NOT filter on the cached status and can't be fooled by a stale one."""
    try:
        rows = _rest("GET", "/batch_grants", token, params={
            "file_id": f"eq.{file_id}", "grantee_id": f"eq.{grantee_id}",
            "select": "merkle_root,leaf,proof,grant_type", "order": "created_at.desc",
            "limit": limit}) or []
    except SupabaseError:   # pre-0016
        rows = _rest("GET", "/batch_grants", token, params={
            "file_id": f"eq.{file_id}", "grantee_id": f"eq.{grantee_id}",
            "select": "merkle_root,leaf,proof", "order": "created_at.desc",
            "limit": limit}) or []
    for r in rows:
        r.setdefault("grant_type", "download")
    return rows
