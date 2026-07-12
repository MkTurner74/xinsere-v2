"""Organizations, membership and API keys — the machine-access plane.

Everything here runs on the Supabase SERVICE-ROLE key. Callers are authenticated
BEFORE these helpers run (platform-admin session for admin ops, hashed API key
for /v1 ops); RLS on these tables is deny-by-default so the user-token plane
(supa.py) can never touch them.

Key format: `xin_<43 url-safe chars>`. Only the SHA-256 hex of the full key is
stored; the plaintext is shown once at mint time. Lookup is by hash — O(1) via
the unique index, no scanning.

Each organization has a *service identity*: a real Supabase auth user whose
profile uuid owns every node stored through the org's API keys and is the
on-chain party for grants. That way the /v1 plane reuses the exact node/share/
chain machinery the interactive app uses — no parallel ownership model.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone

import supa

SERVICE_DOMAIN = "service.xinsere.io"   # service identities: svc-<slug>@<domain>
KEY_PREFIX = "xin_"

# Scope vocabulary. Enforced per-route in v1.py via need(ctx, scope).
SCOPE_FILES_READ = "files:read"
SCOPE_FILES_WRITE = "files:write"
SCOPE_GRANTS_MANAGE = "grants:manage"
SCOPE_VERIFY_READ = "verify:read"
# Canonical order — used to normalize any requested set.
ALL_SCOPES = [SCOPE_FILES_READ, SCOPE_FILES_WRITE, SCOPE_GRANTS_MANAGE, SCOPE_VERIFY_READ]

# Least-privilege default. A key minted without an explicit scope choice can READ
# and VERIFY only — it cannot write, delete, or manage grants. (This reverses the
# prior all-scopes default: one leaked key could enumerate + exfiltrate a whole
# org — 2026-07-12 API security audit. Write/manage must now be opted into.)
READ_ONLY_SCOPES = [SCOPE_FILES_READ, SCOPE_VERIFY_READ]
DEFAULT_SCOPES = READ_ONLY_SCOPES


def validate_scopes(scopes: list[str] | None) -> list[str]:
    """Normalize a requested scope set to canonical order, rejecting unknown or
    empty sets. Returns the least-privilege default when scopes is None."""
    if scopes is None:
        return list(DEFAULT_SCOPES)
    requested = {s.strip() for s in scopes if s and s.strip()}
    unknown = requested - set(ALL_SCOPES)
    if unknown:
        raise ValueError(f"unknown scope(s): {sorted(unknown)}; valid: {ALL_SCOPES}")
    if not requested:
        raise ValueError("at least one scope is required")
    return [s for s in ALL_SCOPES if s in requested]


def _svc() -> str:
    if not supa.SERVICE_ROLE_KEY:
        raise supa.SupabaseError(501, "Service role key not configured")
    return supa.SERVICE_ROLE_KEY


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not s:
        raise ValueError("Organization name must contain letters or digits")
    return s[:40]


# --- organizations -----------------------------------------------------------

def list_orgs() -> list[dict]:
    return supa._rest("GET", "/organizations", _svc(),
                      params={"select": "*", "order": "created_at.asc"}) or []


def get_org(org_id: str) -> dict | None:
    rows = supa._rest("GET", "/organizations", _svc(),
                      params={"id": f"eq.{org_id}", "select": "*", "limit": 1})
    return rows[0] if rows else None


def get_org_by_slug(slug: str) -> dict | None:
    rows = supa._rest("GET", "/organizations", _svc(),
                      params={"slug": f"eq.{slug}", "select": "*", "limit": 1})
    return rows[0] if rows else None


def create_org(name: str, created_by: str | None) -> dict:
    """Create the org AND its service identity (auth user + profile + root
    folder). The service identity's password is random and discarded — the
    backend always acts for it via the service-role key, never by login."""
    slug = slugify(name)
    if get_org_by_slug(slug):
        raise supa.SupabaseError(409, f"An organization with slug '{slug}' already exists")
    svc_email = f"svc-{slug}@{SERVICE_DOMAIN}"
    user = supa.admin_create_user(svc_email, secrets.token_urlsafe(24), f"{name} (service)")
    service_user = user["id"]
    supa.ensure_root(_svc(), service_user)
    rows = supa._rest("POST", "/organizations", _svc(), prefer="return=representation",
                      json_body={"name": name, "slug": slug,
                                 "service_user": service_user, "created_by": created_by})
    return rows[0]


def set_org_status(org_id: str, status: str) -> dict:
    rows = supa._rest("PATCH", "/organizations", _svc(), params={"id": f"eq.{org_id}"},
                      prefer="return=representation", json_body={"status": status})
    return rows[0] if rows else {}


# --- membership ---------------------------------------------------------------

def org_members(org_id: str) -> list[dict]:
    rows = supa._rest("GET", "/org_members", _svc(),
                      params={"org_id": f"eq.{org_id}",
                              "select": "org_id,user_id,role,created_at,profiles(id,email,name)",
                              "order": "created_at.asc"}) or []
    return rows


def memberships_for_user(user_id: str) -> list[dict]:
    return supa._rest("GET", "/org_members", _svc(),
                      params={"user_id": f"eq.{user_id}",
                              "select": "org_id,role,organizations(id,name,slug,status)"}) or []


def add_member(org_id: str, user_id: str, role: str = "member") -> dict:
    rows = supa._rest("POST", "/org_members", _svc(),
                      prefer="return=representation,resolution=merge-duplicates",
                      json_body={"org_id": org_id, "user_id": user_id, "role": role})
    return rows[0] if rows else {"org_id": org_id, "user_id": user_id, "role": role}


def set_member_role(org_id: str, user_id: str, role: str) -> None:
    supa._rest("PATCH", "/org_members", _svc(),
               params={"org_id": f"eq.{org_id}", "user_id": f"eq.{user_id}"},
               json_body={"role": role})


def remove_member(org_id: str, user_id: str) -> None:
    supa._rest("DELETE", "/org_members", _svc(),
               params={"org_id": f"eq.{org_id}", "user_id": f"eq.{user_id}"})


def resolve_party_by_slug(slug: str) -> dict | None:
    """Resolve a counterparty organization's on-chain party_id from its slug — the
    minimum machine-to-machine discovery an integrator needs to grant to another
    org without a human reading a uuid out of the admin console (integrator
    feedback #3). Opt-in and minimal by design: active orgs only, exact-slug match,
    and only {slug, name, party_id} is returned — never members, keys or status."""
    slug = (slug or "").strip().lower()
    if not slug:
        return None
    rows = supa._rest("GET", "/organizations", _svc(),
                      params={"slug": f"eq.{slug}", "status": "eq.active",
                              "select": "slug,name,service_user", "limit": 1})
    if not rows or not rows[0].get("service_user"):
        return None
    o = rows[0]
    return {"slug": o["slug"], "name": o["name"], "party_id": o["service_user"]}


def get_profile_by_email(email: str) -> dict | None:
    rows = supa._rest("GET", "/profiles", _svc(),
                      params={"email": f"eq.{email.strip().lower()}",
                              "select": "id,email,name", "limit": 1})
    return rows[0] if rows else None


def list_all_users() -> list[dict]:
    """Every profile + their org memberships (for the admin user directory)."""
    profiles = supa._rest("GET", "/profiles", _svc(),
                          params={"select": "id,email,name,created_at", "order": "created_at.asc"}) or []
    members = supa._rest("GET", "/org_members", _svc(),
                         params={"select": "org_id,user_id,role,organizations(name,slug)"}) or []
    by_user: dict[str, list] = {}
    for m in members:
        by_user.setdefault(m["user_id"], []).append(
            {"org_id": m["org_id"], "role": m["role"],
             "org_name": (m.get("organizations") or {}).get("name")})
    for p in profiles:
        p["memberships"] = by_user.get(p["id"], [])
    return profiles


# --- API keys ------------------------------------------------------------------

def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def mint_key(org_id: str, name: str, created_by: str | None,
             scopes: list[str] | None = None) -> tuple[str, dict]:
    """Create a key; returns (plaintext_key, row). The plaintext is NEVER stored
    or retrievable again — the caller must surface it once."""
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    granted = validate_scopes(scopes)  # least-privilege default; rejects unknown scopes
    rows = supa._rest("POST", "/api_keys", _svc(), prefer="return=representation",
                      json_body={"org_id": org_id, "name": name, "prefix": key[:12],
                                 "key_hash": _hash(key), "scopes": granted,
                                 "created_by": created_by})
    return key, rows[0]


def org_keys(org_id: str) -> list[dict]:
    rows = supa._rest("GET", "/api_keys", _svc(),
                      params={"org_id": f"eq.{org_id}", "order": "created_at.desc",
                              "select": "id,name,prefix,scopes,created_at,last_used_at,revoked_at"})
    return rows or []


def revoke_key(key_id: str) -> None:
    supa._rest("PATCH", "/api_keys", _svc(), params={"id": f"eq.{key_id}"},
               json_body={"revoked_at": _now()})


def resolve_key(presented: str) -> dict | None:
    """Hash the presented key and return its full auth context, or None.
    Context: {key_id, org_id, org_name, org_slug, service_user, scopes}.
    Rejects revoked keys and suspended orgs. Touches last_used_at best-effort."""
    if not presented or not presented.startswith(KEY_PREFIX):
        return None
    rows = supa._rest("GET", "/api_keys", _svc(),
                      params={"key_hash": f"eq.{_hash(presented)}", "limit": 1,
                              "select": "id,org_id,scopes,revoked_at,"
                                        "organizations(id,name,slug,status,service_user)"})
    if not rows or rows[0].get("revoked_at"):
        return None
    row = rows[0]
    org = row.get("organizations") or {}
    if org.get("status") != "active" or not org.get("service_user"):
        return None
    try:
        supa._rest("PATCH", "/api_keys", _svc(), params={"id": f"eq.{row['id']}"},
                   json_body={"last_used_at": _now()})
    except Exception:
        pass  # telemetry only — never block auth on it
    return {"key_id": row["id"], "org_id": org["id"], "org_name": org["name"],
            "org_slug": org["slug"], "service_user": org["service_user"],
            "scopes": row.get("scopes") or []}
