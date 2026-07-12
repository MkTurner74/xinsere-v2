"""Security + isolation regression tests for the /v1 machine API.

These substitute for RLS on the service-role plane: they assert that one org can
never reach another org's assets, that scopes are enforced, that the inline cap
holds, and that the error contract is uniform. Chain/pipeline/Supabase are faked —
we are testing the /v1 authorization logic, not the backends.
"""
import pytest
from fastapi.testclient import TestClient

import access_log
import app as app_module
import orgs
import quotas
import supa
import v1
from chain import CHAIN

client = TestClient(app_module.app)

# Two orgs, each with its own service identity.
CTX_A = {"key_id": "k1", "org_id": "o-a", "org_name": "Org A", "org_slug": "org-a",
         "service_user": "svc-a", "scopes": ["files:read", "files:write", "grants:manage", "verify:read"]}
CTX_B_NODE = {"id": "fil_bbb", "type": "file", "name": "b.pdf", "parent": "root:svc-b",
              "owner": "svc-b", "file_id": "fileB", "sha": "x", "size": 1, "frags": 7,
              "content_type": "application/pdf", "deleted_at": None}

KEY_A = "xin_orgA"
H = {"Authorization": f"Bearer {KEY_A}"}


def _blocked_rest(*a, **k):
    # Stand-in for a successful Supabase REST call (access_log insert) — no network.
    return None


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    # Key resolution: only KEY_A is valid, resolving to org A.
    def resolve_key(presented):
        return dict(CTX_A) if presented == KEY_A else None
    monkeypatch.setattr(orgs, "resolve_key", resolve_key)
    # get_owned_node enforces the owner filter (the DB backstop) in the fake too.
    def get_owned_node(_svc, node_id, owner):
        if node_id == CTX_B_NODE["id"] and owner != "svc-b":
            return None
        return None
    monkeypatch.setattr(supa, "get_owned_node", get_owned_node)
    # get_node returns org B's node regardless of caller (as the real DB would on
    # the service-role plane) — the endpoint must then reject it.
    monkeypatch.setattr(supa, "get_node", lambda _svc, nid: dict(CTX_B_NODE) if nid == CTX_B_NODE["id"] else None)
    # No on-chain grant to anyone by default.
    monkeypatch.setattr(CHAIN, "verify", lambda fid, party: (False, 0))
    # Quota counters: stub the atomic RPC so tests never hit Supabase. Default is
    # "well under limit" so enforcement runs for real but always passes; specific
    # tests override _bump to simulate over-limit.
    monkeypatch.setattr(quotas, "_bump",
                        lambda *a, **k: {"requests": 0, "bytes": 0, "files": 0})
    # Access log: stub the DB insert so recording never hits Supabase (the pure
    # hash/merkle/OCSF logic is tested directly below).
    monkeypatch.setattr(supa, "_rest", _blocked_rest, raising=False)
    yield


def test_ping_requires_key_and_advertises_inline_cap():
    assert client.get("/v1/ping").status_code == 401          # no header
    assert client.get("/v1/ping", headers={"Authorization": "Bearer xin_bogus"}).status_code == 401
    r = client.get("/v1/ping", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["organization"] == "Org A"
    assert body["party_id"] == "svc-a"
    assert isinstance(body["max_inline_bytes"], int) and body["max_inline_bytes"] > 0


def test_scope_enforced(monkeypatch):
    # A key without files:read cannot list.
    monkeypatch.setattr(orgs, "resolve_key",
                        lambda p: ({**CTX_A, "scopes": ["verify:read"]} if p == KEY_A else None))
    r = client.get("/v1/files", headers=H)
    assert r.status_code == 403
    assert "scope" in r.json()["error"].lower()


def test_cross_org_file_meta_is_404():
    # Org A asks for org B's node id: not owner, no grant -> hidden as 404.
    r = client.get(f"/v1/files/{CTX_B_NODE['id']}", headers=H)
    assert r.status_code == 404
    assert r.json()["error"] == "File not found"


def test_cross_org_delete_is_404():
    r = client.delete(f"/v1/files/{CTX_B_NODE['id']}", headers=H)
    assert r.status_code == 404


def test_cross_org_grant_is_404():
    r = client.post(f"/v1/files/{CTX_B_NODE['id']}/grants", headers=H, data={"party_id": "svc-c"})
    assert r.status_code == 404


def test_inline_cap_enforced(monkeypatch):
    monkeypatch.setattr(v1, "MAX_INLINE_BYTES", 1024)  # shrink for the test
    big = b"x" * 2048
    r = client.post("/v1/files", headers=H, files={"file": ("big.bin", big, "application/octet-stream")})
    assert r.status_code == 413
    assert "max_inline_bytes" in r.json()["error"] or "Inline body limit" in r.json()["error"]


def test_chain_status(monkeypatch):
    monkeypatch.setattr(CHAIN, "status", lambda: {
        "wallet": "0xabc", "balance_pol": 0.5, "gas_price_gwei": 26.0, "max_fee_gwei": 30,
        "gas_limit": 200000, "per_grant_pol": 0.006, "est_grants_remaining": 83, "wallet_ok": True})
    r = client.get("/v1/chain/status", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["wallet_ok"] is True
    assert body["est_grants_remaining"] == 83


def test_resolve_party(monkeypatch):
    monkeypatch.setattr(orgs, "resolve_party_by_slug",
                        lambda slug: {"slug": "samsyn", "name": "Samsyn", "party_id": "svc-samsyn"}
                        if slug == "samsyn" else None)
    r = client.get("/v1/parties", headers=H, params={"slug": "samsyn"})
    assert r.status_code == 200 and r.json()["party_id"] == "svc-samsyn"
    r2 = client.get("/v1/parties", headers=H, params={"slug": "nope"})
    assert r2.status_code == 404


def test_error_shape_is_uniform():
    # 422 validation error (missing required slug) must use {error} + {errors}, not {detail}.
    r = client.get("/v1/parties", headers=H)
    assert r.status_code == 422
    body = r.json()
    assert "error" in body and "detail" not in body
    assert isinstance(body.get("errors"), list)


# --- API key scoping (2026-07-12 audit: no all-scopes-by-default) -------------

def test_default_key_scopes_are_least_privilege():
    # A key minted with no explicit scope choice must be read+verify ONLY — never
    # write or grant management. This is the regression guard for the audit finding
    # that one leaked key could enumerate and exfiltrate a whole org.
    assert orgs.DEFAULT_SCOPES == orgs.READ_ONLY_SCOPES
    assert orgs.SCOPE_FILES_WRITE not in orgs.DEFAULT_SCOPES
    assert orgs.SCOPE_GRANTS_MANAGE not in orgs.DEFAULT_SCOPES
    assert orgs.validate_scopes(None) == [orgs.SCOPE_FILES_READ, orgs.SCOPE_VERIFY_READ]


def test_validate_scopes_normalizes_and_rejects():
    # Requested subset is normalized to canonical order, deduped.
    assert orgs.validate_scopes(["verify:read", "files:read", "files:read"]) == \
        [orgs.SCOPE_FILES_READ, orgs.SCOPE_VERIFY_READ]
    # A full explicit request is honored (opt-in), in canonical order.
    assert orgs.validate_scopes(list(reversed(orgs.ALL_SCOPES))) == orgs.ALL_SCOPES
    # Unknown scope is rejected.
    with pytest.raises(ValueError):
        orgs.validate_scopes(["files:read", "files:delete-everything"])
    # An empty explicit set is rejected (None means default, [] means nothing).
    with pytest.raises(ValueError):
        orgs.validate_scopes([])


# --- Per-key quotas (anti-exfiltration rate + egress limits) ------------------

def test_rate_limit_returns_429_end_to_end(monkeypatch):
    # Over the per-minute request cap -> the auth dependency rejects with 429,
    # before any endpoint logic runs.
    monkeypatch.setattr(quotas, "_bump",
                        lambda *a, **k: {"requests": quotas.RATE_PER_MIN + 1, "bytes": 0, "files": 0})
    r = client.get("/v1/ping", headers=H)
    assert r.status_code == 429
    assert "rate_limited" in r.json()["error"].lower()


def test_rate_limit_passes_when_under(monkeypatch):
    monkeypatch.setattr(quotas, "_bump",
                        lambda *a, **k: {"requests": quotas.RATE_PER_MIN, "bytes": 0, "files": 0})
    quotas.enforce_request(dict(CTX_A))  # exactly at limit -> allowed (over is > limit)


def test_egress_quota_enforced_on_bytes(monkeypatch):
    monkeypatch.setattr(quotas, "_bump",
                        lambda *a, **k: {"requests": 0, "bytes": quotas.EGRESS_BYTES_PER_DAY + 1, "files": 1})
    with pytest.raises(Exception) as exc:
        quotas.record_and_enforce_egress(dict(CTX_A), 1)
    assert getattr(exc.value, "status_code", None) == 429
    assert "egress_quota" in str(exc.value.detail)


def test_egress_quota_enforced_on_file_count(monkeypatch):
    monkeypatch.setattr(quotas, "_bump",
                        lambda *a, **k: {"requests": 0, "bytes": 1, "files": quotas.EGRESS_FILES_PER_DAY + 1})
    with pytest.raises(Exception) as exc:
        quotas.record_and_enforce_egress(dict(CTX_A), 1)
    assert getattr(exc.value, "status_code", None) == 429


def test_quota_fails_open_when_counter_unavailable(monkeypatch):
    # A counter-store outage must not break legitimate traffic (fail-open).
    def boom(*a, **k):
        raise RuntimeError("supabase down")
    monkeypatch.setattr(quotas, "_bump", boom)
    quotas.enforce_request(dict(CTX_A))              # no raise
    quotas.record_and_enforce_egress(dict(CTX_A), 1)  # no raise


# --- Tamper-evident access log (per-user audit + Merkle anchor) ---------------

def test_entry_hash_is_deterministic_and_tamper_evident():
    e = access_log.build_entry(org_id="o", actor_id="u1", actor_type="api_key",
                               action="file.read", key_id="k1", file_id="f1", bytes=10)
    assert e["entry_hash"] == access_log.entry_hash(
        {k: v for k, v in e.items() if k != "entry_hash"})
    # Altering any committed field changes the hash — you can't silently edit a row.
    tampered = {k: v for k, v in e.items() if k != "entry_hash"}
    tampered["bytes"] = 11
    assert access_log.entry_hash(tampered) != e["entry_hash"]


def test_merkle_root_deterministic_and_changes_on_any_leaf():
    leaves = [access_log.entry_hash({"i": i}) for i in range(5)]  # odd count
    root = access_log.merkle_root(leaves)
    assert root == access_log.merkle_root(list(leaves))      # deterministic
    assert access_log.merkle_root([]) == access_log.GENESIS  # empty -> genesis
    flipped = list(leaves)
    flipped[2] = access_log.entry_hash({"i": 999})
    assert access_log.merkle_root(flipped) != root           # any change moves the root


def test_build_daily_root_orders_entries_reproducibly():
    a = access_log.build_entry(org_id="o", actor_id="u", actor_type="api_key", action="file.read")
    b = access_log.build_entry(org_id="o", actor_id="u", actor_type="api_key", action="grant")
    r1, n1 = access_log.build_daily_root([a, b])
    r2, n2 = access_log.build_daily_root([b, a])  # input order shuffled
    assert r1 == r2 and n1 == n2 == 2             # root independent of input order


def test_ocsf_mapping_carries_individual_actor_and_anchor():
    e = access_log.build_entry(org_id="o", actor_id="u1", actor_type="api_key",
                               action="file.read", key_id="k9", file_id="f1", bytes=42)
    o = access_log.to_ocsf({**e, "day": e["ts"][:10]})
    assert o["class_uid"] == 1001 and o["activity_id"] == 2
    assert o["actor"]["user"]["uid"] == "u1"          # scopes back to the individual
    assert o["actor"]["session"]["uid"] == "k9"        # ...and which key
    assert o["metadata"]["xinsere"]["entry_hash"] == e["entry_hash"]


def test_record_is_fail_open_and_captures_actor(monkeypatch):
    captured = {}

    def capture_rest(method, path, token, *, json_body=None, **k):
        captured.update({"path": path, "body": json_body})
        return None
    monkeypatch.setattr(supa, "_rest", capture_rest)
    e = access_log.record(org_id="o", actor_id="u1", actor_type="api_key",
                          action="file.read", key_id="k1", file_id="f1", bytes=7)
    assert captured["path"] == "/access_log"
    assert captured["body"]["actor_id"] == "u1" and captured["body"]["key_id"] == "k1"
    assert captured["body"]["entry_hash"] == e["entry_hash"]

    # A logging-store outage must not raise to the caller.
    def boom(*a, **k):
        raise RuntimeError("supabase down")
    monkeypatch.setattr(supa, "_rest", boom)
    assert access_log.record(org_id="o", actor_id="u1", actor_type="api_key",
                             action="file.read") is not None  # returns entry, no raise
