"""Tests for the Finding 2 completion controls: per-user share-rate cap and the
shared-wallet low-balance guard (defense-in-depth on top of the batch path)."""
import app as app_module
import share_quota
import supa
from chain import CHAIN
from fastapi import HTTPException


def test_share_rate_allows_under_cap(monkeypatch):
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "svc")
    monkeypatch.setattr(share_quota, "_bump", lambda *a, **k: 1)   # first share of the window
    share_quota.enforce_share_rate("user-1")                       # no raise


def test_share_rate_blocks_over_per_min(monkeypatch):
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "svc")
    monkeypatch.setattr(share_quota, "SHARE_PER_MIN", 5)
    monkeypatch.setattr(share_quota, "_bump",
                        lambda uid, win, bucket, count=1: 6 if win == "minute" else 6)
    try:
        share_quota.enforce_share_rate("user-1")
    except HTTPException as exc:
        assert exc.status_code == 429 and "share_rate_limited" in exc.detail
    else:
        raise AssertionError("expected 429 over per-minute cap")


def test_share_rate_fails_open_on_counter_error(monkeypatch):
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "svc")

    def _boom(*a, **k):
        raise RuntimeError("supabase down")
    monkeypatch.setattr(share_quota, "_bump", _boom)
    share_quota.enforce_share_rate("user-1")   # must NOT raise (fail-open)


def test_share_rate_noop_without_service_key(monkeypatch):
    monkeypatch.setattr(supa, "SERVICE_ROLE_KEY", "")
    share_quota.enforce_share_rate("user-1")   # no key -> no-op, no raise


def test_wallet_guard_blocks_when_depleted(monkeypatch):
    monkeypatch.setattr(CHAIN, "status",
                        lambda: {"wallet_ok": False, "balance_pol": 0.0, "est_grants_remaining": 0})
    try:
        app_module._wallet_guard()
    except HTTPException as exc:
        assert exc.status_code == 503 and "wallet_low" in exc.detail
    else:
        raise AssertionError("expected 503 when wallet depleted")


def test_wallet_guard_allows_when_healthy(monkeypatch):
    monkeypatch.setattr(CHAIN, "status",
                        lambda: {"wallet_ok": True, "balance_pol": 1.0, "est_grants_remaining": 80})
    app_module._wallet_guard()   # no raise


def test_wallet_guard_fails_open_on_status_error(monkeypatch):
    def _boom():
        raise RuntimeError("rpc down")
    monkeypatch.setattr(CHAIN, "status", _boom)
    app_module._wallet_guard()   # status check error is non-fatal (fail-open)
