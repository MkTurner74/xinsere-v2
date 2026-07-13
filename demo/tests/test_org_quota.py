"""Per-org ingest/egress quota tests (Finding 8)."""
import quotas
import supa
from fastapi import HTTPException

CTX = {"org_id": "org-1", "key_id": "k1"}


def test_org_egress_over_limit_429(monkeypatch):
    monkeypatch.setattr(quotas, "EGRESS_FILES_PER_DAY_ORG", 2)
    monkeypatch.setattr(quotas, "_bump_org",
                        lambda org, bucket, **c: {"egress_bytes": 1, "egress_files": 3,
                                                  "ingest_bytes": 0, "ingest_files": 0})
    try:
        quotas._enforce_org(CTX, egress_files=1)
    except HTTPException as e:
        assert e.status_code == 429 and "org_egress_quota" in e.detail
    else:
        raise AssertionError("expected 429")


def test_org_ingest_over_limit_429(monkeypatch):
    monkeypatch.setattr(quotas, "INGEST_BYTES_PER_DAY_ORG", 100)
    monkeypatch.setattr(quotas, "_bump_org",
                        lambda org, bucket, **c: {"egress_bytes": 0, "egress_files": 0,
                                                  "ingest_bytes": 200, "ingest_files": 1})
    try:
        quotas.record_and_enforce_ingest(CTX, 200)
    except HTTPException as e:
        assert e.status_code == 429 and "org_ingest_quota" in e.detail
    else:
        raise AssertionError("expected 429")


def test_org_quota_noop_without_org(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(quotas, "_bump_org", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    quotas.record_and_enforce_ingest({"key_id": "k1"}, 999)   # no org_id
    assert called["n"] == 0


def test_org_quota_fails_open_on_counter_error(monkeypatch):
    def _boom(*a, **k): raise RuntimeError("down")
    monkeypatch.setattr(quotas, "_bump_org", _boom)
    quotas._enforce_org(CTX, ingest_bytes=1)   # must not raise (fail-open)
