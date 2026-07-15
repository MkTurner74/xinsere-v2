"""End-to-end forensic-watermarking + audit loop through the real app endpoints.

These are the integration checks Mark asked for: prove that a non-owner download
is actually watermarked, that the embedded mark is the viewer's access-log entry
(so it resolves back through the audit path), that owners get clean bit-perfect
copies, and that the org override gates it. Pipeline / chain / session / access
log are stubbed; watermark + app wiring are exercised for real.
"""
import hashlib
import io

import pytest

pytest.importorskip("PIL")
pytest.importorskip("pypdf")
pytest.importorskip("reportlab")

import access_log
import app as app_module
import supa
import watermark
from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas

client = TestClient(app_module.app)

OWNER = "owner-uid"
GRANTEE = "grantee-uid"
ENTRY_HASH = "deadbeefcafe0001deadbeefcafe0002deadbeefcafe0003"


def _pdf(text="confidential board pack") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(100, 700, text)
    c.showPage()
    c.save()
    return buf.getvalue()


class _FakeRetrieve:
    def __init__(self, content, ctype="application/pdf"):
        self.content = content
        self.content_type = ctype
        self.timings = {}


class _FakePipeline:
    def __init__(self, content):
        self._content = content
    def retrieve(self, file_id):
        return _FakeRetrieve(self._content)


def _setup(monkeypatch, *, viewer, owner=OWNER, level="download",
           wm_enabled=True, content=None):
    content = content if content is not None else _pdf()
    node = {"id": "fil_x", "type": "file", "file_id": "f1", "owner": owner,
            "name": "board.pdf", "content_type": "application/pdf",
            "size": len(content), "sha": hashlib.sha256(content).hexdigest()}
    monkeypatch.setattr(app_module, "_session", lambda req: {"access_token": "t", "user_id": viewer})
    monkeypatch.setattr(supa, "get_node", lambda tok, nid: node)
    monkeypatch.setattr(app_module, "_authorize", lambda n, uid, need="download": (True, "amoy-batch", level))
    monkeypatch.setattr(app_module, "get_pipeline", lambda: _FakePipeline(content))
    monkeypatch.setattr(app_module, "_wm_enabled", lambda ownr: wm_enabled)
    recorded = {}
    def fake_record(**kw):
        recorded.update(kw)
        return {"entry_hash": ENTRY_HASH}
    monkeypatch.setattr(access_log, "record", fake_record)
    return node, content, recorded


# --- download: the core loop ------------------------------------------------------

def test_owner_download_is_clean_and_bit_perfect(monkeypatch):
    node, content, _ = _setup(monkeypatch, viewer=OWNER)
    r = client.get("/api/download/fil_x")
    assert r.status_code == 200
    assert r.headers["X-Watermarked"] == "false"
    assert r.content == content                                  # untouched
    assert r.headers["X-Content-SHA256"] == node["sha"]          # original hash
    assert not watermark.extract(r.content)                      # no mark


def test_grantee_download_is_marked_and_traceable(monkeypatch):
    node, content, recorded = _setup(monkeypatch, viewer=GRANTEE)
    r = client.get("/api/download/fil_x")
    assert r.status_code == 200
    assert r.headers["X-Watermarked"] == "true"
    assert r.content != content                                  # bytes changed
    # delivered hash is the MARKED copy's hash, not the original
    assert r.headers["X-Content-SHA256"] == hashlib.sha256(r.content).hexdigest()
    assert r.headers["X-Content-SHA256"] != node["sha"]
    # the audit path ran, against the individual grantee
    assert recorded["actor_id"] == GRANTEE and recorded["action"] == "file.download"
    # THE FORENSIC LOOP: the embedded mark resolves to this access's log entry
    marks = watermark.extract(r.content)
    assert watermark.forensic_mark(ENTRY_HASH) in marks


def test_org_flag_off_disables_marking(monkeypatch):
    node, content, _ = _setup(monkeypatch, viewer=GRANTEE, wm_enabled=False)
    r = client.get("/api/download/fil_x")
    assert r.headers["X-Watermarked"] == "false"
    assert r.content == content
    assert not watermark.extract(r.content)


def test_view_only_grantee_cannot_download(monkeypatch):
    _setup(monkeypatch, viewer=GRANTEE, level="view")
    # _authorize returns need='download' unmet -> app maps to (False, ..., 'view')
    monkeypatch.setattr(app_module, "_authorize",
                        lambda n, uid, need="download": (need != "download", "amoy-batch", "view"))
    r = client.get("/api/download/fil_x")
    assert r.status_code == 403
    body=r.json(); assert "view-only" in (body.get("detail") or body.get("error") or "").lower()


# --- preview: marked for non-owner, clean for owner --------------------------------

def test_preview_marks_non_owner(monkeypatch):
    node, content, recorded = _setup(monkeypatch, viewer=GRANTEE, level="view")
    r = client.get("/api/preview/fil_x")
    assert r.status_code == 200
    assert r.headers.get("X-Watermarked") == "true"
    assert recorded["action"] == "file.view"
    assert watermark.forensic_mark(ENTRY_HASH) in watermark.extract(r.content)


def test_preview_clean_for_owner(monkeypatch):
    node, content, _ = _setup(monkeypatch, viewer=OWNER, level="download")
    r = client.get("/api/preview/fil_x")
    assert r.status_code == 200
    assert r.headers.get("X-Watermarked") == "false"
    assert not watermark.extract(r.content)


# --- audit trace resolves an extracted mark back to the access --------------------

def test_trace_resolves_mark_to_access(monkeypatch):
    """The admin 'Trace a file' path: an extracted mark -> the access_log row ->
    who/when. Stubs the log + profile lookups; asserts the resolver wiring."""
    import admin as admin_module
    from authn import require_admin
    app_module.app.dependency_overrides[require_admin] = lambda: {
        "user_id": "admin", "profile": {"email": "admin@xinsere.com"}}
    mark = watermark.forensic_mark(ENTRY_HASH)
    hexid = ENTRY_HASH[:16]

    def fake_rest(method, path, token, params=None, **kw):
        if path == "/access_log":
            assert hexid in params.get("entry_hash", "")
            return [{"ts": "2026-07-15T10:00:00Z", "day": "2026-07-15",
                     "actor_id": GRANTEE, "actor_type": "user", "action": "file.download",
                     "file_id": "f1", "node_id": "fil_x", "bytes": 1,
                     "entry_hash": ENTRY_HASH}]
        if path == "/profiles":
            return [{"email": "jeremy@xinsere.com", "name": "Jeremy Katz"}]
        if path == "/nodes":
            return [{"name": "board.pdf", "owner": OWNER}]
        if path == "/access_log_anchors":
            return [{"tx_hash": "0xabc", "anchored_at": "2026-07-16T00:00:00Z"}]
        return []

    monkeypatch.setattr(supa, "_rest", fake_rest)
    try:
        r = client.post("/api/admin/audit-marks", data={"marks": mark, "filename": "leak.pdf"})
        assert r.status_code == 200
        body = r.json()
        assert body["matches"], "mark should resolve to an access record"
        m = body["matches"][0]
        assert m["actor_email"] == "jeremy@xinsere.com"
        assert m["action"] == "file.download"
        assert m["sealed"] is True
    finally:
        app_module.app.dependency_overrides.pop(require_admin, None)
