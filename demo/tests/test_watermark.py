"""Watermark module — stamped renders must stay valid documents, and apply()
must be fail-open (a stamping failure never blocks an authorized view)."""
import io

import pytest

import watermark

PIL = pytest.importorskip("PIL", reason="Pillow not installed")
from PIL import Image  # noqa: E402


def _jpeg(w=800, h=600) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (40, 80, 120)).save(buf, "JPEG")
    return buf.getvalue()


def test_image_stamp_changes_bytes_and_stays_decodable():
    out, ctype = watermark.apply(_jpeg(), "image/jpeg", "jeremy@xinsere.com")
    assert out != _jpeg()
    img = Image.open(io.BytesIO(out))
    assert img.size == (800, 600)
    assert ctype in ("image/jpeg", "image/png")


def test_pdf_stamp_preserves_page_count():
    pypdf = pytest.importorskip("pypdf")
    reportlab = pytest.importorskip("reportlab")
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for _ in range(3):
        c.drawString(100, 700, "confidential")
        c.showPage()
    c.save()
    original = buf.getvalue()
    out, ctype = watermark.apply(original, "application/pdf", "joshua@xinsere.com")
    assert out != original and ctype == "application/pdf"
    reader = pypdf.PdfReader(io.BytesIO(out))
    assert len(reader.pages) == 3
    assert "joshua@xinsere.com" in reader.pages[0].extract_text()


def test_text_gets_banner():
    out, _ = watermark.apply(b"hello world", "text/plain; charset=utf-8", "max@xinsere.com")
    assert out.startswith(b"[ max@xinsere.com")
    assert out.endswith(b"hello world")


def test_apply_fails_open_on_garbage():
    junk = b"\x00\x01not-an-image"
    out, ctype = watermark.apply(junk, "image/jpeg", "x@y.com")
    assert out == junk and ctype == "image/jpeg"   # unchanged, never raises


def test_gif_and_svg_are_passed_through():
    for t in ("image/gif", "image/svg+xml"):
        out, ctype = watermark.apply(b"raw", t, "x@y.com")
        assert out == b"raw" and ctype == t
