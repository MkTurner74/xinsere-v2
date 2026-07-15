"""Forensic watermarking for view-only previews (0016 view grants).

Policy: ONLY view-level grantees get stamped renders — owners and download-level
users can fetch the clean original anyway, so stamping them is friction without
security. The stamp ties every view-only render to the individual viewer and
moment ("who leaked this screenshot"), which is the enforcement model that fits
a browser: deterrence and attribution, not DRM.

Fail-open by design: if a specific document defeats the stamper (encrypted PDF,
exotic image mode), the preview still serves — the access decision was already
made on-chain; the watermark is a deterrent layered on top. Failures are logged
loudly so they show up.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime, timezone

_log = logging.getLogger("xinsere.watermark")


def stamp_text(viewer_email: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"{viewer_email} · {ts} · Xinsere view-only"


def image(img, stamp: str):
    """Tile `stamp` across a PIL image (returns a new RGBA image). Two-pass text
    (dark shadow + light face) keeps it legible on any background at low alpha."""
    from PIL import Image, ImageDraw, ImageFont
    base = img.convert("RGBA")
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    size = max(13, base.width // 55)
    try:
        font = ImageFont.load_default(size=size)
    except TypeError:          # older Pillow: fixed-size bitmap font
        font = ImageFont.load_default()
    tw = int(d.textlength(stamp, font=font))
    step_x, step_y = tw + 90, max(80, base.height // 9)
    for row, y in enumerate(range(0, base.height + step_y, step_y)):
        off = (row % 2) * (step_x // 2)
        for x in range(-step_x, base.width + step_x, step_x):
            d.text((x + off + 1, y + 1), stamp, font=font, fill=(0, 0, 0, 46))
            d.text((x + off, y), stamp, font=font, fill=(255, 255, 255, 60))
    return Image.alpha_composite(base, layer)


def pdf(content: bytes, stamp: str) -> bytes:
    """Merge a diagonal tiled-text overlay onto every page. The stamp is baked
    into the page content stream of the served copy (the stored original is
    untouched)."""
    from pypdf import PdfReader, PdfWriter
    from reportlab.lib.colors import Color
    from reportlab.pdfgen import canvas

    reader = PdfReader(io.BytesIO(content))
    writer = PdfWriter()
    overlays: dict[tuple[int, int], object] = {}   # one overlay per page geometry
    for page in reader.pages:
        w, h = float(page.mediabox.width), float(page.mediabox.height)
        key = (int(w), int(h))
        if key not in overlays:
            buf = io.BytesIO()
            c = canvas.Canvas(buf, pagesize=(w, h))
            c.setFont("Helvetica", 9)
            c.setFillColor(Color(0.45, 0.45, 0.5, alpha=0.30))
            c.saveState()
            c.translate(w / 2, h / 2)
            c.rotate(35)
            span = int(max(w, h) * 1.5)
            for y in range(-span, span, 110):
                for x in range(-span, span, 320):
                    c.drawString(x, y, stamp)
            c.restoreState()
            c.save()
            overlays[key] = PdfReader(buf).pages[0]
        page.merge_page(overlays[key])
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def text(content: bytes, stamp: str) -> bytes:
    banner = f"[ {stamp} ]\n\n".encode()
    return banner + content


def apply(content: bytes, serve_type: str, viewer_email: str) -> tuple[bytes, str]:
    """Best-effort stamp for a view-only render. Returns (bytes, serve_type) —
    unchanged input on any failure (fail-open; see module docstring)."""
    stamp = stamp_text(viewer_email)
    try:
        base = serve_type.split(";")[0].strip().lower()
        if base == "application/pdf":
            return pdf(content, stamp), serve_type
        if base.startswith("text/"):
            return text(content, stamp), serve_type
        if base.startswith("image/") and base not in ("image/svg+xml", "image/gif"):
            from PIL import Image
            img = Image.open(io.BytesIO(content))
            out = io.BytesIO()
            stamped = image(img, stamp)
            if base in ("image/png", "image/webp") or img.mode in ("RGBA", "LA", "P"):
                stamped.save(out, "PNG", optimize=True)
                return out.getvalue(), "image/png"
            stamped.convert("RGB").save(out, "JPEG", quality=82, progressive=True)
            return out.getvalue(), "image/jpeg"
    except Exception as exc:   # noqa: BLE001 — deterrence layer, never block the view
        _log.warning("watermark failed type=%s viewer=%s: %s", serve_type, viewer_email, exc)
    return content, serve_type
