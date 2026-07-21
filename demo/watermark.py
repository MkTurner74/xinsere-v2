"""Invisible forensic watermarking for previews (Phase 1 of the traceability
plan — see ai-brain projects/Xinsere/forensic-watermarking-design-2026-07-15.md).

Direction (Mark, 2026-07-15): marks must be INVISIBLE, embedded in the file
contents where they're hard to strip, and (Phase 2) carried on downloaded
copies too, so an auditor can trace a leaked file back to the recipient.

The mark is a FORENSIC ID — the first 16 hex chars of the viewer's access_log
entry_hash. That row is append-only and its day is Merkle-anchored on-chain
(0005/0014), so an extracted ID resolves to WHO accessed the file and WHEN with
tamper-evident backing. We embed the ID, not the identity: nothing personal is
readable in the file itself.

Phase-1 channels (no heavy deps, applied to every non-owner view):
  PDF   — ID in the Info/keywords metadata AND as an invisible zero-size text
          object on every page (survives metadata scrubbers; re-rendering the
          document defeats it — that's Phase 2 territory).
  text  — zero-width unicode encoding of the ID appended to the content.
  image — ID in metadata (PNG tEXt / JPEG EXIF UserComment). Pixel-domain
          (DCT) steganography is Phase 2 — it needs cv2/numpy, which have to be
          weighed against the serverless bundle budget.

extract(content) implements the auditor side for every Phase-1 channel.
Fail-open: an unmarkable document still serves (access was already decided
on-chain); failures log loudly and X-Watermarked reports the truth.
"""
from __future__ import annotations

import io
import logging
import re

_log = logging.getLogger("xinsere.watermark")

_MARK_PREFIX = "XIN-FWM-"          # namespaced so extraction can't false-positive
_ZW = {"0": "​", "1": "‌"}   # zero-width space / non-joiner
_ZW_START, _ZW_END = "⁠", "⁤"   # word-joiner / invisible-plus delimiters


def forensic_mark(entry_hash: str) -> str:
    """The embedded token for one access: XIN-FWM-<16 hex of the log entry>."""
    return _MARK_PREFIX + (entry_hash or "").removeprefix("0x")[:16]


# --- channel: PDF -------------------------------------------------------------

def pdf(content: bytes, mark: str) -> bytes:
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import DecodedStreamObject

    reader = PdfReader(io.BytesIO(content))
    writer = PdfWriter()
    writer.append(reader)
    writer.add_metadata({"/Keywords": mark})
    # Invisible per-page object: text in rendering mode 3 (no paint) at 0.1pt —
    # no visual footprint, but present in every page's content stream, so page
    # extraction or metadata scrubbing alone doesn't shed the mark.
    for page in writer.pages:
        existing = page.get_contents()
        data = existing.get_data() if existing is not None else b""
        stream = DecodedStreamObject()
        stream.set_data(data + b"\nBT /F1 0.1 Tf 3 Tr 0 0 Td (" + mark.encode() + b") Tj ET")
        page.replace_contents(stream)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# --- channel: text (zero-width steganography) ----------------------------------

def text(content: bytes, mark: str) -> bytes:
    bits = "".join(f"{b:08b}" for b in mark.encode())
    hidden = _ZW_START + "".join(_ZW[b] for b in bits) + _ZW_END
    return content + hidden.encode("utf-8")


# --- channel: image metadata (Phase 1) ------------------------------------------

def image(content: bytes, mark: str, base_type: str) -> tuple[bytes, str]:
    from PIL import Image, PngImagePlugin
    img = Image.open(io.BytesIO(content))
    # Phase 2 (2026-07-21): invisible keyed pixel-domain mark — survives
    # screenshots/rescale, which the metadata channels below never could.
    # Fail-open: embed() returns None on tiny/odd images and we keep serving
    # with metadata-only marks.
    try:
        import wm_pixel
        marked = wm_pixel.embed(img, mark[len(_MARK_PREFIX):])
        if marked is not None:
            img = marked
    except Exception:   # noqa: BLE001 — marking must never break the serve
        pass
    out = io.BytesIO()
    if base_type == "image/png" or img.mode in ("RGBA", "LA", "P"):
        info = PngImagePlugin.PngInfo()
        info.add_text("xinsere-fwm", mark)
        img.save(out, "PNG", optimize=True, pnginfo=info)
        return out.getvalue(), "image/png"
    exif = img.getexif()
    exif[0x9286] = mark                      # UserComment
    img.convert("RGB").save(out, "JPEG", quality=88, progressive=True, exif=exif.tobytes())
    return out.getvalue(), "image/jpeg"


# --- channel: Office OOXML (docx/xlsx/pptx = zip containers) --------------------

_OFFICE_TYPES = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
)
_CUSTOM_XML = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"'
               ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
               '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="XinsereFWM">'
               '<vt:lpwstr>%s</vt:lpwstr></property></Properties>')


def office(content: bytes, mark: str) -> bytes:
    """Embed the mark as a custom document property (docProps/custom.xml) —
    Office apps carry custom properties through edits and re-saves, unlike an
    alien zip entry. Wires the part into [Content_Types].xml and _rels/.rels."""
    import re as _re
    import zipfile
    src = zipfile.ZipFile(io.BytesIO(content))
    names = set(src.namelist())
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "docProps/custom.xml":
                data = data.replace(b"</Properties>",
                    ('<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="99" '
                     'name="XinsereFWM"><vt:lpwstr>' + mark + "</vt:lpwstr></property></Properties>"
                     ).encode())
            elif item.filename == "[Content_Types].xml" and "docProps/custom.xml" not in names:
                data = data.replace(b"</Types>",
                    b'<Override PartName="/docProps/custom.xml" ContentType="application/'
                    b'vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>')
            elif item.filename == "_rels/.rels" and "docProps/custom.xml" not in names:
                data = data.replace(b"</Relationships>",
                    b'<Relationship Id="rIdXinFWM" Type="http://schemas.openxmlformats.org/'
                    b'officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>'
                    b"</Relationships>")
            z.writestr(item, data)
        if "docProps/custom.xml" not in names:
            z.writestr("docProps/custom.xml", _CUSTOM_XML % mark)
    return out.getvalue()


# --- apply / extract -------------------------------------------------------------

def apply(content: bytes, serve_type: str, entry_hash: str) -> tuple[bytes, str, bool]:
    """Embed the forensic mark for one access. Returns (bytes, type, marked).
    Unchanged input on failure — deterrence layer, never blocks the view."""
    mark = forensic_mark(entry_hash)
    if len(mark) <= len(_MARK_PREFIX):
        return content, serve_type, False
    base = serve_type.split(";")[0].strip().lower()
    try:
        if base == "application/pdf":
            return pdf(content, mark), serve_type, True
        if base.startswith("text/"):
            return text(content, mark), serve_type, True
        if base.startswith("image/") and base not in ("image/svg+xml", "image/gif"):
            data, new_type = image(content, mark, base)
            return data, new_type, True
        if base in _OFFICE_TYPES:
            return office(content, mark), serve_type, True
    except Exception as exc:   # noqa: BLE001
        _log.warning("forensic mark failed type=%s: %s", serve_type, exc)
    return content, serve_type, False


def extract(content: bytes) -> list[str]:
    """Auditor side: pull every Phase-1 forensic ID out of a suspect file."""
    found = set(m.decode() for m in re.findall(
        (_MARK_PREFIX + r"[0-9a-f]{16}").encode(), content))
    # Office/zip containers compress their parts — scan each entry too.
    try:
        import zipfile
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            for name in z.namelist():
                for m in re.findall((_MARK_PREFIX + r"[0-9a-f]{16}").encode(), z.read(name)):
                    found.add(m.decode())
    except Exception:   # noqa: BLE001 — not a zip
        pass
    # zero-width channel
    try:
        s = content.decode("utf-8", "ignore")
        for blob in re.findall(f"{_ZW_START}([{_ZW['0']}{_ZW['1']}]+){_ZW_END}", s):
            bits = "".join("0" if c == _ZW["0"] else "1" for c in blob)
            raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
            m = raw.decode("ascii", "ignore")
            if m.startswith(_MARK_PREFIX):
                found.add(m)
    except Exception:   # noqa: BLE001
        pass
    # Phase-2 pixel-domain channel (screenshots/rescans of images).
    try:
        import wm_pixel
        hex16 = wm_pixel.detect(content)
        if hex16:
            found.add(_MARK_PREFIX + hex16)
    except Exception:   # noqa: BLE001
        pass
    return sorted(found)
