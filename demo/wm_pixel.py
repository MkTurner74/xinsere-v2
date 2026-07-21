"""Phase-2 forensic watermark: invisible, keyed, PIXEL-domain (survives screenshots).

Phase 1 marked images in metadata only (EXIF/tEXt) — a screen grab creates new
pixels in a new file, so nothing carried across (team finding, 2026-07-21). This
module embeds the forensic ID into the image CONTENT with a blind spread-spectrum
scheme in the global DCT domain, numpy-only (no OpenCV — the bundling question
that parked Phase 2).

Scheme
------
* Luma only. The image's Y channel is resized to a canonical CANON x CANON grid,
  full-frame orthonormal DCT-II (matmul with a cached basis — no scipy).
* A PRNG seeded from SHA-256(XINSERE_WM_KEY) picks CHIPS mid-frequency
  coefficient positions per payload bit and a +/-1 chip sign for each — without
  the key the mark can be neither read nor surgically stripped.
* Payload = 64-bit forensic ID (the 16-hex tail of XIN-FWM-...) + CRC-16 = 80
  bits. Each bit ADDs alpha*sigma*chip to its coefficients; the delta is
  inverse-DCT'd, resized back to the original resolution, and added to Y.
* Detection is blind: canonicalize the suspect, DCT, correlate each bit's chips,
  CRC gate. Canonicalization makes it scale-invariant, so a rescaled/re-encoded
  screenshot of the IMAGE still resolves.

Honest limits (documented for the team): survives rescale + re-encode (the
screenshot case) and light touch-ups; it does NOT survive heavy cropping or a
grab where the image is a small region among UI chrome — crop the suspect to
the image content before tracing. Detection needs the same key that embedded.
"""
from __future__ import annotations

import binascii
import hashlib
import io
import logging
import os

_log = logging.getLogger("xinsere.wm_pixel")

CANON = 512                      # canonical analysis grid (px)
CHIPS = 128                      # coefficients per payload bit
PAYLOAD_BITS = 80                # 64-bit ID + CRC-16
ALPHA = float(os.environ.get("XINSERE_WM_ALPHA", "1.1"))   # embed strength (x sigma)
MIN_DIM = 128                    # skip pixel-marking tiny images
_BAND_LO, _BAND_HI = 12, 160     # u+v ring: low enough to survive downscale,
                                 # high enough to stay invisible
_KEY = os.environ.get("XINSERE_WM_KEY", "xinsere-fwm-v1-default")

_cache: dict = {}


def _np():
    import numpy as np
    return np


def _dct_matrix(n: int):
    """Orthonormal DCT-II basis (n x n): X_dct = D @ X @ D.T."""
    np = _np()
    if ("D", n) not in _cache:
        k = np.arange(n).reshape(-1, 1)
        i = np.arange(n).reshape(1, -1)
        d = np.cos(np.pi * (2 * i + 1) * k / (2 * n)) * np.sqrt(2.0 / n)
        d[0, :] = np.sqrt(1.0 / n)
        _cache[("D", n)] = d
    return _cache[("D", n)]


def _positions():
    """(PAYLOAD_BITS*CHIPS) keyed coefficient positions + chip signs."""
    np = _np()
    if "pos" not in _cache:
        seed = int.from_bytes(hashlib.sha256(_KEY.encode()).digest()[:8], "big")
        rng = np.random.default_rng(seed)
        band = [(u, v) for u in range(CANON) for v in range(CANON)
                if _BAND_LO <= u + v <= _BAND_HI]
        idx = rng.permutation(len(band))[:PAYLOAD_BITS * CHIPS]
        pos = np.array([band[i] for i in idx])              # (bits*chips, 2)
        chips = rng.choice([-1.0, 1.0], size=PAYLOAD_BITS * CHIPS)
        _cache["pos"] = (pos[:, 0], pos[:, 1], chips)
    return _cache["pos"]


def _payload_bits(hex16: str):
    np = _np()
    ident = bytes.fromhex(hex16)                            # 8 bytes
    crc = binascii.crc_hqx(ident, 0xFFFF).to_bytes(2, "big")
    raw = ident + crc                                       # 10 bytes = 80 bits
    return np.unpackbits(np.frombuffer(raw, dtype=np.uint8)).astype(np.float64) * 2 - 1


def _canon_luma(img):
    """PIL image -> (float64 CANON x CANON luma, original-size float64 luma)."""
    np = _np()
    from PIL import Image
    y_full = np.asarray(img.convert("L"), dtype=np.float64)
    y_can = np.asarray(img.convert("L").resize((CANON, CANON), Image.BILINEAR),
                       dtype=np.float64)
    return y_can, y_full


def embed(img, hex16: str):
    """Embed the 16-hex forensic ID into a PIL image's pixels.
    Returns a new PIL Image (mode preserved incl. alpha), or None to skip
    (image too small, or anything unexpected — caller falls back to
    metadata-only, never blocks the serve)."""
    try:
        np = _np()
        from PIL import Image
        if img.width < MIN_DIM or img.height < MIN_DIM:
            return None
        alpha_ch = img.getchannel("A") if img.mode in ("RGBA", "LA") else None
        rgb = img.convert("RGB")
        ycc = rgb.convert("YCbCr")
        y, cb, cr = ycc.split()
        y_full = np.asarray(y, dtype=np.float64)
        y_can = np.asarray(y.resize((CANON, CANON), Image.BILINEAR), dtype=np.float64)

        d = _dct_matrix(CANON)
        coeff = d @ y_can @ d.T
        us, vs, chips = _positions()
        sel = coeff[us, vs]
        sigma = max(float(np.std(sel)), 1.0)
        bits = np.repeat(_payload_bits(hex16), CHIPS)
        delta_c = np.zeros_like(coeff)
        delta_c[us, vs] = ALPHA * sigma * chips * bits
        delta = d.T @ delta_c @ d                            # inverse DCT of the delta

        # Apply at ORIGINAL resolution so we never resample the picture itself.
        delta_img = Image.fromarray(
            np.clip(delta + 128.0, 0, 255).astype("uint8"), "L"
        ).resize((img.width, img.height), Image.BILINEAR)
        delta_full = np.asarray(delta_img, dtype=np.float64) - 128.0
        y_new = np.clip(y_full + delta_full, 0, 255).astype("uint8")

        out = Image.merge("YCbCr", (Image.fromarray(y_new, "L"), cb, cr)).convert("RGB")
        if alpha_ch is not None:
            out = out.convert("RGBA")
            out.putalpha(alpha_ch)
        return out
    except Exception as exc:   # noqa: BLE001 — marking must never break serving
        _log.warning("pixel embed skipped: %s", exc)
        return None


def detect(content: bytes) -> str | None:
    """Blind extraction from suspect image bytes. Returns the 16-hex forensic ID
    or None. CRC-16 gates false positives (~2^-16 on unmarked input)."""
    try:
        np = _np()
        from PIL import Image
        img = Image.open(io.BytesIO(content))
        if img.width < MIN_DIM // 2 or img.height < MIN_DIM // 2:
            return None
        y_can, _ = _canon_luma(img)
        d = _dct_matrix(CANON)
        coeff = d @ y_can @ d.T
        us, vs, chips = _positions()
        corr = (coeff[us, vs] * chips).reshape(PAYLOAD_BITS, CHIPS).sum(axis=1)
        bits = (corr > 0).astype(np.uint8)
        raw = np.packbits(bits).tobytes()                    # 10 bytes
        ident, crc = raw[:8], raw[8:10]
        if binascii.crc_hqx(ident, 0xFFFF).to_bytes(2, "big") != crc:
            return None
        return ident.hex()
    except Exception:   # noqa: BLE001 — not an image / unreadable
        return None
