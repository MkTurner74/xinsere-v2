"""Phase-2 forensic watermark: invisible, keyed, PIXEL-domain (survives screenshots).

Phase 1 marked images in metadata only (EXIF/tEXt) — a screen grab creates new
pixels in a new file, so nothing carried across (team finding, 2026-07-21). This
module embeds the forensic ID into the image CONTENT with a blind spread-spectrum
scheme in the global DCT domain, numpy-only (no OpenCV — the bundling question
that parked Phase 2).

Scheme (v3 — after the first cut shipped visibly mottled, Mark's flower photo)
------------------------------------------------------------------------------
* Luma only. The Y channel is resized to a canonical CANON x CANON grid and
  full-frame orthonormal DCT-II'd (matmul with a cached basis — no scipy).
* A PRNG seeded from SHA-256(XINSERE_WM_KEY) picks CHIPS mid-frequency
  coefficient positions per payload bit and a +/-1 chip per position — without
  the key the mark can be neither read nor surgically stripped.
* Payload = 64-bit forensic ID (16-hex tail of XIN-FWM-...) + CRC-32 = 96 bits.
* EMBEDDING is informed and closed-loop:
    - raw delta shaped along the image's own spectrum (capped, so one huge edge
      coefficient can't ring the frame);
    - a HARD per-pixel ceiling from an ERODED local-activity map: flat pixels
      allow only +/-D_FLAT (invisible on black), texture up to +/-D_TEX, and
      erosion stops the ceiling bleeding past object edges (no halo);
    - the loop measures, per bit, the NORMALIZED correlation the ceiling-clipped
      delta actually delivers — exactly what the detector will compute — and
      boosts only the bits that fall short. Every image gets the smallest
      footprint that still detects.
* DETECTION is blind and scale-invariant: canonicalize, DCT, soft-sign
  normalize (tames the heavy-tailed host spectrum), correlate per bit, then
  CHASE-DECODE: if the CRC doesn't lock, retry with the weakest bits flipped
  (subsets up to CHASE_DEPTH of the CHASE_POOL least-confident bits). ~800
  tries against a 2^-32 gate keeps false accepts ~4e-7.

Honest limits (for the team): survives rescale + re-encode (the screenshot
case) and light touch-ups; it does NOT survive heavy cropping or a grab where
the image is a small region among UI chrome — crop the suspect to the image
content before tracing. A perfectly flat image has nowhere to hide payload and
may not mark. Detection needs the key that embedded.
"""
from __future__ import annotations

import binascii
import hashlib
import io
import itertools
import logging
import os

_log = logging.getLogger("xinsere.wm_pixel")

CANON = 512                      # canonical analysis grid (px)
PAYLOAD_BITS = 96                # 64-bit ID + CRC-32
CHIPS = 200                      # coefficients per payload bit (96*200 fits band)
ALPHA = float(os.environ.get("XINSERE_WM_ALPHA", "0.12"))   # base shaping gain
ACT_REF = 8.0                    # local activity (levels) = fully textured
D_FLAT = 1.5                     # per-pixel delta ceiling on flat areas (levels)
D_TEX = 14.0                     # ceiling in full texture (masked by the texture)
T_NORM = 0.16                    # per-bit normalized-correlation target (clean)
KB_MAX = 60.0                    # max per-bit boost in the informed loop
LOOP_ITERS = 10                  # informed-embedding refinement passes
CHASE_POOL = 16                  # weakest bits eligible for chase flipping
CHASE_DEPTH = 5                  # max simultaneous flips (C(16,1..5)=6884 tries)
MIN_DIM = 128                    # skip pixel-marking tiny images
_BAND_LO, _BAND_HI = 12, 240     # u+v ring: low enough to survive downscale,
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
    crc = (binascii.crc32(ident) & 0xFFFFFFFF).to_bytes(4, "big")
    raw = ident + crc                                       # 12 bytes = 96 bits
    return np.unpackbits(np.frombuffer(raw, dtype=np.uint8)).astype(np.float64) * 2 - 1


def _crc_ok(raw: bytes) -> bool:
    return (binascii.crc32(raw[:8]) & 0xFFFFFFFF).to_bytes(4, "big") == raw[8:12]


def _box_mean(a, r: int):
    """Box-filter mean with window (2r+1)^2 via an integral image (edge-clamped)."""
    np = _np()
    h, w = a.shape
    ii = np.zeros((h + 1, w + 1))
    np.cumsum(np.cumsum(a, axis=0), axis=1, out=ii[1:, 1:])
    y0 = np.clip(np.arange(h) - r, 0, h); y1 = np.clip(np.arange(h) + r + 1, 0, h)
    x0 = np.clip(np.arange(w) - r, 0, w); x1 = np.clip(np.arange(w) + r + 1, 0, w)
    s = (ii[y1][:, x1] - ii[y0][:, x1] - ii[y1][:, x0] + ii[y0][:, x0])
    area = (y1 - y0)[:, None] * (x1 - x0)[None, :]
    return s / area


def _erode(a, r: int):
    """Grayscale min-filter (square window) by shifted np.minimum passes —
    pulls the activity map BACK from object edges so the delta ceiling never
    bleeds onto the flat side of a boundary (the v2 halo)."""
    np = _np()
    out = a
    for axis in (0, 1):
        m = out
        for s in range(1, r + 1):
            m = np.minimum(m, np.roll(out, s, axis=axis))
            m = np.minimum(m, np.roll(out, -s, axis=axis))
        out = m
    return out


def _norm_bits(c, sign):
    """Per-bit soft-sign correlation: c/(|c|+q) tames the heavy-tailed host
    spectrum (structured images have huge coefficients a linear detector can
    never out-shout), then correlate against the keyed chips."""
    np = _np()
    q = float(np.median(np.abs(c))) + 1e-6
    n = c / (np.abs(c) + q)
    return (n * sign).reshape(PAYLOAD_BITS, CHIPS).mean(axis=1)


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
        sign = np.repeat(_payload_bits(hex16), CHIPS) * chips

        # Raw shaped delta: rides the image's spectrum, capped so one huge
        # edge coefficient can't ring the whole frame.
        amp = ALPHA * (np.minimum(np.abs(sel), 3.0 * sigma) + 0.05 * sigma)

        # Per-pixel delta ceiling from an ERODED activity map: flat stays flat,
        # texture absorbs the mark, edges don't halo.
        act = _erode(_box_mean(np.abs(y_can - _box_mean(y_can, 2)), 3), 1)
        allowed = D_FLAT + (D_TEX - D_FLAT) * np.clip(act / ACT_REF, 0.0, 1.0)

        # Informed clip-aware loop against the detector's own normalized metric:
        # boost only bits that fall short; measure AFTER the ceiling clip so the
        # loop can never promise energy the ceiling then removes.
        kb = np.ones(PAYLOAD_BITS)
        final = None
        for _ in range(LOOP_ITERS):
            delta_c = np.zeros_like(coeff)
            delta_c[us, vs] = amp * sign * np.repeat(kb, CHIPS)
            final = np.clip(d.T @ delta_c @ d, -allowed, allowed)
            nb = _norm_bits((coeff + d @ final @ d.T)[us, vs], sign)
            short = nb < T_NORM
            if not short.any():
                break
            kb[short] *= np.clip(T_NORM / np.maximum(nb[short], T_NORM / 6.0), 1.0, 3.0)
            kb = np.minimum(kb, KB_MAX)

        # Apply at ORIGINAL resolution, float precision end-to-end.
        delta_full = np.asarray(
            Image.fromarray(final.astype("float32"), "F")
                 .resize((img.width, img.height), Image.BILINEAR), dtype=np.float64)
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
    or None. Chase decoding flips the least-confident bits against the CRC-32
    gate, so a handful of weak bits (flat images, hard screenshots) still
    resolve; false accepts stay ~4e-7."""
    try:
        np = _np()
        from PIL import Image
        img = Image.open(io.BytesIO(content))
        if img.width < MIN_DIM // 2 or img.height < MIN_DIM // 2:
            return None
        y_can = np.asarray(img.convert("L").resize((CANON, CANON), Image.BILINEAR),
                           dtype=np.float64)
        d = _dct_matrix(CANON)
        coeff = d @ y_can @ d.T
        us, vs, chips = _positions()
        corr = _norm_bits(coeff[us, vs], chips)
        bits = (corr > 0).astype(np.uint8)

        def _try(b) -> str | None:
            raw = np.packbits(b).tobytes()                   # 12 bytes
            return raw[:8].hex() if _crc_ok(raw) else None

        got = _try(bits)
        if got:
            return got
        weakest = np.argsort(np.abs(corr))[:CHASE_POOL]
        for k in range(1, CHASE_DEPTH + 1):
            for combo in itertools.combinations(weakest, k):
                flipped = bits.copy()
                flipped[list(combo)] ^= 1
                got = _try(flipped)
                if got:
                    return got
        return None
    except Exception:   # noqa: BLE001 — not an image / unreadable
        return None
