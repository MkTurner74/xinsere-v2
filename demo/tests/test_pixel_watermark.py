"""Phase-2 pixel-domain forensic watermark (wm_pixel) — the screenshot case.

Proves: embed/detect roundtrip; survival of a simulated SCREEN GRAB (rescale +
JPEG re-encode, both down and up); no false positives on unmarked images (CRC
gate); key dependence (wrong key reads nothing); imperceptibility bounds; tiny
images skip pixel marking but keep the Phase-1 metadata mark; and the
watermark.extract() auditor path surfaces the pixel mark end-to-end.
"""
import io

import numpy as np
import pytest
from PIL import Image

import watermark
import wm_pixel

MARK16 = "daf2bf0f35850b7e"


def _photo(w=1400, h=900, seed=7):
    """Deterministic photo-like test image: gradients + structure + noise."""
    rng = np.random.default_rng(seed)
    x = np.linspace(0, 1, w)[None, :]
    y = np.linspace(0, 1, h)[:, None]
    base = 120 + 80 * np.sin(6 * x + 2 * y) * np.cos(3 * y)
    tex = rng.normal(0, 12, (h, w))
    lum = np.clip(base + tex, 0, 255).astype("uint8")
    rgb = np.stack([lum,
                    np.clip(lum * 0.9 + 10, 0, 255).astype("uint8"),
                    np.clip(lum * 0.8 + 25, 0, 255).astype("uint8")], axis=-1)
    return Image.fromarray(rgb, "RGB")


def _jpeg(img, q=85):
    out = io.BytesIO()
    img.convert("RGB").save(out, "JPEG", quality=q)
    return out.getvalue()


@pytest.fixture(autouse=True)
def _stable_key():
    old_key = wm_pixel._KEY
    wm_pixel._KEY = "test-key-alpha"
    wm_pixel._cache.clear()
    yield
    wm_pixel._KEY = old_key
    wm_pixel._cache.clear()


def test_roundtrip_embed_detect():
    marked = wm_pixel.embed(_photo(), MARK16)
    assert marked is not None
    assert wm_pixel.detect(_jpeg(marked, 92)) == MARK16


def test_survives_screenshot_downscale_reencode():
    marked = wm_pixel.embed(_photo(), MARK16)
    grabbed = Image.open(io.BytesIO(_jpeg(marked, 88)))
    # A screen grab: rendered smaller than native, re-encoded by the grabber.
    small = grabbed.resize((int(grabbed.width * 0.61), int(grabbed.height * 0.61)),
                           Image.BILINEAR)
    assert wm_pixel.detect(_jpeg(small, 80)) == MARK16


def test_survives_upscale_and_png_resave():
    marked = wm_pixel.embed(_photo(w=900, h=700), MARK16)
    big = Image.open(io.BytesIO(_jpeg(marked, 90))).resize((1280, 995), Image.BILINEAR)
    out = io.BytesIO(); big.save(out, "PNG")
    assert wm_pixel.detect(out.getvalue()) == MARK16


def test_no_false_positive_on_unmarked_image():
    assert wm_pixel.detect(_jpeg(_photo(seed=99), 90)) is None


def test_wrong_key_reads_nothing():
    marked = wm_pixel.embed(_photo(), MARK16)
    blob = _jpeg(marked, 92)
    wm_pixel._KEY = "a-different-key"
    wm_pixel._cache.clear()
    assert wm_pixel.detect(blob) is None


def _flower_on_black(w=1300, h=1300, seed=3):
    """The case that caught v1: a detailed bright subject on a FLAT black
    background — any energy dumped into the background is instantly visible."""
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:h, 0:w]
    cx, cy, r = w / 2, h / 2, min(w, h) * 0.34
    dist = np.sqrt((xx - cx) ** 2 + (yy - cy) ** 2)
    petals = (np.sin(np.arctan2(yy - cy, xx - cx) * 9) * 0.2 + 1.0) * r
    inside = dist < petals
    lum = np.zeros((h, w))
    lum[inside] = 150 + 60 * np.sin(dist[inside] / 9) + rng.normal(0, 14, int(inside.sum()))
    rgb = np.stack([np.clip(lum * 1.15, 0, 255), np.clip(lum * 0.55, 0, 255),
                    np.clip(lum * 0.55, 0, 255)], axis=-1).astype("uint8")
    return Image.fromarray(rgb, "RGB"), inside


def test_imperceptibility_bounds():
    src = _photo()
    marked = wm_pixel.embed(src, MARK16)
    a = np.asarray(src.convert("L"), dtype=np.float64)
    b = np.asarray(marked.convert("L"), dtype=np.float64)
    diff = np.abs(a - b)
    assert diff.mean() < 1.8          # invisible on average
    assert diff.max() <= wm_pixel.D_TEX + 2   # ceiling honored (+resize interp)
    mse = ((a - b) ** 2).mean()
    psnr = 10 * np.log10(255 ** 2 / max(mse, 1e-9))
    assert psnr > 41                  # transparent, not merely tolerable


def test_flat_background_stays_clean():
    """v1 regression (Mark's flower screenshot): flat black must stay black.
    The FAR background (outside a dilated edge band) is the visibility-critical
    region — a thin ring hugging the high-contrast petal edge is perceptually
    edge-masked and allowed a little more."""
    src, inside = _flower_on_black()
    marked = wm_pixel.embed(src, MARK16)
    a = np.asarray(src.convert("L"), dtype=np.float64)
    b = np.asarray(marked.convert("L"), dtype=np.float64)
    diff = np.abs(a - b)
    near_edge = wm_pixel._box_mean(inside.astype(float), 14) > 0.001
    far_bg = ~near_edge
    assert diff[far_bg].max() <= 2.0     # imperceptible on flat black
    assert diff[far_bg].mean() < 0.6
    assert diff[~inside].mean() < 1.0    # whole background incl. edge ring


def test_flower_on_black_still_traces_after_screenshot():
    src, _ = _flower_on_black()
    marked = wm_pixel.embed(src, MARK16)
    grabbed = Image.open(io.BytesIO(_jpeg(marked, 88)))
    small = grabbed.resize((int(grabbed.width * 0.66), int(grabbed.height * 0.66)),
                           Image.BILINEAR)
    assert wm_pixel.detect(_jpeg(small, 82)) == MARK16


def test_tiny_image_skips_pixel_mark_keeps_metadata():
    tiny = _photo(w=96, h=96)
    assert wm_pixel.embed(tiny, MARK16) is None
    out = io.BytesIO(); tiny.save(out, "PNG")
    data, ctype = watermark.image(out.getvalue(), "XIN-FWM-" + MARK16, "image/png")
    assert ("XIN-FWM-" + MARK16).encode() in data          # tEXt metadata mark


def test_alpha_channel_preserved():
    rgba = _photo(w=600, h=400).convert("RGBA")
    alpha = Image.new("L", rgba.size, 180)
    rgba.putalpha(alpha)
    marked = wm_pixel.embed(rgba, MARK16)
    assert marked.mode == "RGBA"
    assert np.asarray(marked.getchannel("A")).min() == 180


def test_auditor_extract_end_to_end():
    src = io.BytesIO(); _photo().save(src, "PNG")
    served, ctype = watermark.image(src.getvalue(), "XIN-FWM-" + MARK16, "image/jpeg")
    # Strip metadata the way a screenshot would: pixels only, new file.
    img = Image.open(io.BytesIO(served))
    pixels_only = Image.new("RGB", img.size)
    pixels_only.paste(img)
    grabbed = io.BytesIO(); pixels_only.save(grabbed, "PNG")
    assert ("XIN-FWM-" + MARK16) in watermark.extract(grabbed.getvalue())
