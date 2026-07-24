"""Format classification + the marking-policy matrix (2026-07-23).

Extends 0017 (watermark_downloads, blanket on/off) and 0022
(watermark_pixel_images, visible-vs-invisible) into a matrix: per FORMAT CLASS
x per SERVE CONTEXT (preview/download), should this be marked at all.
Production masters default UNMARKED (bit-perfect for editorial use);
distribution copies and documents default MARKED (traceable). An org's
`watermark_policy` JSONB only needs to list the class/context pairs it wants
to DEVIATE from these defaults — an empty/missing entry falls through to
DEFAULT_POLICY, so an org that never touches the matrix needs no backfill.

Resolution order (highest priority first), see `resolve()`:
  1. Per-share `serve_unmarked` override -> never mark.
  2. Org's 0017 kill switch (`watermark_downloads` == False) -> never mark.
  3. Org's watermark_policy[class][context], if the org set it.
  4. Built-in DEFAULT_POLICY[class][context].

Note: `watermark.apply()` currently has no video or audio channel — video/audio
classes are here so the matrix is ready when that lands (see the 2026-07-23
watermarking research spike), but today they're moot; only image_*/document
resolve to an actual embed.
"""
from __future__ import annotations

# Extension-first: codec/container intent (ProRes vs H.264, RAW vs JPEG) isn't
# reliably carried in the MIME type, so masters are identified by their common
# production extensions. Anything not listed here classifies by MIME prefix.
_MASTER_VIDEO_EXT = {".mov", ".mxf", ".braw", ".r3d", ".ari"}
_MASTER_IMAGE_EXT = {".dpx", ".exr", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".tif", ".tiff"}
_MASTER_AUDIO_EXT = {".wav", ".aif", ".aiff"}

_OFFICE_TYPES = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
)

CLASSES = ("video_master", "video_distribution", "image_master", "image_distribution",
          "audio_master", "audio_distribution", "document", "other")
CONTEXTS = ("preview", "download")

# Built-in defaults: masters stay bit-perfect (unmarked); distribution copies +
# documents are traced. "other" (unrecognized types) fails toward marking, the
# same direction the pre-matrix blanket flag already failed.
DEFAULT_POLICY = {
    "video_master":       {"preview": False, "download": False},
    "video_distribution": {"preview": True,  "download": True},
    "image_master":       {"preview": False, "download": False},
    "image_distribution": {"preview": True,  "download": True},
    "audio_master":       {"preview": False, "download": False},
    "audio_distribution": {"preview": True,  "download": True},
    "document":           {"preview": True,  "download": True},
    "other":              {"preview": True,  "download": True},
}


def classify(filename: str, content_type: str) -> str:
    """Best-effort format class for a file, from its extension and MIME type."""
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if filename and "." in filename else ""
    base = (content_type or "").split(";")[0].strip().lower()
    if ext in _MASTER_VIDEO_EXT:
        return "video_master"
    if ext in _MASTER_IMAGE_EXT:
        return "image_master"
    if ext in _MASTER_AUDIO_EXT:
        return "audio_master"
    if base.startswith("video/"):
        return "video_distribution"
    if base.startswith("image/") and base not in ("image/svg+xml", "image/gif"):
        return "image_distribution"
    if base.startswith("audio/"):
        return "audio_distribution"
    if base == "application/pdf" or base.startswith("text/") or base in _OFFICE_TYPES:
        return "document"
    return "other"


def resolve(filename: str, content_type: str, context: str,
           watermark_downloads: bool, watermark_policy: dict | None,
           share_serve_unmarked: bool = False) -> bool:
    """True if this serve should be marked. `watermark_downloads` is the org's
    0017 kill switch (already resolved with its own fail-toward-marking
    default upstream); `watermark_policy` is the org's raw matrix JSONB
    (may be None/{}/partial)."""
    if share_serve_unmarked:
        return False
    if not watermark_downloads:
        return False
    cls = classify(filename, content_type)
    override = (watermark_policy or {}).get(cls, {})
    if context in override:
        return bool(override[context])
    return DEFAULT_POLICY[cls][context]
