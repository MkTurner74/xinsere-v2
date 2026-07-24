"""Marking-policy matrix (0023) — format classification and resolution order."""
import format_policy as fp


def test_classify_by_master_extension_beats_mime():
    # A .mov is classified as a video MASTER even though its MIME is a generic
    # video/* type — codec/container intent isn't reliably in the MIME.
    assert fp.classify("dailies_reel.mov", "video/quicktime") == "video_master"
    assert fp.classify("still.dpx", "application/octet-stream") == "image_master"
    assert fp.classify("mix.wav", "audio/wav") == "audio_master"


def test_classify_distribution_and_document_by_mime():
    assert fp.classify("clip.mp4", "video/mp4") == "video_distribution"
    assert fp.classify("photo.jpg", "image/jpeg") == "image_distribution"
    assert fp.classify("deck.pptx",
                       "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                       ) == "document"
    assert fp.classify("report.pdf", "application/pdf") == "document"
    assert fp.classify("weird.xyz", "application/x-unknown") == "other"


def test_default_policy_unmarks_masters_marks_distribution():
    for cls in ("video_master", "image_master", "audio_master"):
        assert fp.DEFAULT_POLICY[cls]["preview"] is False
        assert fp.DEFAULT_POLICY[cls]["download"] is False
    for cls in ("video_distribution", "image_distribution", "audio_distribution", "document"):
        assert fp.DEFAULT_POLICY[cls]["preview"] is True
        assert fp.DEFAULT_POLICY[cls]["download"] is True


def test_resolve_falls_through_to_default_when_org_has_no_override():
    assert fp.resolve("master.dpx", "application/octet-stream", "download",
                      watermark_downloads=True, watermark_policy={}) is False
    assert fp.resolve("photo.jpg", "image/jpeg", "download",
                      watermark_downloads=True, watermark_policy=None) is True


def test_resolve_honors_org_override_over_default():
    policy = {"image_master": {"download": True}}   # org wants masters marked on download
    assert fp.resolve("raw.dng", "image/x-adobe-dng", "download",
                      watermark_downloads=True, watermark_policy=policy) is True
    # preview wasn't overridden — still falls through to the default (unmarked)
    assert fp.resolve("raw.dng", "image/x-adobe-dng", "preview",
                      watermark_downloads=True, watermark_policy=policy) is False


def test_resolve_kill_switch_beats_everything():
    policy = {"document": {"download": True}}
    assert fp.resolve("report.pdf", "application/pdf", "download",
                      watermark_downloads=False, watermark_policy=policy) is False


def test_resolve_share_override_beats_everything_including_kill_switch_state():
    assert fp.resolve("report.pdf", "application/pdf", "download",
                      watermark_downloads=True, watermark_policy=None,
                      share_serve_unmarked=True) is False
