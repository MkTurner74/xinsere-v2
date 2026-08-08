"""Size-derived fragment count, as the /v1 API and the demo surface it.

The pipeline-side policy has its own coverage (lambdas/pipeline tests, group H).
What matters here is the layer above it: an API caller may pin a count, a bad
pin must be a 400 rather than a 500, and the count a file was actually stored
at is what gets written to the node row and handed back to the client — because
that value is what the UI's "N encrypted fragments" and the sales story both
read from.
"""
import pytest
from fastapi import HTTPException

import v1
from xinsere_pipeline import fragmenter
from xinsere_pipeline.config import MAX_FRAGMENT_COUNT, MIN_FRAGMENT_COUNT

MiB = 1024 * 1024


# --- the API's parse-and-reject guard ---------------------------------------

@pytest.mark.parametrize("raw", ["", "   ", None])
def test_absent_fragment_count_means_auto(raw):
    """Omitting the field must mean "size-derived", never a silent default of 7."""
    assert v1._requested_fragments(raw) is None


@pytest.mark.parametrize("raw,want", [("3", 3), ("7", 7), ("11", 11), ("64", 64), (" 16 ", 16)])
def test_valid_counts_parse(raw, want):
    assert v1._requested_fragments(raw) == want


@pytest.mark.parametrize("raw", ["2", "0", "-3", "65", "1000"])
def test_out_of_range_is_400_not_500(raw):
    """The range check is the only thing between a caller and a 1-fragment file."""
    with pytest.raises(HTTPException) as e:
        v1._requested_fragments(raw)
    assert e.value.status_code == 400
    assert str(MIN_FRAGMENT_COUNT) in e.value.detail and str(MAX_FRAGMENT_COUNT) in e.value.detail


@pytest.mark.parametrize("raw", ["abc", "7.5", "seven", "0x7"])
def test_non_integer_is_400(raw):
    with pytest.raises(HTTPException) as e:
        v1._requested_fragments(raw)
    assert e.value.status_code == 400


def test_both_write_endpoints_accept_the_override():
    import inspect
    for fn in (v1.store_file, v1.finalize_upload):
        assert "fragment_count" in inspect.signature(fn).parameters


def test_ping_advertises_the_policy(monkeypatch):
    """Integrators shouldn't have to guess the bounds — /v1/ping states them."""
    monkeypatch.setattr(v1, "configured_fragment_count", lambda: None)
    ctx = {"org_name": "O", "org_slug": "o", "service_user": "svc", "scopes": []}
    body = v1.ping(ctx)
    assert body["fragment_count"] == {"mode": "auto", "pinned": None,
                                      "min": MIN_FRAGMENT_COUNT, "max": MAX_FRAGMENT_COUNT}
    monkeypatch.setattr(v1, "configured_fragment_count", lambda: 7)
    assert v1.ping(ctx)["fragment_count"]["mode"] == "pinned"


# --- what the UI ends up displaying -----------------------------------------

def test_stored_count_is_what_reaches_the_node_row():
    """`frags` on the node row feeds every fragment count the UI shows (list
    tooltip, grid tile, details panel, /v1 responses, TAMS segment table). It
    must be the count the pipeline actually used, not a re-derivation."""
    view = v1._file_view({"id": "fil_x", "name": "a.mov", "parent": "p", "size": 9 * MiB,
                          "content_type": "video/quicktime", "sha": "abc",
                          "frags": fragmenter.plan_fragment_count(9 * MiB),
                          "created_at": "2026-08-08T00:00:00Z"})
    assert view["fragments"] == 7


def test_a_segment_sized_object_reports_fewer_than_a_large_one():
    """The visible consequence of the change: a 2s media segment and a 300MB
    master must not report the same fragment count."""
    segment = fragmenter.plan_fragment_count(700_000)     # ~2s of HLS
    master = fragmenter.plan_fragment_count(300 * MiB)
    assert segment == MIN_FRAGMENT_COUNT
    assert master > segment
