"""TAMS demo — timeline model, timerange queries, playlist ingest, access gate.

The interesting surface here is not the HTTP layer but the four things that
decide whether a time-addressable store is correct: timestamp round-tripping,
half-open range overlap, mapping node names back to segments in time order, and
a gate that fails closed. Those are what these cover.
"""
import pytest

import tams

NS = 1_000_000_000


# --- timestamps and timeranges ------------------------------------------------

def test_timestamp_roundtrip():
    assert tams.fmt_ts(3 * NS + 500) == "3:500"
    assert tams.parse_ts("3:500") == 3 * NS + 500
    assert tams.parse_ts("7") == 7 * NS           # bare seconds, no nanos
    assert tams.parse_ts(tams.fmt_ts(123456789012345)) == 123456789012345


def test_timerange_accepts_the_shapes_callers_actually_send():
    assert tams.fmt_timerange(0, 10 * NS) == "[0:0_10:0)"
    # A space is what people type when they can't find the underscore, and an
    # absolute TAI range is long enough that they will retype it. Accept it.
    for text in ("[0:0_10:0)", "0:0_10:0", "(0:0_10:0]", "0:0 10:0", "[0:0 10:0)"):
        assert tams.parse_timerange(text) == (0, 10 * NS)
    assert tams.parse_timerange("2:0/4:0") == (2 * NS, 4 * NS)


def test_timerange_errors_name_the_offending_value():
    """These strings surface verbatim in the UI, so they have to be actionable —
    'Request failed' is what we are fixing."""
    with pytest.raises(ValueError, match="only one timestamp"):
        tams.parse_timerange("0:0")
    with pytest.raises(ValueError, match="ends before it starts"):
        tams.parse_timerange("[10:0_2:0)")
    with pytest.raises(ValueError, match="Pick a from/to segment"):
        tams.parse_timerange("")


@pytest.mark.parametrize("bad", ["", "0:0", "abc_def", "[10:0_2:0)"])
def test_timerange_rejects_nonsense(bad):
    """A bad range must raise, not silently match everything — an over-broad
    query on a rights-gated store is a disclosure bug, not a UX bug."""
    with pytest.raises(ValueError):
        tams.parse_timerange(bad)


# --- node names <-> segments --------------------------------------------------

def _seg_name(start_ns, end_ns):
    return f"s{start_ns:020d}_e{end_ns:020d}"


def test_segment_names_sort_lexically_into_time_order():
    """The whole index design rests on this: zero-padded names mean the child
    listing comes back in time order without a sort key."""
    early = _seg_name(2 * NS, 4 * NS)
    late = _seg_name(10 * NS, 12 * NS)
    assert sorted([late, early]) == [early, late]
    assert tams._seg_bounds(early) == (2 * NS, 4 * NS)
    assert tams._seg_bounds(tams.META_PREFIX + "{}") is None


def _nodes():
    meta = tams.META_PREFIX + '{"label":"CAM 1","source_id":"venue-a","essence":"video"}'
    return [
        {"id": "fil_m", "type": "file", "name": meta, "file_id": None, "size": None,
         "frags": None, "sha": None, "content_type": "application/json"},
        {"id": "fil_b", "type": "file", "name": _seg_name(10 * NS, 12 * NS),
         "file_id": "obj_b", "size": 20, "frags": 7, "sha": "bb", "content_type": "video/mp2t"},
        {"id": "fil_a", "type": "file", "name": _seg_name(2 * NS, 4 * NS),
         "file_id": "obj_a", "size": 10, "frags": 7, "sha": "aa", "content_type": "video/mp2t"},
    ]


def test_flow_metadata_rides_on_the_marker_node():
    assert tams._flow_meta(_nodes())["label"] == "CAM 1"
    assert tams._flow_meta([]) == {}                 # no marker -> empty, never a crash


def test_marker_node_is_never_mistaken_for_a_segment():
    segs = tams._segments(_nodes())
    assert [s["object_id"] for s in segs] == ["obj_a", "obj_b"]
    assert segs[0]["timerange"] == "[2:0_4:0)"


@pytest.mark.parametrize("lo,hi,expected", [
    (2 * NS, 3 * NS, ["obj_a"]),            # inside the first segment
    (3 * NS, 11 * NS, ["obj_a", "obj_b"]),  # spanning the gap between them
    (4 * NS, 10 * NS, []),                  # half-open: touching a boundary is not overlap
    (0, 1 * NS, []),                        # before everything
])
def test_half_open_overlap(lo, hi, expected):
    segs = tams._segments(_nodes())
    assert [s["object_id"] for s in segs if s["start_ns"] < hi and s["end_ns"] > lo] == expected


# --- HLS ingest ---------------------------------------------------------------

MEDIA = """#EXTM3U
#EXT-X-TARGETDURATION:10
#EXTINF:9.009,
seg0.ts
#EXTINF:9.009,
seg1.ts
#EXTINF:4.5,
sub/seg2.ts
#EXT-X-ENDLIST
"""

MASTER = """#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360
low/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2400000
high/index.m3u8
"""


def test_media_playlist_urls_resolve_against_the_playlist():
    got = tams._parse_media_playlist("https://h.example/v/index.m3u8", MEDIA, 10)
    assert [u for u, _ in got] == [
        "https://h.example/v/seg0.ts",
        "https://h.example/v/seg1.ts",
        "https://h.example/v/sub/seg2.ts",
    ]
    assert round(got[0][1], 3) == 9.009


def test_segment_limit_is_honoured():
    """Ingest is bounded so a demo can't run past the function timeout."""
    assert len(tams._parse_media_playlist("https://h.example/i.m3u8", MEDIA, 2)) == 2


def test_master_playlist_follows_its_first_variant(monkeypatch):
    seen = {}

    def fake_fetch(url):
        seen["url"] = url
        return MEDIA

    monkeypatch.setattr(tams, "_fetch_text", fake_fetch)
    url, _text = tams._resolve_variant("https://h.example/master.m3u8", MASTER)
    assert url == seen["url"] == "https://h.example/low/index.m3u8"


def test_media_playlist_is_not_treated_as_a_master():
    url, text = tams._resolve_variant("https://h.example/v/index.m3u8", MEDIA)
    assert url == "https://h.example/v/index.m3u8" and text == MEDIA


# --- shared timelines ---------------------------------------------------------

def _flow_folder(fid, source_id, origin_ns):
    import json
    meta = tams.META_PREFIX + json.dumps({"source_id": source_id, "origin_ns": origin_ns})
    return fid, [{"id": f"{fid}_m", "type": "file", "name": meta, "file_id": None,
                  "size": None, "frags": None, "sha": None, "content_type": "application/json"}]


def _wire_flows(monkeypatch, folders):
    """folders: [(flow_id, source_id, origin_ns)] under a fake flows root."""
    root_children = [{"id": fid, "type": "folder", "name": fid, "parent": "root",
                      "owner": "u", "created_at": None, "file_id": None, "sha": None,
                      "size": None, "frags": None, "content_type": None, "deleted_at": None}
                     for fid, _src, _o in folders]
    kids = {}
    for fid, src, origin in folders:
        _id, meta_nodes = _flow_folder(fid, src, origin)
        kids[fid] = meta_nodes

    def children(_token, parent):
        return root_children if parent == "flows_root" else kids.get(parent, [])

    monkeypatch.setattr(tams.supa, "children", children)


def test_a_new_source_establishes_its_own_origin(monkeypatch):
    _wire_flows(monkeypatch, [])
    assert tams._source_origin("t", "flows_root", "venue-a") is None


def test_later_flows_inherit_the_source_origin(monkeypatch):
    """A Source IS a shared timeline. If each ingest started at its own wall
    clock, two cameras nominally on one timeline would sit hours apart and the
    multicam claim would be false."""
    _wire_flows(monkeypatch, [("fld_1", "venue-a", 1000 * NS)])
    assert tams._source_origin("t", "flows_root", "venue-a") == 1000 * NS


def test_the_earliest_origin_wins(monkeypatch):
    _wire_flows(monkeypatch, [("fld_1", "venue-a", 5000 * NS), ("fld_2", "venue-a", 1000 * NS)])
    assert tams._source_origin("t", "flows_root", "venue-a") == 1000 * NS


def test_a_different_source_is_a_different_timeline(monkeypatch):
    _wire_flows(monkeypatch, [("fld_1", "venue-a", 1000 * NS)])
    assert tams._source_origin("t", "flows_root", "venue-b") is None


def test_a_flow_with_unreadable_metadata_is_skipped(monkeypatch):
    _wire_flows(monkeypatch, [("fld_1", "venue-a", "not-a-number"),
                              ("fld_2", "venue-a", 2000 * NS)])
    assert tams._source_origin("t", "flows_root", "venue-a") == 2000 * NS


# --- the access gate ----------------------------------------------------------

class _Chain:
    def __init__(self, answer=False, boom=False):
        self.answer, self.boom, self.calls = answer, boom, 0

    def verify(self, _file_id, _grantee):
        self.calls += 1
        if self.boom:
            raise RuntimeError("rpc down")
        return (self.answer, 1)


@pytest.fixture(autouse=True)
def _clear_cache():
    tams._verify_cache.clear()
    yield
    tams._verify_cache.clear()


def test_stranger_with_no_grant_is_denied(monkeypatch):
    monkeypatch.setattr(tams, "CHAIN", _Chain(answer=False))
    allowed, _ms, _cached, source = tams._verify("obj", "stranger", is_owner=False)
    assert (allowed, source) == (False, "none")


def test_owner_falls_back_only_when_no_grant_is_anchored(monkeypatch):
    """Matches app._authorize: the owner is verified on-chain like everyone
    else and let through as a labelled fallback, never silently bypassed."""
    monkeypatch.setattr(tams, "CHAIN", _Chain(answer=False))
    allowed, _ms, _cached, source = tams._verify("obj", "owner", is_owner=True)
    assert (allowed, source) == (True, "owner-fallback")


def test_granted_party_is_authorized_by_the_contract(monkeypatch):
    monkeypatch.setattr(tams, "CHAIN", _Chain(answer=True))
    allowed, _ms, cached, source = tams._verify("obj", "party", is_owner=False)
    assert (allowed, source, cached) == (True, "amoy-contract", False)


def test_only_positive_verdicts_are_cached(monkeypatch):
    """A denial must never be cached, or a revoke wouldn't bite until the TTL
    expired. A positive verdict is cached so playback doesn't pay an RPC per
    segment."""
    yes = _Chain(answer=True)
    monkeypatch.setattr(tams, "CHAIN", yes)
    tams._verify("obj", "party", is_owner=False)
    _allowed, _ms, cached, _source = tams._verify("obj", "party", is_owner=False)
    assert cached is True and yes.calls == 1

    no = _Chain(answer=False)
    monkeypatch.setattr(tams, "CHAIN", no)
    tams._verify("other", "stranger", is_owner=False)
    tams._verify("other", "stranger", is_owner=False)
    assert no.calls == 2


def test_chain_outage_denies_a_stranger_rather_than_admitting_them(monkeypatch):
    monkeypatch.setattr(tams, "CHAIN", _Chain(boom=True))
    with pytest.raises(Exception) as exc:
        tams._verify("obj", "stranger", is_owner=False)
    assert getattr(exc.value, "status_code", None) == 503
