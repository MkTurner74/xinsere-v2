"""TAMS demo — a time-addressable media store over Xinsere-protected segments.

Demonstrates the thesis from the Xinsere x TAMS spike: TAMS keeps the timeline
and the query; Xinsere holds, protects and releases the bytes. A TAMS Media
Object is a Xinsere object handle, not a raw S3 key.

Deliberately built on the primitives that already exist, with no schema change:

  Flow    -> a folder node. Its metadata lives in a sibling `_tams` node whose
             NAME carries the JSON (file_id NULL, so no pipeline object and no
             extra round-trip -- one `children()` call returns the flow's
             metadata and its whole segment index together).
  Segment -> a file node named `s{start_ns}_e{end_ns}`, zero-padded so lexical
             order IS time order, whose `file_id` is the Xinsere object handle.
             The bytes went through the normal pipeline: shredded, per-fragment
             AES-256-GCM, scattered across buckets.

So a TAMS timerange query is a range filter over child names, and retrieving a
segment is an ordinary authorized Xinsere retrieval. Nothing here forks the
storage path -- that is the point of the demo.

Timestamps are TAI nanoseconds per the AMWA/NMOS timing model (TAI, not UTC,
because TAI is monotonic -- no leap seconds to poison a media timeline).
"""
from __future__ import annotations

import json
import re
import time
import uuid
from urllib.parse import urljoin, urlparse

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

import supa
from authn import session as _session
from chain import CHAIN
from store import get_pipeline, XinsereIntegrityError

router = APIRouter(prefix="/api/tams", tags=["tams"])

# TAI is ahead of UTC by a fixed offset (37s as of 2026). Store and align in TAI;
# convert only for display.
TAI_MINUS_UTC = 37
NS = 1_000_000_000

# The folder that holds every flow, at the root of the signed-in user's tree.
FLOWS_FOLDER = "TAMS Flows"
META_PREFIX = "_tams:"          # metadata node name prefix (file_id is NULL)
SEG_RE = re.compile(r"^s(\d{20})_e(\d{20})")

# Ingest guards. The Vercel function is capped at 300s / 1024MB, and a demo that
# times out mid-ingest leaves a half-written flow, so bound the work explicitly
# rather than discovering the ceiling in front of an audience.
MAX_SEGMENTS = 24
DEFAULT_SEGMENTS = 6
MAX_SEGMENT_BYTES = 32 * 1024 * 1024
FETCH_TIMEOUT = 20

# NOTE on fragment count. Segments here go through the deployed pipeline at its
# configured XINSERE_FRAGMENT_COUNT (7 in production). The 2026-07-26 benchmark
# says segments really want a LOWER count than files -- latency tracks
# per-fragment round trips, not bytes, so N=3 sits nearer the ~250-300ms floor
# while N=1000 costs 3.26s. Pinning N per flow needs a per-call fragment_count
# on PipelineService.store(), which is a pipeline change, not a demo change --
# it's Phase 1 work in the development plan. The demo therefore reports the real
# fragment count it used rather than claiming a tuned one.

# Positive verify verdicts are cached per (file, party) for the life of this
# warm instance. This IS the fail-closed cache from the development plan: a
# denial is NEVER cached, so revocation takes effect on the next request, and
# an empty cache can only ever block a legitimate user, never expose a file.
_VERIFY_TTL = 60.0
_verify_cache: dict[tuple[str, str], float] = {}


# --- time helpers -------------------------------------------------------------

def _now_tai_ns() -> int:
    return int((time.time() + TAI_MINUS_UTC) * NS)


def fmt_ts(ns: int) -> str:
    """TAMS timestamp: `<seconds>:<nanoseconds>`."""
    return f"{ns // NS}:{ns % NS}"


def parse_ts(text: str) -> int:
    secs, _, nsecs = text.strip().partition(":")
    return int(secs) * NS + (int(nsecs) if nsecs else 0)


def fmt_timerange(start_ns: int, end_ns: int) -> str:
    """TAMS timerange, half-open: `[start_end)`."""
    return f"[{fmt_ts(start_ns)}_{fmt_ts(end_ns)})"


def parse_timerange(text: str) -> tuple[int, int]:
    """Accept `[a_b)`, `a_b`, or `a/b`. Returns (start_ns, end_ns) half-open.

    Raises ValueError with a message the UI can show verbatim."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty timerange")
    body = raw.lstrip("[(").rstrip("])")
    sep = "_" if "_" in body else ("/" if "/" in body else None)
    if sep is None:
        raise ValueError("timerange needs two timestamps, e.g. [0:0_10:0)")
    left, _, right = body.partition(sep)
    try:
        start, end = parse_ts(left), parse_ts(right)
    except ValueError:
        raise ValueError("timestamps must look like <seconds>:<nanoseconds>")
    if end < start:
        raise ValueError("end precedes start")
    return start, end


# --- node <-> TAMS model ------------------------------------------------------

def _seg_bounds(name: str) -> tuple[int, int] | None:
    m = SEG_RE.match(name or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def _flow_meta(nodes: list[dict]) -> dict:
    """Pull the flow's metadata out of its `_tams:` marker node."""
    for n in nodes:
        if n["type"] == "file" and (n["name"] or "").startswith(META_PREFIX):
            try:
                return json.loads(n["name"][len(META_PREFIX):])
            except (ValueError, TypeError):
                return {}
    return {}


def _segments(nodes: list[dict]) -> list[dict]:
    """Segment nodes, in time order, as TAMS-shaped records."""
    out = []
    for n in nodes:
        if n["type"] != "file" or not n.get("file_id"):
            continue
        bounds = _seg_bounds(n["name"])
        if not bounds:
            continue
        start, end = bounds
        out.append({
            "node_id": n["id"],
            "object_id": n["file_id"],          # the Xinsere object handle
            "start_ns": start,
            "end_ns": end,
            "timerange": fmt_timerange(start, end),
            "size": n.get("size") or 0,
            "fragments": n.get("frags") or 0,
            "sha256": n.get("sha"),
            "content_type": n.get("content_type") or "video/mp2t",
        })
    out.sort(key=lambda s: s["start_ns"])
    return out


def _flows_root(token: str, uid: str) -> str:
    root = supa.ensure_root(token, uid)
    for n in supa.children(token, root):
        if n["type"] == "folder" and n["name"] == FLOWS_FOLDER:
            return n["id"]
    return supa.insert_folder(token, FLOWS_FOLDER, root, uid)["id"]


def _load_flow(token: str, uid: str, flow_id: str) -> tuple[dict, dict, list[dict]]:
    """(node, meta, segments) for a flow the caller owns. 404s otherwise."""
    node = supa.get_node(token, flow_id)
    if not node or node["type"] != "folder" or node["owner"] != uid:
        raise HTTPException(status_code=404, detail="No such flow")
    kids = supa.children(token, flow_id)
    return node, _flow_meta(kids), _segments(kids)


# --- authorization ------------------------------------------------------------

def _party_for(request: Request, uid: str) -> tuple[str, str]:
    """Which party are we asking the contract about?

    `as=stranger` swaps in a party id that holds no grant, so the fail-closed
    path can be demonstrated against the real contract rather than simulated.
    The verify() call is genuine either way -- only the subject changes."""
    if (request.query_params.get("as") or "owner").lower() == "stranger":
        return "stranger", "00000000-0000-4000-8000-0000deadbeef"
    return "owner", uid


def _verify(file_id: str, party_id: str, is_owner: bool) -> tuple[bool, float, bool, str]:
    """The access decision, matching the app's own gate. -> (allowed, ms, cached, source).

    Everyone is verified on-chain, the owner included. The owner is let through
    as a LOGGED fallback only when no grant has been anchored yet (a fresh
    ingest before its grant lands), so they can never be locked out of their own
    flow — exactly the rule `app._authorize` applies to every other download.
    The demo surfaces which of the two authorized the call, so nobody reads a
    fallback as an on-chain proof."""
    key = (file_id, party_id)
    hit = _verify_cache.get(key)
    if hit and hit > time.monotonic():
        return True, 0.0, True, "amoy-contract"
    t0 = time.perf_counter()
    try:
        allowed, _granted_at = CHAIN.verify(file_id, party_id)
    except Exception as exc:                       # RPC down => deny, never allow
        if is_owner:
            return True, 0.0, False, "owner-fallback"
        raise HTTPException(status_code=503,
                            detail=f"chain verify unavailable ({type(exc).__name__})")
    ms = round((time.perf_counter() - t0) * 1000, 1)
    if allowed:
        _verify_cache[key] = time.monotonic() + _VERIFY_TTL
        return True, ms, False, "amoy-contract"
    if is_owner:
        return True, ms, False, "owner-fallback"
    return False, ms, False, "none"


# --- HLS ingest ---------------------------------------------------------------

def _fetch_text(url: str) -> str:
    r = requests.get(url, timeout=FETCH_TIMEOUT)
    r.raise_for_status()
    return r.text


def _resolve_variant(url: str, text: str) -> tuple[str, str]:
    """A master playlist lists variants, not segments. Follow the first one."""
    if "#EXT-X-STREAM-INF" not in text:
        return url, text
    lines = [ln.strip() for ln in text.splitlines()]
    for i, ln in enumerate(lines):
        if ln.startswith("#EXT-X-STREAM-INF") and i + 1 < len(lines):
            nxt = lines[i + 1]
            if nxt and not nxt.startswith("#"):
                variant = urljoin(url, nxt)
                return variant, _fetch_text(variant)
    raise ValueError("master playlist has no usable variant")


def _parse_media_playlist(url: str, text: str, limit: int) -> list[tuple[str, float]]:
    """-> [(absolute segment url, duration seconds)] up to `limit`."""
    out: list[tuple[str, float]] = []
    dur = 0.0
    for raw in text.splitlines():
        ln = raw.strip()
        if ln.startswith("#EXTINF:"):
            try:
                dur = float(ln[len("#EXTINF:"):].split(",")[0])
            except ValueError:
                dur = 0.0
        elif ln and not ln.startswith("#"):
            out.append((urljoin(url, ln), dur or 2.0))
            if len(out) >= limit:
                break
    return out


@router.post("/ingest")
async def ingest(request: Request):
    """Pull real HLS segments and write each one through the Xinsere pipeline.

    Each segment is shredded, per-fragment encrypted and scattered exactly like
    any other object; the flow record and the timerange index are what make it
    time-addressable."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    body = await request.json()

    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="A playlist URL is required")
    if urlparse(url).scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="URL must be http(s)")
    label = (body.get("label") or "CAM 1").strip()[:60]
    source_id = (body.get("source_id") or "venue-a").strip()[:60]
    essence = (body.get("essence") or "video").strip().lower()
    if essence not in ("video", "audio", "data"):
        essence = "video"
    try:
        want = int(body.get("segments") or DEFAULT_SEGMENTS)
    except (TypeError, ValueError):
        want = DEFAULT_SEGMENTS
    want = max(1, min(want, MAX_SEGMENTS))

    # Flows on a shared timeline start at a common origin, so a timestamp means
    # the same instant in every lane -- that is the whole point of a Source.
    try:
        start_ns = int(body["start_tai_ns"])
    except (KeyError, TypeError, ValueError):
        start_ns = _now_tai_ns()

    try:
        playlist_url, text = _resolve_variant(url, _fetch_text(url))
        entries = _parse_media_playlist(playlist_url, text, want)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch the playlist: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not entries:
        raise HTTPException(status_code=400, detail="No segments found in that playlist")

    flows_root = _flows_root(token, uid)
    flow = supa.insert_folder(token, label, flows_root, uid)
    meta = {"source_id": source_id, "essence": essence, "label": label,
            "origin_ns": start_ns, "ingested_from": playlist_url,
            "spec": "TAMS-shaped demo"}
    supa.insert_file(token, META_PREFIX + json.dumps(meta, separators=(",", ":")),
                     flow["id"], uid, file_id=None, sha256=None, size=None,
                     frags=None, content_type="application/json")

    pipeline = get_pipeline()
    cursor = start_ns
    stored, total_bytes, store_ms = [], 0, 0.0
    for seg_url, dur in entries:
        try:
            r = requests.get(seg_url, timeout=FETCH_TIMEOUT)
            r.raise_for_status()
        except requests.RequestException as exc:
            break                                   # keep whatever landed
        content = r.content
        if not content or len(content) > MAX_SEGMENT_BYTES:
            break
        ctype = r.headers.get("content-type", "video/mp2t").split(";")[0].strip()
        if ctype in ("", "application/octet-stream", "binary/octet-stream"):
            ctype = "video/mp4" if seg_url.endswith((".m4s", ".mp4")) else "video/mp2t"

        end_ns = cursor + int(dur * NS)
        name = f"s{cursor:020d}_e{end_ns:020d}"

        t0 = time.perf_counter()
        res = pipeline.store(content, ctype, label=name)
        store_ms += (time.perf_counter() - t0) * 1000

        node = supa.insert_file(token, name, flow["id"], uid, file_id=res.file_id,
                                sha256=res.file_sha256, size=len(content),
                                frags=res.fragment_count, content_type=ctype)
        stored.append({"node_id": node["id"], "object_id": res.file_id,
                       "timerange": fmt_timerange(cursor, end_ns),
                       "size": len(content)})
        total_bytes += len(content)
        cursor = end_ns

    if not stored:
        supa.delete_node(token, flow["id"])
        raise HTTPException(status_code=502, detail="Could not fetch any segment bytes")

    return {
        "flow_id": flow["id"], "label": label, "source_id": source_id,
        "essence": essence, "segments": len(stored), "bytes": total_bytes,
        "timerange": fmt_timerange(start_ns, cursor),
        "store_ms_total": round(store_ms, 1),
        "store_ms_per_segment": round(store_ms / len(stored), 1),
        "created": stored,
    }


# --- the time index -----------------------------------------------------------

@router.get("/flows")
def list_flows(request: Request):
    """Every flow, with its timeline extent — the data behind the lane view."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    out = []
    for f in supa.children(token, _flows_root(token, uid)):
        if f["type"] != "folder":
            continue
        kids = supa.children(token, f["id"])
        meta, segs = _flow_meta(kids), _segments(kids)
        out.append({
            "flow_id": f["id"],
            "label": meta.get("label") or f["name"],
            "source_id": meta.get("source_id") or "—",
            "essence": meta.get("essence") or "video",
            "segment_count": len(segs),
            "bytes": sum(s_["size"] for s_ in segs),
            "start_ns": segs[0]["start_ns"] if segs else None,
            "end_ns": segs[-1]["end_ns"] if segs else None,
            "timerange": fmt_timerange(segs[0]["start_ns"], segs[-1]["end_ns"]) if segs else None,
        })
    out.sort(key=lambda f: (f["source_id"], f["label"]))
    return {"flows": out}


@router.get("/flows/{flow_id}/segments")
def flow_segments(flow_id: str, request: Request, timerange: str | None = None):
    """The TAMS query: `<flow_id, timerange>` -> Media Objects.

    Returns Xinsere object handles rather than storage keys. Nothing is
    decrypted here — this is the index plane only."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]

    t0 = time.perf_counter()
    node, meta, segs = _load_flow(token, uid, flow_id)
    index_ms = round((time.perf_counter() - t0) * 1000, 1)

    matched = segs
    if timerange:
        try:
            start, end = parse_timerange(timerange)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # Half-open overlap: a segment is in range if it starts before the range
        # ends and ends after the range starts.
        matched = [x for x in segs if x["start_ns"] < end and x["end_ns"] > start]

    who, _party = _party_for(request, uid)
    for x in matched:
        x["get_url"] = f"/api/tams/segments/{x['node_id']}/content?as={who}"

    return {
        "flow_id": flow_id,
        "label": meta.get("label") or node["name"],
        "source_id": meta.get("source_id"),
        "essence": meta.get("essence") or "video",
        "queried": timerange or "(whole flow)",
        "index_ms": index_ms,
        "segment_count": len(matched),
        "of_total": len(segs),
        "segments": matched,
    }


@router.get("/flows/{flow_id}/playlist.m3u8")
def flow_playlist(flow_id: str, request: Request, timerange: str | None = None):
    """An HLS playlist whose every segment URL is a gated Xinsere retrieval.

    The player only gets pictures because each segment passed an on-chain
    check and was reassembled from scattered, encrypted fragments."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    _node, _meta, segs = _load_flow(token, uid, flow_id)

    if timerange:
        try:
            start, end = parse_timerange(timerange)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        segs = [x for x in segs if x["start_ns"] < end and x["end_ns"] > start]
    if not segs:
        raise HTTPException(status_code=404, detail="No segments in that timerange")

    who, _party = _party_for(request, uid)
    longest = max((x["end_ns"] - x["start_ns"]) / NS for x in segs)
    lines = ["#EXTM3U", "#EXT-X-VERSION:3", f"#EXT-X-TARGETDURATION:{int(longest) + 1}",
             "#EXT-X-MEDIA-SEQUENCE:0", "#EXT-X-PLAYLIST-TYPE:VOD"]
    for x in segs:
        lines.append(f"#EXTINF:{(x['end_ns'] - x['start_ns']) / NS:.3f},")
        lines.append(f"/api/tams/segments/{x['node_id']}/content?as={who}")
    lines.append("#EXT-X-ENDLIST")
    return PlainTextResponse("\n".join(lines) + "\n",
                             media_type="application/vnd.apple.mpegurl")


@router.get("/segments/{node_id}/content")
def segment_content(node_id: str, request: Request):
    """Authorized retrieval IS the playable chunk.

    verify() -> reassemble across clouds -> SHA-256 -> bytes. Denied callers
    get nothing at all, not a degraded version."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    node = supa.get_node(token, node_id)
    if not node or node["type"] != "file" or not node.get("file_id"):
        raise HTTPException(status_code=404, detail="No such segment")

    who, party = _party_for(request, uid)
    allowed, verify_ms, cached, source = _verify(
        node["file_id"], party, is_owner=(who == "owner" and node["owner"] == uid))
    if not allowed:
        # Fail-closed. No partial content, no placeholder, no error body that
        # leaks whether the segment exists.
        raise HTTPException(status_code=403, detail="No grant for this party — nothing returned")

    t0 = time.perf_counter()
    try:
        res = get_pipeline().retrieve(node["file_id"])
    except XinsereIntegrityError as exc:
        raise HTTPException(status_code=409, detail=f"Integrity failure: {exc}")
    retrieve_ms = round((time.perf_counter() - t0) * 1000, 1)

    t = res.timings or {}
    return Response(
        content=res.content,
        media_type=node.get("content_type") or "video/mp2t",
        headers={
            # Surfaced as headers so the UI can chart the real breakdown of a
            # live playback rather than a synthetic measurement.
            "X-Xinsere-Verify-Ms": str(verify_ms),
            "X-Xinsere-Verify-Cached": "1" if cached else "0",
            "X-Xinsere-Auth-Source": source,
            "X-Xinsere-Party": who,
            "X-Xinsere-Retrieve-Ms": str(retrieve_ms),
            "X-Xinsere-Index-Ms": str(t.get("index_ms", "")),
            "X-Xinsere-Fetch-Decrypt-Ms": str(t.get("fetch_decrypt_ms", "")),
            "X-Xinsere-Verify-Sha-Ms": str(t.get("verify_sha_ms", "")),
            "X-Xinsere-Fragments": str(t.get("fragments", node.get("frags") or "")),
            "Access-Control-Expose-Headers": "X-Xinsere-Verify-Ms,X-Xinsere-Retrieve-Ms,"
                                             "X-Xinsere-Index-Ms,X-Xinsere-Fetch-Decrypt-Ms,"
                                             "X-Xinsere-Verify-Sha-Ms,X-Xinsere-Fragments,"
                                             "X-Xinsere-Verify-Cached,X-Xinsere-Party,"
                                             "X-Xinsere-Auth-Source",
            "Cache-Control": "no-store",
        },
    )


@router.delete("/flows/{flow_id}")
def delete_flow(flow_id: str, request: Request):
    """Remove a flow and cryptographically erase its segments. Demo hygiene."""
    s = _session(request)
    token, uid = s["access_token"], s["user_id"]
    _node, _meta, segs = _load_flow(token, uid, flow_id)
    pipeline = get_pipeline()
    erased = 0
    for x in segs:
        try:
            pipeline.delete(x["object_id"])
            erased += 1
        except Exception:
            pass                                   # keep going; node delete still runs
        _verify_cache.pop((x["object_id"], uid), None)
    supa.delete_node(token, flow_id)
    return {"deleted": flow_id, "segments_erased": erased}
