"""Xinsere file-fragment pipeline — test matrix.

Runs the full pipeline against the local backends and prints a pass/fail matrix.
No AWS required.

    python tests/test_matrix.py          # from lambdas/pipeline/
    python -m tests.test_matrix

Covers: round-trip correctness, integrity/security properties (no plaintext
leakage, tamper detection, missing-fragment, wrong-key), fragment distribution,
and lifecycle (exists/delete).
"""
from __future__ import annotations

import hashlib
import os
import re
import sys

# Allow running as a loose script (python tests/test_matrix.py).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from xinsere_pipeline import PipelineService, XinsereIntegrityError, XinsereNotFoundError
from xinsere_pipeline.backends.local import LocalIndexStore, LocalKeyManager, LocalObjectStore
from xinsere_pipeline.config import ROUTE_HYBRID
from xinsere_pipeline import fragmenter

_passed = 0
_failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    mark = "PASS" if ok else "FAIL"
    if ok:
        _passed += 1
    else:
        _failed += 1
    tail = f"  ({detail})" if detail else ""
    print(f"  [{mark}] {name}{tail}")


def section(title: str) -> None:
    print(f"\n{title}")


def make_service(fragment_count: int = 7, route_mode: str = "modular", bucket_count: int = 8):
    """Fresh pipeline + its local backends (returned so tests can inspect them)."""
    store = LocalObjectStore(bucket_count=bucket_count)
    keys = LocalKeyManager()
    index = LocalIndexStore()
    svc = PipelineService(
        store, keys, index, fragment_count=fragment_count, route_mode=route_mode
    )
    return svc, store, keys, index


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --- A. Round-trip correctness ----------------------------------------------

def group_a() -> None:
    section("A. Round-trip correctness")

    svc, *_ = make_service()
    content = b"hello world"
    r = svc.store(content, "text/plain")
    out = svc.retrieve(r.file_id)
    check("A1 tiny file round-trips byte-identical", out.content == content)

    svc, *_ = make_service()
    r = svc.store(b"", "application/octet-stream")
    check("A2 empty file round-trips", svc.retrieve(r.file_id).content == b"")

    svc, *_ = make_service(fragment_count=7)
    content = os.urandom(700)  # exact multiple of 7
    r = svc.store(content, "application/octet-stream")
    check("A3 exact-multiple size round-trips", svc.retrieve(r.file_id).content == content)

    svc, *_ = make_service(fragment_count=7)
    content = os.urandom(703)  # remainder of 3
    r = svc.store(content, "application/octet-stream")
    check("A4 non-even size (remainder) round-trips", svc.retrieve(r.file_id).content == content)

    svc, *_ = make_service()
    content = os.urandom(200_000)
    r = svc.store(content, "application/octet-stream")
    check("A5 large binary (200KB) round-trips", svc.retrieve(r.file_id).content == content)

    ok_all = True
    detail = []
    for n in (3, 5, 7, 11, 16):
        svc, _s, _k, index = make_service(fragment_count=n)
        content = os.urandom(5000)
        r = svc.store(content, "application/octet-stream")
        frags = index.get_fragments(r.file_id)
        this = (
            svc.retrieve(r.file_id).content == content
            and r.fragment_count == n
            and len(frags) == n
        )
        detail.append(f"N={n}:{'ok' if this else 'BAD'}")
        ok_all = ok_all and this
    check("A6 all fragment counts round-trip", ok_all, " ".join(detail))


# --- B. Integrity & security ------------------------------------------------

def group_b() -> None:
    section("B. Integrity & security")

    # B1 — SHA recorded and verified
    svc, *_ = make_service()
    content = os.urandom(1234)
    r = svc.store(content, "application/octet-stream")
    check("B1 whole-file SHA-256 recorded correctly", r.file_sha256 == sha(content))

    # B2 — no plaintext leakage into stored fragments
    svc, store, _k, _i = make_service()
    marker = b"TOP-SECRET-MARKER-" * 64  # highly distinctive plaintext
    r = svc.store(marker, "text/plain")
    objects = store.all_objects()
    leaked = any(b"TOP-SECRET-MARKER" in data for (_b, _k2, data) in objects)
    check("B2 no plaintext marker present in any stored fragment", not leaked,
          f"{len(objects)} objects scanned")

    # B3 — no single fragment reconstructs (or reveals) the file
    svc, store, _k, _i = make_service()
    content = os.urandom(4096)
    r = svc.store(content, "application/octet-stream")
    objs = [d for (_b, _k2, d) in store.all_objects()]
    none_is_file = all(d != content for d in objs)
    concat_ne = b"".join(objs) != content  # even all ciphertext concatenated != plaintext
    check("B3 no single fragment equals the file; ciphertext != plaintext",
          none_is_file and concat_ne, f"{len(objs)} fragments")

    # B4 — tamper detection (flip a byte in one fragment ciphertext)
    svc, store, _k, index = make_service()
    content = os.urandom(2048)
    r = svc.store(content, "application/octet-stream")
    fr = index.get_fragments(r.file_id)[2]
    ct = bytearray(store.get(fr.bucket, fr.fragment_id))
    ct[0] ^= 0x01
    store.put(fr.bucket, fr.fragment_id, bytes(ct))
    try:
        svc.retrieve(r.file_id)
        check("B4 tampered fragment is detected", False, "retrieve did NOT raise")
    except XinsereIntegrityError:
        check("B4 tampered fragment is detected", True)

    # B5 — missing fragment object fails loudly (no silent partial)
    svc, store, _k, index = make_service()
    content = os.urandom(2048)
    r = svc.store(content, "application/octet-stream")
    fr = index.get_fragments(r.file_id)[0]
    store.delete(fr.bucket, fr.fragment_id)
    try:
        svc.retrieve(r.file_id)
        check("B5 missing fragment raises (no partial data)", False, "retrieve did NOT raise")
    except XinsereIntegrityError:
        check("B5 missing fragment raises (no partial data)", True)

    # B6 — corrupted wrapped key cannot decrypt
    svc, _s, _k, index = make_service()
    content = os.urandom(2048)
    r = svc.store(content, "application/octet-stream")
    index._fragments[r.file_id][1].wrapped_key = os.urandom(60)  # white-box corrupt
    try:
        svc.retrieve(r.file_id)
        check("B6 corrupted data key cannot decrypt", False, "retrieve did NOT raise")
    except XinsereIntegrityError:
        check("B6 corrupted data key cannot decrypt", True)

    # B7 — metadata stripped: fragment ids are {uuid}_{seq}, no filename anywhere
    svc, _s, _k, index = make_service()
    r = svc.store(b"some bytes", "text/plain", label="quarterly-report.pdf")
    frags = index.get_fragments(r.file_id)
    id_ok = all(re.fullmatch(r"[0-9a-f]{32}_\d+", f.fragment_id) for f in frags)
    no_name_in_ids = all("quarterly-report" not in f.fragment_id for f in frags)
    file_rec = index.get_file(r.file_id)
    no_filename_field = not hasattr(file_rec, "filename")
    check("B7 fragment ids carry no filename; metadata stripped",
          id_ok and no_name_in_ids and no_filename_field)


# --- C. Distribution & routing ----------------------------------------------

def group_c() -> None:
    section("C. Distribution & routing")

    svc, _s, _k, index = make_service(fragment_count=7, bucket_count=8)
    r = svc.store(os.urandom(1000), "application/octet-stream")
    frags = index.get_fragments(r.file_id)
    used = {f.bucket for f in frags}
    check("C1 fragments spread across multiple buckets", len(used) > 1,
          f"{len(used)} distinct buckets")

    all_valid = all(f.bucket in svc._objects.buckets() for f in frags)
    check("C2 every fragment routed to a registered bucket", all_valid)

    buckets = [f"b{i}" for i in range(8)]
    even_ok = all(
        buckets.index(fragmenter.route(seq, buckets, mode=ROUTE_HYBRID, jitter=0)) < 4
        for seq in range(0, 16, 2)
    )
    odd_ok = all(
        buckets.index(fragmenter.route(seq, buckets, mode=ROUTE_HYBRID, jitter=0)) >= 4
        for seq in range(1, 16, 2)
    )
    check("C3 hybrid routing splits odd/even across bucket groups", even_ok and odd_ok)


# --- D. Lifecycle -----------------------------------------------------------

def group_d() -> None:
    section("D. Lifecycle")

    svc, store, _k, index = make_service()
    content = os.urandom(1500)
    r = svc.store(content, "application/octet-stream")
    check("D1 exists() true for stored hash, false for unknown",
          svc.exists(r.file_sha256) and not svc.exists(sha(b"never stored")))

    n_before = len(store.all_objects())
    svc.delete(r.file_id)
    n_after = len(store.all_objects())
    gone_from_index = index.get_file(r.file_id) is None
    retrieve_raises = False
    try:
        svc.retrieve(r.file_id)
    except XinsereNotFoundError:
        retrieve_raises = True
    check("D2 delete() erases fragments + index; retrieve then fails",
          n_after == 0 and n_before > 0 and gone_from_index and retrieve_raises,
          f"{n_before}->{n_after} objects")


def main() -> int:
    print("=" * 64)
    print("Xinsere file-fragment pipeline — test matrix (local backends)")
    print("=" * 64)
    group_a()
    group_b()
    group_c()
    group_d()
    print("\n" + "=" * 64)
    print(f"RESULT: {_passed} passed, {_failed} failed")
    print("=" * 64)
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
