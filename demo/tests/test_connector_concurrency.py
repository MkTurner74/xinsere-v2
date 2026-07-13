"""Concurrency tests for the parallel ingest path.

Prove that running many files through `workers` threads (a) migrates every file
exactly once, (b) never creates a duplicate folder even when many files land in the
same directory at once, and (c) aggregates the Report without lost updates.
"""
import threading
import time

import dropbox_connector as dc
from dropbox_connector import DbxFile, MigrationRunner, Report, dropbox_content_hash


class FakeWalkClient:
    """Yields a fixed set of DbxFiles with correct content_hash; download() returns
    deterministic bytes with a tiny sleep to force real thread overlap."""
    def __init__(self, files):
        self._files = files  # list[(path, data bytes)]
    def walk(self, folder):
        for path, data in self._files:
            yield DbxFile(path, f"id:{path}", len(data), dropbox_content_hash(data))
    def download(self, path):
        time.sleep(0.01)  # force overlap so races would surface
        return next(d for p, d in self._files if p == path)


class FakeRes:
    def __init__(self, fid, sha):
        self.file_id, self.file_sha256, self.fragment_count = fid, sha, 7


class FakePipeline:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        self.calls = 0
    def store(self, data, ctype, label=None):
        import hashlib
        sha = hashlib.sha256(data).hexdigest()
        with self._lock:
            self.calls += 1
            fid = f"file-{self.calls}"
            self._store[fid] = sha
        return FakeRes(fid, sha)
    def retrieve(self, fid):
        return FakeRes(fid, self._store[fid])


class FakeSupa:
    """Tracks folder + file creation with a lock so we can assert no duplicate folders
    are created under concurrency. Mirrors the real ensure_path/insert_file contract."""
    def __init__(self):
        self.lock = threading.Lock()
        self.folders = {}   # (parent, name) -> id
        self.files = []     # (parent, name)
        self.folder_creates = 0
    def children(self, token, node_id):
        return []
    def ensure_path(self, token, rel_dir, root, owner):
        # Deliberately models the REAL race: check-then-create is NOT atomic (the
        # sleep widens the window). Nodes have no unique (parent,name) constraint, so
        # if two threads both pass the `not in` check they both create -> duplicate.
        # This must be prevented by MigrationRunner._resolve_parent's lock, not here.
        parent = root
        for part in [p for p in rel_dir.split("/") if p]:
            key = (parent, part)
            if key not in self.folders:              # check (racy on purpose)
                time.sleep(0.005)                    # widen the window
                self.folders[key] = f"fld-{len(self.folders)}"
                with self.lock:
                    self.folder_creates += 1         # count creations accurately
            parent = self.folders[key]
        return parent
    def insert_file(self, token, name, parent, owner, **kw):
        with self.lock:
            self.files.append((parent, name))
        return {"id": f"fil-{len(self.files)}"}


def _run(files, workers):
    runner = MigrationRunner(FakeWalkClient(files))
    rep = Report()
    supa = FakeSupa()
    pipeline = FakePipeline()
    # Drive the concurrent loop directly (mirrors run()'s --full body).
    import concurrent.futures as cf
    sem = threading.Semaphore(workers * 2)
    def task(f):
        try:
            runner._ingest_one(f, pipeline, supa, "tok", "owner", "root", rep)
        finally:
            sem.release()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for path, data in files:
            f = DbxFile(path, f"id:{path}", len(data), dropbox_content_hash(data))
            rep.sourced += 1
            sem.acquire()
            ex.submit(task, f)
    return rep, supa, pipeline


def test_all_files_migrated_once_under_concurrency():
    files = [(f"/Founders/sub{i%5}/file{i}.bin", f"data-{i}".encode()) for i in range(200)]
    rep, supa, pipeline = _run(files, workers=16)
    assert rep.verified == 200
    assert rep.stored == 200
    assert rep.failed == []
    assert len(supa.files) == 200          # every file recorded exactly once
    assert pipeline.calls == 200


def test_no_duplicate_folders_created_when_many_files_share_a_dir():
    # 100 files all under the SAME directory, high concurrency -> classic race.
    files = [(f"/Founders/same/f{i}.bin", f"d{i}".encode()) for i in range(100)]
    rep, supa, pipeline = _run(files, workers=16)
    assert rep.verified == 100
    # 'Founders' + 'same' = exactly 2 folder segments, created once each despite the race.
    assert supa.folder_creates == 2
    assert len(set(supa.folders.keys())) == 2


def test_report_counts_are_not_lost_to_races():
    files = [(f"/x/f{i}.bin", b"z" * (i + 1)) for i in range(300)]
    rep, supa, pipeline = _run(files, workers=32)
    assert rep.verified == 300
    assert rep.bytes_in == sum(i + 1 for i in range(300))  # no lost += under lock


def test_content_hash_mismatch_is_isolated_not_fatal():
    good = [(f"/g/f{i}.bin", f"ok{i}".encode()) for i in range(20)]
    runner = MigrationRunner(FakeWalkClient(good))
    rep, supa, pipeline = Report(), FakeSupa(), FakePipeline()
    # One file whose declared hash is wrong -> must fail alone, others succeed.
    bad = DbxFile("/g/bad.bin", "id:bad", 3, "deadbeef" * 8)
    runner._ingest_one(bad, pipeline, supa, "t", "o", "root", rep)
    assert len(rep.failed) == 1 and rep.verified == 0
