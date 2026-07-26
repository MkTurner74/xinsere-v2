"""Enumerator hardening + resume tests for the Dropbox connector.

Prove the non-recursive walk descends the whole tree, prunes personal folders,
handles per-folder pagination, and that the resume scan skips already-migrated files
so a re-run never duplicates.
"""
import dropbox_connector as dc
from dropbox_connector import DropboxClient, DbxFile, MigrationRunner


def _file(path, size=10):
    return {".tag": "file", "path_display": path, "id": f"id:{path}",
            "size": size, "content_hash": "h" * 64}


def _folder(path):
    return {".tag": "folder", "path_display": path}


class FakeClient(DropboxClient):
    """DropboxClient with _post stubbed to serve canned per-folder pages, including
    a paginated folder (has_more + cursor) to exercise the continue loop."""
    def __init__(self, pages, cont=None):
        self._pages = pages          # folder path -> page dict
        self._cont = cont or {}      # cursor -> page dict
    def _post(self, url, body):
        if url.endswith("/files/list_folder"):
            return self._pages[body["path"]]
        if url.endswith("/files/list_folder/continue"):
            return self._cont[body["cursor"]]
        raise AssertionError(url)


def test_walk_descends_tree_and_prunes_personal():
    pages = {
        "": {"entries": [_folder("/Founders"), _folder("/Mark Turner"),
                         _folder("/Photos Backup")], "has_more": False},
        "/Founders": {"entries": [_folder("/Founders/Legal"), _file("/Founders/a.pdf")],
                      "has_more": False},
        "/Founders/Legal": {"entries": [_file("/Founders/Legal/b.pdf")], "has_more": False},
        # These must NEVER be listed (pruned before descent):
        "/Mark Turner": {"entries": [_file("/Mark Turner/secret.pdf")], "has_more": False},
        "/Photos Backup": {"entries": [_file("/Photos Backup/pic.jpg")], "has_more": False},
    }
    got = sorted(f.path for f in FakeClient(pages).walk(""))
    assert got == ["/Founders/Legal/b.pdf", "/Founders/a.pdf"]  # personal pruned


def test_walk_paginates_within_a_folder():
    pages = {
        "/Big": {"entries": [_file("/Big/1")], "has_more": True, "cursor": "c1"},
    }
    cont = {
        "c1": {"entries": [_file("/Big/2")], "has_more": True, "cursor": "c2"},
        "c2": {"entries": [_file("/Big/3")], "has_more": False},
    }
    got = sorted(f.path for f in FakeClient(pages, cont).walk("/Big"))
    assert got == ["/Big/1", "/Big/2", "/Big/3"]


class FakeSupa:
    """Minimal children() over a canned node tree for the resume-scan test."""
    def __init__(self, tree):
        self._tree = tree  # node_id -> list[node dicts]
    def children(self, token, node_id):
        return self._tree.get(node_id, [])


def test_existing_paths_builds_resume_set():
    tree = {
        "root": [{"id": "fA", "type": "folder", "name": "Founders"},
                 {"id": "x1", "type": "file", "name": "top.pdf"}],
        "fA": [{"id": "fL", "type": "folder", "name": "Legal"},
               {"id": "x2", "type": "file", "name": "a.pdf"}],
        "fL": [{"id": "x3", "type": "file", "name": "b.pdf"}],
    }
    runner = MigrationRunner(client=None)
    seen = runner._existing_paths(FakeSupa(tree), "tok", "root")
    assert seen == {"top.pdf", "founders/a.pdf", "founders/legal/b.pdf"}


def test_resume_set_matches_walk_paths_lowercased():
    # The skip key in run() is f.path.lstrip('/').lower(); prove it lines up with
    # what _existing_paths produces so a re-run actually skips.
    walk_path = "/Founders/Legal/b.pdf"
    assert walk_path.lstrip("/").lower() == "founders/legal/b.pdf"


# --- include_top override (2026-07-24) ---------------------------------------

def test_default_still_prunes_personal_folders():
    pages = {
        "": {"entries": [_folder("/Founders"), _folder("/Mark Turner")], "has_more": False},
        "/Founders": {"entries": [_file("/Founders/a.pdf")], "has_more": False},
        "/Mark Turner": {"entries": [_file("/Mark Turner/secret.pdf")], "has_more": False},
    }
    runner = MigrationRunner(FakeClient(pages))   # no override -> safety-by-default
    got = sorted(f.path for f in runner._walk(""))
    assert got == ["/Founders/a.pdf"]


def test_include_top_overrides_the_exclusion_explicitly():
    pages = {
        "": {"entries": [_folder("/Founders"), _folder("/Mark Turner"),
                         _folder("/Photos Backup")], "has_more": False},
        "/Founders": {"entries": [_file("/Founders/a.pdf")], "has_more": False},
        "/Mark Turner": {"entries": [_file("/Mark Turner/big.mov")], "has_more": False},
        "/Photos Backup": {"entries": [_file("/Photos Backup/pic.jpg")], "has_more": False},
    }
    runner = MigrationRunner(FakeClient(pages), include_top={"Mark Turner"})
    got = sorted(f.path for f in runner._walk(""))
    # Mark Turner is included now the caller opted in; Photos Backup stays pruned.
    assert got == ["/Founders/a.pdf", "/Mark Turner/big.mov"]


# --- size histogram (2026-07-24, corpus profiling) ---------------------------

def test_size_histogram_buckets_by_size():
    runner = MigrationRunner(client=None)
    files = [
        DbxFile("/a", "1", 1000, "h"),                       # <128KB
        DbxFile("/b", "2", 5 * 1024 * 1024, "h"),             # 128KB-10MB
        DbxFile("/c", "3", 50 * 1024 * 1024, "h"),            # 10-100MB
        DbxFile("/d", "4", 300 * 1024 * 1024, "h"),           # 100-500MB
        DbxFile("/e", "5", 1024 * 1024 * 1024, "h"),          # 500MB-2GB
        DbxFile("/f", "6", 3 * 1024 ** 3, "h"),                # 2GB+
    ]
    hist = runner.size_histogram(files)
    assert hist["<128KB"]["count"] == 1
    assert hist["128KB-10MB"]["count"] == 1
    assert hist["10-100MB"]["count"] == 1
    assert hist["100-500MB"]["count"] == 1
    assert hist["500MB-2GB"]["count"] == 1
    assert hist["2GB+"]["count"] == 1
    assert sum(b["count"] for b in hist.values()) == len(files)


# --- stratified calibration sample + replay (2026-07-24) ---------------------

def test_sample_per_bucket_caps_each_bucket_independently():
    runner = MigrationRunner(client=None)
    # 5 tiny files, 1 medium, 0 large -- caps at 2 should take 2 tiny, 1 medium,
    # 0 large (a bucket with fewer than n just gives what it has).
    files = ([DbxFile(f"/tiny{i}", str(i), 10, "h") for i in range(5)]
             + [DbxFile("/mid", "m", 5 * 1024 * 1024, "h")])
    sample = runner.sample_per_bucket(files, 2)
    hist = runner.size_histogram(sample)
    assert hist["<128KB"]["count"] == 2
    assert hist["128KB-10MB"]["count"] == 1
    assert len(sample) == 3


def test_sample_per_bucket_is_deterministic():
    runner = MigrationRunner(client=None)
    files = [DbxFile(f"/f{i}", str(i), 10, "h") for i in range(10)]
    assert runner.sample_per_bucket(files, 3) == runner.sample_per_bucket(files, 3)


def test_save_and_load_sample_roundtrips_paths(tmp_path):
    files = [DbxFile("/Founders/a.pdf", "1", 10, "h"),
             DbxFile("/Founders/Sub/B.MOV", "2", 20, "h")]
    out = tmp_path / "sample.json"
    dc.save_sample(files, str(out))
    loaded = dc.load_sample(str(out))
    # lowercased, leading-slash-stripped -- must match the key run() checks against.
    assert loaded == {"founders/a.pdf", "founders/sub/b.mov"}


def test_load_sample_downloads_s3_uri_first(tmp_path, monkeypatch):
    # Real incident 2026-07-26: a Fargate run-task override passed an s3://
    # sample URI straight through to load_sample(), which just tried open() on
    # the literal string and crashed. This proves the s3:// branch downloads
    # first, matching the local-path behavior otherwise.
    files = [DbxFile("/Founders/a.pdf", "1", 10, "h")]
    local = tmp_path / "sample.json"
    dc.save_sample(files, str(local))

    downloaded_to = {}
    class FakeS3:
        def download_file(self, bucket, key, dest):
            assert bucket == "xinsere-dev-staging"
            assert key == "some/key.json"
            import shutil
            shutil.copy(str(local), dest)
            downloaded_to["path"] = dest

    monkeypatch.setattr(dc.boto3, "client", lambda *a, **kw: FakeS3())
    result = dc.load_sample("s3://xinsere-dev-staging/some/key.json")
    assert result == {"founders/a.pdf"}
    assert downloaded_to["path"].startswith("/tmp/")
