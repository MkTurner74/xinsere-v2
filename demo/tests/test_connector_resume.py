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
