"""Duplicate-name conflict handling + deep-nesting verification (2026-07-20).

Covers the "Keep both / Cancel" collision model (Mark 2026-07-20 — no destructive
Replace) and the folder-upload path-rebuild:

  * _suffix_name: ' (n)' goes before a file's extension, at the end of a folder,
    and cascades (2)->(3) past names already taken.
  * _resolve_name: no collision passes through; a collision 409s with a suggestion;
    on_conflict='keep-both' auto-suffixes to a free name.
  * ensure_path: a deep relative path rebuilds the exact folder chain, REUSES the
    existing folders on a re-upload (no duplicates), and rejects an absurd depth.
"""
import pytest

import app
import supa
from fastapi import HTTPException


# --- _suffix_name (pure) ----------------------------------------------------

def test_suffix_name_inserts_counter_before_file_extension():
    assert app._suffix_name("report.pdf", True, {"report.pdf"}) == "report (2).pdf"


def test_suffix_name_appends_for_a_folder():
    assert app._suffix_name("Documents", False, {"documents"}) == "Documents (2)"


def test_suffix_name_cascades_past_taken_variants():
    taken = {"report.pdf", "report (2).pdf", "report (3).pdf"}
    assert app._suffix_name("report.pdf", True, taken) == "report (4).pdf"


# --- _resolve_name (uses supa.children) -------------------------------------

class _Kids:
    """Monkeypatch target for supa.children — returns a fixed sibling set."""
    def __init__(self, names_types):
        self._kids = [{"id": f"n{i}", "type": t, "name": nm}
                      for i, (nm, t) in enumerate(names_types)]

    def __call__(self, token, parent_id):
        return list(self._kids)


def test_resolve_name_passes_through_when_no_collision(monkeypatch):
    monkeypatch.setattr(supa, "children", _Kids([("other.pdf", "file")]))
    assert app._resolve_name("t", "p", "report.pdf", is_file=True,
                             exclude_id=None, on_conflict=None) == "report.pdf"


def test_resolve_name_is_case_insensitive_and_409s(monkeypatch):
    monkeypatch.setattr(supa, "children", _Kids([("Report.PDF", "file")]))
    with pytest.raises(HTTPException) as ei:
        app._resolve_name("t", "p", "report.pdf", is_file=True,
                          exclude_id=None, on_conflict=None)
    assert ei.value.status_code == 409
    assert ei.value.detail["conflict"] is True
    assert ei.value.detail["suggestion"] == "report (2).pdf"


def test_resolve_name_keep_both_auto_suffixes(monkeypatch):
    monkeypatch.setattr(supa, "children", _Kids([("report.pdf", "file")]))
    assert app._resolve_name("t", "p", "report.pdf", is_file=True,
                             exclude_id=None, on_conflict="keep-both") == "report (2).pdf"


def test_resolve_name_excludes_self_so_a_noop_rename_is_allowed(monkeypatch):
    # The item keeping its own name (case-only edit) must not collide with itself.
    monkeypatch.setattr(supa, "children",
                        lambda token, parent: [{"id": "self", "type": "file", "name": "a.pdf"}])
    assert app._resolve_name("t", "p", "a.pdf", is_file=True,
                             exclude_id="self", on_conflict=None) == "a.pdf"


# --- ensure_path deep nesting (fake in-memory tree) -------------------------

class FakeTree:
    """Minimal in-memory node store for ensure_path: children() + insert_folder()."""
    def __init__(self):
        self.nodes: dict[str, dict] = {"root": {"id": "root", "type": "folder", "name": "", "parent": None}}
        self._seq = 0

    def children(self, token, parent_id):
        return [n for n in self.nodes.values() if n.get("parent") == parent_id]

    def insert_folder(self, token, name, parent_id, owner):
        self._seq += 1
        nid = f"f{self._seq}"
        self.nodes[nid] = {"id": nid, "type": "folder", "name": name, "parent": parent_id}
        return self.nodes[nid]


def test_ensure_path_rebuilds_deep_chain_then_reuses_it(monkeypatch):
    tree = FakeTree()
    monkeypatch.setattr(supa, "children", tree.children)
    monkeypatch.setattr(supa, "insert_folder", tree.insert_folder)

    rel = "/".join(f"level{i}" for i in range(20))     # 20 levels deep
    leaf = supa.ensure_path("t", rel, "root", "owner")

    # Exactly 20 folders created, chained parent->child in order.
    folders = [n for n in tree.nodes.values() if n["id"] != "root"]
    assert len(folders) == 20
    assert tree.nodes[leaf]["name"] == "level19"

    # Re-uploading the same path REUSES every folder — no duplicates.
    leaf2 = supa.ensure_path("t", rel, "root", "owner")
    assert leaf2 == leaf
    assert len([n for n in tree.nodes.values() if n["id"] != "root"]) == 20


def test_ensure_path_strips_dot_segments(monkeypatch):
    tree = FakeTree()
    monkeypatch.setattr(supa, "children", tree.children)
    monkeypatch.setattr(supa, "insert_folder", tree.insert_folder)
    leaf = supa.ensure_path("t", "a/./b/../c", "root", "owner")
    # '.' and '..' are dropped, so only a, b, c folders exist (no traversal).
    names = sorted(n["name"] for n in tree.nodes.values() if n["id"] != "root")
    assert names == ["a", "b", "c"]
    assert tree.nodes[leaf]["name"] == "c"


def test_ensure_path_rejects_absurd_depth(monkeypatch):
    tree = FakeTree()
    monkeypatch.setattr(supa, "children", tree.children)
    monkeypatch.setattr(supa, "insert_folder", tree.insert_folder)
    monkeypatch.setattr(supa, "MAX_PATH_DEPTH", 8)
    rel = "/".join(f"d{i}" for i in range(9))
    with pytest.raises(supa.PathTooDeepError):
        supa.ensure_path("t", rel, "root", "owner")
