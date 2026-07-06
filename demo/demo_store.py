"""Demo persistence: users, a virtual file tree (folders + files), shares, and a
JSON-backed index so the pipeline survives restarts.

Real file bytes go through the actual PipelineService (fragmented, encrypted,
scattered). The tree/folder structure and sharing live here in the demo layer —
that's how a production build would model "source-asset trees" on top of the DPD
core: folders are metadata; every leaf file is a real DPD object.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone

# Make the pipeline package importable from the sibling lambdas/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lambdas", "pipeline"))

from xinsere_pipeline import PipelineService  # noqa: E402
from xinsere_pipeline.backends.base import (  # noqa: E402
    FileRecord,
    FragmentRecord,
    IndexStore,
)
from xinsere_pipeline.backends.local import LocalKeyManager, LocalObjectStore  # noqa: E402

DATA_DIR = os.environ.get("XINSERE_DATA_DIR", os.path.join(_HERE, "data"))
OBJECTS_DIR = os.path.join(DATA_DIR, "objects")
MASTER_KEY_FILE = os.path.join(DATA_DIR, "master.key")
INDEX_FILE = os.path.join(DATA_DIR, "index.json")
DEMO_FILE = os.path.join(DATA_DIR, "demo.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


# --- Persistent index for the pipeline --------------------------------------

class JsonIndexStore(IndexStore):
    """DynamoDB stand-in that persists to a JSON file so uploads survive restarts."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._files: dict = {}
        self._fragments: dict = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._files = {k: FileRecord(**v) for k, v in raw.get("files", {}).items()}
        for fid, frags in raw.get("fragments", {}).items():
            self._fragments[fid] = [
                FragmentRecord(
                    file_id=fr["file_id"], sequence=fr["sequence"],
                    fragment_id=fr["fragment_id"], bucket=fr["bucket"],
                    wrapped_key=_unb64(fr["wrapped_key"]), nonce=_unb64(fr["nonce"]),
                )
                for fr in frags
            ]

    def _save(self) -> None:
        raw = {
            "files": {k: vars(v) for k, v in self._files.items()},
            "fragments": {
                fid: [
                    {**vars(fr), "wrapped_key": _b64(fr.wrapped_key), "nonce": _b64(fr.nonce)}
                    for fr in frags
                ]
                for fid, frags in self._fragments.items()
            },
        }
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f)
        os.replace(tmp, self._path)

    def put_file(self, rec: FileRecord) -> None:
        with self._lock:
            self._files[rec.file_id] = rec
            self._save()

    def get_file(self, file_id: str):
        return self._files.get(file_id)

    def find_file_by_sha(self, file_sha256: str):
        for rec in self._files.values():
            if rec.file_sha256 == file_sha256:
                return rec
        return None

    def put_fragment(self, rec: FragmentRecord) -> None:
        with self._lock:
            self._fragments.setdefault(rec.file_id, []).append(rec)
            self._save()

    def get_fragments(self, file_id: str):
        return sorted(self._fragments.get(file_id, []), key=lambda f: f.sequence)

    def delete_file(self, file_id: str) -> None:
        with self._lock:
            self._files.pop(file_id, None)
            self._fragments.pop(file_id, None)
            self._save()


# --- Demo store: tree + shares ----------------------------------------------

class DemoStore:
    def __init__(self) -> None:
        os.makedirs(OBJECTS_DIR, exist_ok=True)
        # Persisted master key so encrypted fragments stay decryptable across restarts.
        if os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, "rb") as f:
                master = f.read()
        else:
            master = os.urandom(32)
            with open(MASTER_KEY_FILE, "wb") as f:
                f.write(master)

        self.pipeline = PipelineService(
            LocalObjectStore(bucket_count=8, root=OBJECTS_DIR),
            LocalKeyManager(master_key=master),
            JsonIndexStore(INDEX_FILE),
            fragment_count=7,
        )
        self._lock = threading.Lock()
        self.nodes: dict = {}   # node_id -> node dict
        self.shares: list = []  # {node_id, grantee, tx, at}
        self._load()

    # persistence
    def _load(self) -> None:
        if os.path.exists(DEMO_FILE):
            with open(DEMO_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.nodes = raw.get("nodes", {})
            self.shares = raw.get("shares", [])

    def _save(self) -> None:
        tmp = DEMO_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"nodes": self.nodes, "shares": self.shares}, f, indent=1)
        os.replace(tmp, DEMO_FILE)

    def ensure_root(self, user_id: str) -> str:
        """Create the user's root folder on first sign-in; return its id."""
        rid = self.root_id(user_id)
        if rid not in self.nodes:
            with self._lock:
                self.nodes[rid] = {
                    "id": rid, "type": "folder", "name": "My Files",
                    "parent": None, "owner": user_id, "created_at": _now(),
                }
                self._save()
        return rid

    # tree ops
    def root_id(self, user: str) -> str:
        return f"root:{user}"

    def children(self, parent_id: str) -> list:
        kids = [n for n in self.nodes.values() if n.get("parent") == parent_id]
        kids.sort(key=lambda n: (n["type"] != "folder", n["name"].lower()))
        return kids

    def node(self, node_id: str):
        return self.nodes.get(node_id)

    def create_folder(self, name: str, parent_id: str, owner: str) -> dict:
        nid = "fld_" + uuid.uuid4().hex[:12]
        node = {"id": nid, "type": "folder", "name": name, "parent": parent_id,
                "owner": owner, "created_at": _now()}
        with self._lock:
            self.nodes[nid] = node
            self._save()
        return node

    def add_file(self, name: str, parent_id: str, owner: str, content: bytes,
                 content_type: str) -> dict:
        res = self.pipeline.store(content, content_type, label=name)
        nid = "fil_" + uuid.uuid4().hex[:12]
        node = {
            "id": nid, "type": "file", "name": name, "parent": parent_id,
            "owner": owner, "created_at": _now(),
            "file_id": res.file_id, "sha": res.file_sha256,
            "size": len(content), "frags": res.fragment_count,
            "content_type": content_type,
        }
        with self._lock:
            self.nodes[nid] = node
            self._save()
        return node

    def ensure_path(self, rel_path: str, root_id: str, owner: str) -> str:
        """Create nested folders for a relative dir path; return the leaf folder id."""
        parent = root_id
        for part in [p for p in rel_path.split("/") if p]:
            existing = next(
                (n for n in self.children(parent)
                 if n["type"] == "folder" and n["name"] == part), None)
            parent = existing["id"] if existing else self.create_folder(part, parent, owner)["id"]
        return parent

    def files_under(self, node_id: str) -> list[dict]:
        """All file nodes at or below node_id (recursive). A file returns itself."""
        node = self.nodes.get(node_id)
        if not node:
            return []
        if node["type"] == "file":
            return [node]
        out: list[dict] = []
        for child in self.children(node_id):
            out.extend(self.files_under(child["id"]))
        return out

    def retrieve(self, node: dict) -> tuple[bytes, str]:
        r = self.pipeline.retrieve(node["file_id"])
        return r.content, r.content_type

    # sharing
    def share(self, node_id: str, grantee: str, tx: str | None = None) -> dict:
        rec = {"node_id": node_id, "grantee": grantee, "tx": tx, "at": _now()}
        with self._lock:
            if not any(s["node_id"] == node_id and s["grantee"] == grantee for s in self.shares):
                self.shares.append(rec)
                self._save()
        return rec

    def shares_for_node(self, node_id: str) -> list:
        return [s for s in self.shares if s["node_id"] == node_id]

    def _ancestors(self, node_id: str) -> list[str]:
        chain, cur = [], self.nodes.get(node_id)
        while cur:
            chain.append(cur["id"])
            cur = self.nodes.get(cur.get("parent")) if cur.get("parent") else None
        return chain

    def can_access(self, user: str, node_id: str) -> bool:
        node = self.nodes.get(node_id)
        if not node:
            return False
        if node["owner"] == user:
            return True
        shared_ids = {s["node_id"] for s in self.shares if s["grantee"] == user}
        return any(a in shared_ids for a in self._ancestors(node_id))

    def shared_with(self, user: str) -> list:
        """Top-level nodes shared directly with `user` (folders or files)."""
        ids = [s["node_id"] for s in self.shares if s["grantee"] == user]
        return [self.nodes[i] for i in ids if i in self.nodes]


STORE = DemoStore()
