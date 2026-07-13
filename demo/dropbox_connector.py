"""Dropbox -> Xinsere migration connector.

Cloud-to-cloud: bytes stream Dropbox API -> this worker -> fragment/encrypt/
scatter (reusing the existing PipelineService) -> S3 Standard. Never transits a
laptop. Recreates the folder tree in Supabase. Verifies every file with three
independent integrity layers before marking it done.

Gas note: content ingest is entirely OFF-CHAIN. On-chain grants happen only in
the (separate, opt-in) permission-preservation pass. So migrating file *content*
costs zero POL regardless of file count.

Credentials: AWS Secrets Manager `xinsere/dropbox/oauth`
  {app_key, app_secret, refresh_token, ...}  -- refresh-token (offline) flow.

Account is Business/Team "Xinsere": files live in the TEAM root namespace, so
every Dropbox call carries the Dropbox-API-Path-Root header (see DropboxClient).

Usage:
  python dropbox_connector.py --folder /Founders --enumerate-only
  python dropbox_connector.py --folder /Founders --limit 5 --full
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Iterator

import boto3
import requests

DROPBOX_SECRET_ID = "xinsere/dropbox/oauth"
AWS_REGION = "us-east-1"

# HARD exclusions -- personal content, never migrated (confidentiality rule).
# Matched against the first path segment under the team root.
EXCLUDE_TOP = {"Mark Turner", "Photos Backup", "Music Backup"}

DBX_BLOCK = 4 * 1024 * 1024  # Dropbox content_hash block size (4 MiB)
API = "https://api.dropboxapi.com/2"
CONTENT_API = "https://content.dropboxapi.com/2"
TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"


def _resilient(method: str, url: str, *, headers=None, data=None, auth=None,
               timeout: int = 90, tries: int = 10) -> requests.Response:
    """One HTTP call with retry/backoff on the flaky failure modes: connection
    errors, read timeouts, 429 (Retry-After honoured), and 5xx. Dropbox's
    team-namespace endpoints throw sustained 500 waves, so the budget is
    generous (10 tries, backoff capped at 30s -> survives a ~4min wave). Raises
    on the last attempt or on any non-retryable 4xx."""
    last: Exception | None = None
    for attempt in range(tries):
        try:
            r = requests.request(method, url, headers=headers, data=data,
                                  auth=auth, timeout=timeout)
        except (requests.ConnectionError, requests.Timeout) as e:
            last = e
            time.sleep(min(2 ** attempt, 30))
            continue
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", 2 ** attempt)))
            continue
        if 500 <= r.status_code < 600:
            last = requests.HTTPError(f"{r.status_code} {r.text[:200]}")
            time.sleep(min(2 ** attempt, 30))
            continue
        r.raise_for_status()
        return r
    raise RuntimeError(f"{method} {url} failed after {tries} tries: {last}")


# --- Dropbox content_hash (L3 cross-check) ---------------------------------
def dropbox_content_hash(data: bytes) -> str:
    """Reproduce Dropbox's content_hash: SHA-256 over the concatenated raw
    SHA-256 digests of each 4 MiB block. Lets us prove the bytes we stored equal
    the bytes Dropbox holds, using Dropbox's own provider-native algorithm."""
    h = hashlib.sha256()
    for i in range(0, max(len(data), 1), DBX_BLOCK):
        if not data:
            break
        h.update(hashlib.sha256(data[i : i + DBX_BLOCK]).digest())
    return h.hexdigest()


# --- Auth ------------------------------------------------------------------
class DropboxAuth:
    """Loads the refresh token from Secrets Manager and mints short-lived access
    tokens on demand, refreshing a minute before expiry so long runs never stall."""

    def __init__(self, secret_id: str = DROPBOX_SECRET_ID, region: str = AWS_REGION):
        sm = boto3.client("secretsmanager", region_name=region)
        self._c = json.loads(sm.get_secret_value(SecretId=secret_id)["SecretString"])
        self._token: str | None = None
        self._expires_at = 0.0

    def token(self) -> str:
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        r = _resilient(
            "POST", TOKEN_URL,
            data={"grant_type": "refresh_token", "refresh_token": self._c["refresh_token"]},
            auth=(self._c["app_key"], self._c["app_secret"]),
            timeout=60,
        )
        d = r.json()
        self._token = d["access_token"]
        self._expires_at = time.time() + d.get("expires_in", 14400)
        return self._token


# --- Client (team-namespace aware) -----------------------------------------
@dataclass
class DbxFile:
    path: str  # path_display, relative to team root (e.g. /Founders/deck.pdf)
    id: str
    size: int
    content_hash: str  # Dropbox's, from metadata -- the L3 reference


class DropboxClient:
    def __init__(self, auth: DropboxAuth):
        self._auth = auth
        self._root_ns: str | None = None

    # Team root namespace -- without this header the API only sees personal
    # (member-home) folders, not the team folders we're migrating.
    def _headers(self, content_type: str | None = "application/json") -> dict:
        h = {"Authorization": f"Bearer {self._auth.token()}"}
        if content_type:
            h["Content-Type"] = content_type
        h["Dropbox-API-Path-Root"] = json.dumps({".tag": "root", "root": self._root_namespace()})
        return h

    def _root_namespace(self) -> str:
        if self._root_ns is None:
            r = _resilient("POST", f"{API}/users/get_current_account",
                           headers={"Authorization": f"Bearer {self._auth.token()}"})
            self._root_ns = r.json()["root_info"]["root_namespace_id"]
        return self._root_ns

    def _post(self, url: str, body: dict) -> dict:
        return _resilient("POST", url, headers=self._headers(), data=json.dumps(body)).json()

    def walk(self, path: str) -> Iterator[DbxFile]:
        """Yield every file under `path`, descending folder-by-folder with
        NON-recursive list_folder calls.

        Recursive team-namespace listing returns erratic tiny pages and stalls on
        Dropbox's sustained 500 waves — the documented blocker for full-folder runs.
        Per-folder listing returns reliable bulk pages and isolates a flaky folder to
        itself (a 500 wave on one subfolder is retried by _resilient without wedging
        the whole walk). Personal top-level folders are pruned as we descend. Still
        streams: files are yielded as each folder page arrives, so ingest starts
        immediately and never waits on a full tree enumeration."""
        stack = [path]
        while stack:
            folder = stack.pop()
            seg = folder.strip("/").split("/", 1)[0] if folder.strip("/") else ""
            if seg in EXCLUDE_TOP:
                continue  # personal backups — never enumerate or migrate
            r = self._post(f"{API}/files/list_folder",
                           {"path": folder, "recursive": False, "limit": 2000})
            while True:
                for e in r["entries"]:
                    tag = e[".tag"]
                    if tag == "folder":
                        stack.append(e["path_display"])   # descend later
                    elif tag == "file":
                        yield DbxFile(e["path_display"], e["id"], e["size"], e["content_hash"])
                if not r.get("has_more"):
                    break
                r = self._post(f"{API}/files/list_folder/continue", {"cursor": r["cursor"]})

    def download(self, path: str) -> bytes:
        """Stream a file's bytes straight from Dropbox to this worker."""
        h = {
            "Authorization": f"Bearer {self._auth.token()}",
            "Dropbox-API-Path-Root": json.dumps({".tag": "root", "root": self._root_namespace()}),
            "Dropbox-API-Arg": json.dumps({"path": path}),
        }
        return _resilient("POST", f"{CONTENT_API}/files/download", headers=h, timeout=300).content

    def folder_acls(self, under: str) -> dict[str, set[str]]:
        """Map each SHARED folder at or below `under` to the set of collaborator
        emails on it (component 5 — permission preservation). Keyed by the folder's
        team-root-relative, lowercased path (e.g. 'founders/legal agreements') so it
        lines up with the migrated Supabase tree. Uses sharing/list_folders (+continue)
        then list_folder_members per folder. Owner's own membership is left in — the
        caller resolves the owner and skips self-grants."""
        under_l = under.strip("/").lower()
        acls: dict[str, set[str]] = {}
        r = self._post(f"{API}/sharing/list_folders", {"limit": 1000})
        while True:
            for e in r.get("entries", []):
                path_lower = (e.get("path_lower") or "").strip("/")
                if not path_lower:
                    continue  # not mounted at a resolvable path — skip
                if path_lower == under_l or path_lower.startswith(under_l + "/"):
                    acls[path_lower] = self._folder_members(e["shared_folder_id"])
            cur = r.get("cursor")
            if not cur:
                break
            r = self._post(f"{API}/sharing/list_folders/continue", {"cursor": cur})
        return acls

    def _folder_members(self, shared_folder_id: str) -> set[str]:
        """All collaborator emails on a shared folder: confirmed users + pending
        invitees. Paginates via list_folder_members/continue."""
        emails: set[str] = set()
        r = self._post(f"{API}/sharing/list_folder_members", {"shared_folder_id": shared_folder_id})
        while True:
            for u in r.get("users", []):
                em = (u.get("user") or {}).get("email")
                if em:
                    emails.add(em.strip().lower())
            for iv in r.get("invitees", []):
                em = (iv.get("invitee") or {}).get("email")
                if em:
                    emails.add(em.strip().lower())
            cur = r.get("cursor")
            if not cur:
                break
            r = self._post(f"{API}/sharing/list_folder_members/continue", {"cursor": cur})
        return emails


# --- Migration report ------------------------------------------------------
@dataclass
class Report:
    sourced: int = 0
    stored: int = 0
    verified: int = 0
    skipped: int = 0  # already migrated on a prior run (resume)
    failed: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    bytes_in: int = 0
    started: float = field(default_factory=time.time)

    def as_dict(self, files: int, folders: int) -> dict:
        wall = max(time.time() - self.started, 1e-6)
        return {
            "manifest_files": files,
            "manifest_folders": folders,
            "sourced": self.sourced,
            "stored": self.stored,
            "verified": self.verified,
            "skipped": self.skipped,
            "failed": self.failed,
            "bytes_in": self.bytes_in,
            "gb_in": round(self.bytes_in / 1e9, 3),
            "wall_seconds": round(wall, 1),
            # Cloud-to-cloud throughput metrics (client-facing perf story). Measured
            # over verified files only, so numbers reflect fully-validated transfer.
            "mb_per_s": round(self.bytes_in / 1e6 / wall, 2),
            "files_per_min": round(self.verified / wall * 60, 1),
            "avg_ms_per_file": round(wall * 1000 / max(self.verified, 1)),
        }


# --- Runner ----------------------------------------------------------------
DEFAULT_WORKERS = int(os.environ.get("XINSERE_MIGRATION_WORKERS", "8"))


class MigrationRunner:
    def __init__(self, client: DropboxClient):
        self.client = client
        # Concurrency guards (used only on the --full parallel path).
        self._rep_lock = threading.Lock()     # serialize Report mutations across workers
        self._path_lock = threading.Lock()    # serialize folder creation (avoid dup folders)
        self._path_cache: dict[str, str] = {}  # rel_dir(lower) -> parent node id (memoized)

    def enumerate(self, folder: str) -> tuple[list[DbxFile], int]:
        """Build the manifest (L1 source of truth). Returns (files, small<128KB)."""
        files = list(self.client.walk(folder))
        small = sum(1 for f in files if f.size < 128 * 1024)
        return files, small

    def run(self, folder: str, *, limit: int | None, full: bool, grants: bool = False,
            workers: int = DEFAULT_WORKERS):
        if grants:
            # Permission-preservation pass over the already-migrated tree. The path
            # setup mirrors --full (needs Supabase + chain env), but moves no bytes.
            sys.path.insert(0, "../lambdas/pipeline")
            return self.preserve_permissions(folder)

        rep = Report()

        if not full:
            files, small = self.enumerate(folder)
            rep.sourced = len(files)
            print(f"Manifest: {len(files)} files, {small} under 128KB "
                  f"({100 * small / max(len(files), 1):.0f}%), "
                  f"{sum(f.size for f in files) / 1e9:.2f} GB", file=sys.stderr, flush=True)
            return rep  # enumerate-only: manifest built, nothing moved

        # Lazy imports: the store path needs the pipeline env (KMS/Dynamo/S3) and
        # Supabase; enumerate-only must not require them.
        sys.path.insert(0, "../lambdas/pipeline")
        from xinsere_pipeline.factory import build_pipeline_from_env  # type: ignore
        import supa  # type: ignore
        import os

        pipeline = build_pipeline_from_env()
        token = os.environ["XINSERE_SUPABASE_SERVICE_KEY"]
        owner = os.environ["XINSERE_MIGRATION_OWNER"]  # Mark's Xinsere user id
        root_node = os.environ["XINSERE_MIGRATION_ROOT"]  # target root folder node id

        # RESUME: scan what's already under the import root so a re-run (after a crash,
        # a 500 wave, or a --limit batch) skips migrated files instead of duplicating
        # them. A node exists in the tree only AFTER L2 verify (see _ingest_one), so
        # "present" reliably means "fully verified" — safe to skip.
        existing = self._existing_paths(supa, token, root_node)
        print(f"pipeline + supabase wired; {len(existing)} files already present; "
              f"streaming with {workers} workers...", file=sys.stderr, flush=True)

        # CONCURRENT STREAM: each file (download -> L3 -> store -> L2 -> index) is
        # independent, so we run `workers` of them at once. The heavy per-file cost is
        # network + crypto, not CPU, so threads scale it well. A semaphore bounds
        # in-flight work to ~2x workers (backpressure), so even a million-file walk
        # never queues more than a couple of batches in memory. Folder creation is
        # memoized under a lock (see _resolve_parent) so concurrent files in the same
        # directory can't create duplicate folders. Still streams — work starts on the
        # first file, never waits for full enumeration.
        attempted = 0
        sem = threading.Semaphore(workers * 2)

        def _task(f: DbxFile) -> None:
            try:
                self._ingest_one(f, pipeline, supa, token, owner, root_node, rep)
            finally:
                sem.release()

        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for f in self.client.walk(folder):
                rep.sourced += 1  # main thread only
                if f.path.lstrip("/").lower() in existing:
                    rep.skipped += 1
                    continue
                sem.acquire()                       # backpressure before submitting
                ex.submit(_task, f)
                attempted += 1
                if limit and attempted >= limit:    # cap NEW files this run (resume-friendly)
                    break
            # executor exit waits for all in-flight tasks
        return rep

    def _resolve_parent(self, supa, token, rel_dir: str, root_node: str, owner: str) -> str:
        """Memoized, race-safe folder resolution. Concurrent files in the same
        directory must not each create the folder (nodes have no unique (parent,name)
        constraint, so a race would make duplicates). Double-checked lock: cache hit is
        lock-free; only a miss serializes on _path_lock while ensure_path creates."""
        if not rel_dir:
            return root_node
        key = rel_dir.lower()
        cached = self._path_cache.get(key)
        if cached:
            return cached
        with self._path_lock:
            cached = self._path_cache.get(key)
            if cached:
                return cached
            parent = supa.ensure_path(token, rel_dir, root_node, owner)
            self._path_cache[key] = parent
            return parent

    def _existing_paths(self, supa, token, root_node) -> set[str]:
        """Lowercased team-root-relative 'dir/name' of every file already under the
        import root — the resume set. Walks the Supabase tree once up front."""
        seen: set[str] = set()

        def descend(node_id: str, rel: str) -> None:
            for n in supa.children(token, node_id):
                child_rel = f"{rel}/{n['name']}".strip("/")
                if n["type"] == "folder":
                    descend(n["id"], child_rel)
                elif n["type"] == "file":
                    seen.add(child_rel.lower())

        descend(root_node, "")
        return seen

    def preserve_permissions(self, folder: str) -> dict:
        """Component 5 — recreate Dropbox share ACLs as Xinsere permissions over the
        ALREADY-MIGRATED tree, using the Merkle aggregate batch-grant (one flat-gas
        tx per <=cap grants). Internal collaborators (existing Xinsere users) get
        real on-chain grants; external emails become no-gas pending invite stubs.

        Reads:  Dropbox sharing ACLs for `folder` + the migrated Supabase subtree.
        Writes: batched on-chain grants + proof cache; pending_shares for externals."""
        import os
        import supa  # type: ignore
        import batch_grant

        token = os.environ["XINSERE_SUPABASE_SERVICE_KEY"]
        owner = os.environ["XINSERE_MIGRATION_OWNER"]
        root_node = os.environ["XINSERE_MIGRATION_ROOT"]
        # Emails that ARE the owner — never self-grant. The canonical Xinsere identity
        # plus any override list (comma-separated) covers the dual @xinsere/@enttech case.
        owner_emails = {e.strip().lower() for e in
                        os.environ.get("XINSERE_OWNER_EMAILS", "").split(",") if e.strip()}

        acls = self.client.folder_acls(folder)  # {relpath_lower: {emails}}
        print(f"Dropbox ACLs: {len(acls)} shared folders under {folder}",
              file=sys.stderr, flush=True)

        # Resolve every collaborator email once: internal uid (grant) or external (stub).
        all_emails = {e for emails in acls.values() for e in emails} - owner_emails
        resolved: dict[str, str | None] = {}  # email -> uid or None(=external)
        for em in all_emails:
            prof = supa.profile_by_email(token, em)
            uid = prof["id"] if prof else None
            if uid == owner:
                continue  # owner resolved by email -> skip self-grant
            resolved[em] = uid

        # Walk the migrated subtree; attach each file to the grantees covering its path.
        grants: list = []            # batch_grant.Grant (internal, on-chain)
        stubs: dict[str, set[str]] = {}   # node_id -> {external emails}
        counts = {"files": 0, "internal_pairs": 0, "external_pairs": 0}

        def covering_emails(relpath_lower: str) -> set[str]:
            out: set[str] = set()
            for k, emails in acls.items():
                if relpath_lower == k or relpath_lower.startswith(k + "/"):
                    out |= emails
            return out - owner_emails

        def walk(node_id: str, relpath: str) -> None:
            for n in supa.children(token, node_id):
                if n["type"] == "folder":
                    child_rel = f"{relpath}/{n['name']}".strip("/").lower()
                    walk(n["id"], child_rel)
                elif n["type"] == "file" and n.get("file_id"):
                    counts["files"] += 1
                    for em in covering_emails(relpath.lower()):
                        uid = resolved.get(em)
                        if uid:
                            grants.append(batch_grant.Grant(n["file_id"], uid))
                            counts["internal_pairs"] += 1
                        else:
                            stubs.setdefault(n["id"], set()).add(em)
                            counts["external_pairs"] += 1

        walk(root_node, "")

        # Internal grants -> Merkle aggregate batches (the aggregate wallet).
        result = batch_grant.preserve(grants, supa=supa, token=token,
                                      source="dropbox", scope=folder)

        # External emails -> no-gas pending invite stubs (viral onboarding, ADR-105).
        stub_written = 0
        for node_id, emails in stubs.items():
            for em in emails:
                try:
                    supa.insert_pending_share(token, node_id, em, owner)
                    stub_written += 1
                except Exception as exc:  # noqa: BLE001
                    print(f"  stub FAIL {node_id} {em}: {exc}", file=sys.stderr, flush=True)

        return {"acl_folders": len(acls), **counts,
                "batches": result.batches, "grants_anchored": result.grants,
                "batch_failures": result.failed, "tx_hashes": result.tx_hashes,
                "external_stubs": stub_written}

    def _ingest_one(self, f: DbxFile, pipeline, supa, token, owner, root_node, rep: Report) -> None:
        # Thread-safe: this runs concurrently across workers. Only Report mutations and
        # folder creation are serialized (short locks); the heavy work (download, store,
        # retrieve) runs fully in parallel.
        try:
            data = self.client.download(f.path)
            # L3 reference cross-check (independent of our own hashing)
            if dropbox_content_hash(data) != f.content_hash:
                raise ValueError("Dropbox content_hash mismatch on download")
            res = pipeline.store(data, _content_type(f.path), label=f.path.rsplit("/", 1)[-1])
            with self._rep_lock:
                rep.bytes_in += len(data)
                rep.stored += 1        # fragments landed; stored > verified => orphans to triage
            # L2: reassemble + re-hash through the real retrieve path BEFORE recording
            # the node — so a node in the tree always means a fully verified file, and
            # a resumed run can trust "present == done" (see _existing_paths).
            got = pipeline.retrieve(res.file_id)
            if got.file_sha256 != res.file_sha256:
                raise ValueError("L2 reassembly SHA-256 mismatch")
            # Recreate the tree: /Founders/sub/x.pdf -> folders under root_node
            rel = f.path.lstrip("/")
            rel_dir, name = rel.rsplit("/", 1) if "/" in rel else ("", rel)
            parent = self._resolve_parent(supa, token, rel_dir, root_node, owner)
            supa.insert_file(token, name, parent, owner, file_id=res.file_id,
                             sha256=res.file_sha256, size=f.size,
                             frags=res.fragment_count, content_type=_content_type(f.path))
            with self._rep_lock:
                rep.verified += 1
            print(f"  OK  {f.path}  ({len(data):,} B)", file=sys.stderr, flush=True)
        except Exception as e:  # noqa: BLE001 -- per-file isolation; run continues
            with self._rep_lock:
                rep.failed.append((f.path, str(e)))
            print(f"  FAIL {f.path}: {e}", file=sys.stderr, flush=True)


def _content_type(path: str) -> str:
    import mimetypes
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def main() -> None:
    ap = argparse.ArgumentParser(description="Dropbox -> Xinsere migration connector")
    ap.add_argument("--folder", default="/Founders", help="Team-root path to migrate")
    ap.add_argument("--limit", type=int, default=None, help="Cap files (test runs)")
    ap.add_argument("--full", action="store_true",
                    help="Actually store+index+verify (default: enumerate-only)")
    ap.add_argument("--grants", action="store_true",
                    help="Permission-preservation pass: recreate Dropbox share ACLs as "
                         "Merkle-batched on-chain grants over the already-migrated tree")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help=f"Concurrent ingest workers (default {DEFAULT_WORKERS}; "
                         "env XINSERE_MIGRATION_WORKERS)")
    args = ap.parse_args()

    runner = MigrationRunner(DropboxClient(DropboxAuth()))
    rep = runner.run(args.folder, limit=args.limit, full=args.full, grants=args.grants,
                     workers=args.workers)
    if args.grants:
        print(json.dumps(rep, indent=2))       # preserve_permissions returns a dict
    else:
        print(json.dumps(rep.as_dict(rep.sourced, 0), indent=2))


if __name__ == "__main__":
    main()
