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
import hashlib
import json
import sys
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
        """Recursively yield every file under `path` (folders skipped), applying
        the top-level personal exclusions."""
        r = self._post(f"{API}/files/list_folder", {"path": path, "recursive": True, "limit": 2000})
        while True:
            for e in r["entries"]:
                if e[".tag"] != "file":
                    continue
                disp = e["path_display"]
                top = disp.strip("/").split("/", 1)[0]
                if top in EXCLUDE_TOP:
                    continue
                yield DbxFile(disp, e["id"], e["size"], e["content_hash"])
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


# --- Migration report ------------------------------------------------------
@dataclass
class Report:
    sourced: int = 0
    stored: int = 0
    verified: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    bytes_in: int = 0
    started: float = field(default_factory=time.time)

    def as_dict(self, files: int, folders: int) -> dict:
        return {
            "manifest_files": files,
            "manifest_folders": folders,
            "sourced": self.sourced,
            "stored": self.stored,
            "verified": self.verified,
            "failed": self.failed,
            "bytes_in": self.bytes_in,
            "gb_in": round(self.bytes_in / 1e9, 3),
            "wall_seconds": round(time.time() - self.started, 1),
        }


# --- Runner ----------------------------------------------------------------
class MigrationRunner:
    def __init__(self, client: DropboxClient):
        self.client = client

    def enumerate(self, folder: str) -> tuple[list[DbxFile], int]:
        """Build the manifest (L1 source of truth). Returns (files, small<128KB)."""
        files = list(self.client.walk(folder))
        small = sum(1 for f in files if f.size < 128 * 1024)
        return files, small

    def run(self, folder: str, *, limit: int | None, full: bool) -> Report:
        rep = Report()
        files, small = self.enumerate(folder)
        rep.sourced = len(files)
        print(f"Manifest: {len(files)} files, {small} under 128KB "
              f"({100 * small / max(len(files), 1):.0f}%), "
              f"{sum(f.size for f in files) / 1e9:.2f} GB", file=sys.stderr)

        if not full:
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

        for f in files[: limit or len(files)]:
            try:
                data = self.client.download(f.path)
                rep.bytes_in += len(data)
                # L3 reference cross-check (independent of our own hashing)
                if dropbox_content_hash(data) != f.content_hash:
                    raise ValueError("Dropbox content_hash mismatch on download")
                res = pipeline.store(data, _content_type(f.path), label=f.path.rsplit("/", 1)[-1])
                rep.stored += 1
                # Recreate the tree: /Founders/sub/x.pdf -> folders under root_node
                rel = f.path.lstrip("/")
                rel_dir, name = (rel.rsplit("/", 1) + [""])[:2] if "/" in rel else ("", rel)
                parent = supa.ensure_path(token, rel_dir, root_node, owner) if rel_dir else root_node
                supa.insert_file(token, name, parent, owner, file_id=res.file_id,
                                 sha256=res.file_sha256, size=f.size,
                                 frags=res.fragment_count, content_type=_content_type(f.path))
                # L2: reassemble + re-hash through the real retrieve path
                got = pipeline.retrieve(res.file_id)
                if got.file_sha256 != res.file_sha256:
                    raise ValueError("L2 reassembly SHA-256 mismatch")
                rep.verified += 1
                print(f"  OK  {f.path}  ({len(data)} B)", file=sys.stderr)
            except Exception as e:  # noqa: BLE001 -- per-file isolation; run continues
                rep.failed.append((f.path, str(e)))
                print(f"  FAIL {f.path}: {e}", file=sys.stderr)
        return rep


def _content_type(path: str) -> str:
    import mimetypes
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def main() -> None:
    ap = argparse.ArgumentParser(description="Dropbox -> Xinsere migration connector")
    ap.add_argument("--folder", default="/Founders", help="Team-root path to migrate")
    ap.add_argument("--limit", type=int, default=None, help="Cap files (test runs)")
    ap.add_argument("--full", action="store_true",
                    help="Actually store+index+verify (default: enumerate-only)")
    args = ap.parse_args()

    runner = MigrationRunner(DropboxClient(DropboxAuth()))
    rep = runner.run(args.folder, limit=args.limit, full=args.full)
    print(json.dumps(rep.as_dict(rep.sourced, 0), indent=2))


if __name__ == "__main__":
    main()
