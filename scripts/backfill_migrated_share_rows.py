"""One-off backfill (2026-07-14): write the `shares` metadata rows the first
Dropbox migration's permission pass skipped.

The ACL pass anchored real on-chain batch grants for internal collaborators
(Jeremy 398, Joshua 402, Max 160 files) but never inserted `shares` rows, so
the app's listing (RLS has_node_access) and "Shared with me" showed nothing.
This maps each Dropbox shared folder -> the migrated folder node and upserts
one share row per internal collaborator (idempotent merge-duplicates; the
on-chain grants already exist and stay untouched). Also deletes the two
pending_share stubs to the owner's own alt email (mark.turner@reallyme.me),
which predate that address being listed in XINSERE_OWNER_EMAILS.

Run from repo root:  python scripts/backfill_migrated_share_rows.py [--dry-run]
Credentials: Supabase + Dropbox secrets are read from AWS Secrets Manager with
your local AWS profile — nothing sensitive is passed on the command line.
"""
import json
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))

MIGRATION_OWNER = "98b3cf84-88fa-4a35-9ee3-70ced1ba3c32"   # mark.turner@xinsere.com
MIGRATION_ROOT = "fld_11c55461f5b6"                        # migrated tree root
OWNER_EMAILS = {"mark.turner@xinsere.com", "mark.turner@entertainmenttechnologists.com",
                "mark.turner@reallyme.me"}
DRY = "--dry-run" in sys.argv


def main() -> None:
    sec = json.loads(boto3.client("secretsmanager", region_name="us-east-1")
                     .get_secret_value(SecretId="xinsere/supabase/service-role")["SecretString"])
    os.environ.setdefault("SUPABASE_URL", sec["url"])
    os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", sec["service_role_key"])
    os.environ.setdefault("XINSERE_BACKEND", "local")   # no pipeline needed here

    import supa                       # noqa: E402 (env must be set first)
    from dropbox_connector import DropboxAuth, DropboxClient  # noqa: E402
    supa.SUPABASE_URL = sec["url"].rstrip("/")
    supa.SERVICE_ROLE_KEY = sec["service_role_key"]
    supa.ANON_KEY = sec.get("anon_key") or sec["service_role_key"]
    token = supa.SERVICE_ROLE_KEY

    acls = DropboxClient(DropboxAuth()).folder_acls("")
    print(f"{len(acls)} shared folders in Dropbox ACLs")

    # relpath_lower -> folder node id over the migrated tree
    folder_nodes: dict[str, str] = {}

    def walk(node_id: str, relpath: str) -> None:
        for n in supa.children(token, node_id):
            if n["type"] == "folder":
                rel = f"{relpath}/{n['name']}".strip("/").lower()
                folder_nodes[rel] = n["id"]
                walk(n["id"], rel)

    walk(MIGRATION_ROOT, "")
    print(f"{len(folder_nodes)} folders in the migrated tree")

    resolved: dict[str, str | None] = {}
    inserted = skipped_external = missing = 0
    for path, emails in sorted(acls.items()):
        node_id = folder_nodes.get(path)
        if not node_id:
            missing += 1
            print(f"  (not migrated) {path}")
            continue
        for em in sorted(emails - OWNER_EMAILS):
            if em not in resolved:
                prof = supa.profile_by_email(token, em)
                resolved[em] = prof["id"] if prof else None
            uid = resolved[em]
            if not uid or uid == MIGRATION_OWNER:
                skipped_external += 1
                continue
            print(f"  share {path!r} -> {em}")
            if not DRY:
                supa.insert_share(token, node_id, uid, None)
            inserted += 1

    # Clean the self-stubs to the owner's alt email.
    stubs = supa.pending_shares_for_email(token, "mark.turner@reallyme.me")
    for p in stubs:
        print(f"  drop self-stub {p['id']} (node {p['node_id']})")
        if not DRY:
            supa.delete_pending_share(token, p["id"])

    print(f"\n{'DRY RUN — ' if DRY else ''}share rows upserted: {inserted}, "
          f"external/owner skipped: {skipped_external}, "
          f"acl folders not in tree: {missing}, self-stubs dropped: {len(stubs)}")


if __name__ == "__main__":
    main()
