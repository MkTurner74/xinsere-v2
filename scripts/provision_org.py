"""Provision an organization + API key from the command line.

Runs the exact same code path as the /admin console (demo/orgs.py), so the org
gets its service identity + root folder and the key is hash-only stored. Use
when seeding a client org (e.g. Samsyn) without a browser session.

Usage:
    python scripts/provision_org.py --env .env.seed-tmp "Samsyn" samsyn-production

Prints the org's party_id and the PLAINTEXT KEY ONCE — copy it immediately.
Idempotent on the org (reuses an existing slug); always mints a fresh key.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))


def load_env(path: str) -> None:
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"'))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", help="dotenv file with SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY")
    ap.add_argument("org_name")
    ap.add_argument("key_name")
    ap.add_argument("--created-by", default="provision_org.py")
    args = ap.parse_args()

    if args.env:
        load_env(args.env)

    import orgs  # noqa: E402  (needs env loaded first)

    slug = orgs.slugify(args.org_name)
    org = orgs.get_org_by_slug(slug)
    if org:
        print(f"org exists: {org['name']} (slug={slug})")
    else:
        org = orgs.create_org(args.org_name, args.created_by)
        print(f"org created: {org['name']} (slug={slug})")
    print(f"org_id:   {org['id']}")
    print(f"party_id: {org['service_user']}")

    key, row = orgs.mint_key(org["id"], args.key_name, args.created_by)
    print(f"key '{args.key_name}' minted (id={row['id']}, prefix={row['prefix']})")
    print("PLAINTEXT KEY (shown once, never stored):")
    print(key)


if __name__ == "__main__":
    main()
