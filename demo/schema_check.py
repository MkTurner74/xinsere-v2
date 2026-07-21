#!/usr/bin/env python3
"""Read-only schema probe: confirm migrations 0016 + 0020 (+0021) landed.

Selects each expected column with limit=1 via PostgREST — an unknown column
errors, an applied one returns 200. Credentials come from env, or (like the
backfill scripts) from the xinsere/supabase/service-role secret in AWS
Secrets Manager with the local AWS profile.

Run from demo/:  python schema_check.py
"""
import json
import os
import sys

if not os.environ.get("SUPABASE_URL") or not os.environ.get("SUPABASE_SERVICE_ROLE_KEY"):
    import boto3
    sec = json.loads(boto3.client("secretsmanager", region_name="us-east-1")
                     .get_secret_value(SecretId="xinsere/supabase/service-role")["SecretString"])
    os.environ["SUPABASE_URL"] = sec["url"]
    os.environ["SUPABASE_SERVICE_ROLE_KEY"] = sec["service_role_key"]
    os.environ["SUPABASE_ANON_KEY"] = sec.get("anon_key") or sec["service_role_key"]

import supa  # noqa: E402  (needs env set first)

CHECKS = [  # (migration, table, column)
    ("0016", "shares", "share_type"),
    ("0016", "pending_shares", "share_type"),
    ("0020", "shares", "not_before"),
    ("0020", "shares", "not_after"),
    ("0020", "permission_batches", "not_before"),
    ("0020", "permission_batches", "not_after"),
    ("0021", "pending_shares", "not_before"),
    ("0021", "pending_shares", "not_after"),
]

failed = []
for mig, table, col in CHECKS:
    try:
        supa._rest("GET", f"/{table}", supa.SERVICE_ROLE_KEY,
                   params={"select": col, "limit": 1})
        print(f"  OK      {mig}  {table}.{col}")
    except supa.SupabaseError as exc:
        print(f"  MISSING {mig}  {table}.{col}  ({exc})")
        failed.append((mig, table, col))

sys.exit(1 if failed else 0)
