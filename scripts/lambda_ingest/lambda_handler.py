"""Lambda handler for the Dropbox-ingest connector -- Lambda compute-tier
comparison (Cloud-Performance-Test-Matrix, 2026-07-26).

Runs the SAME connector code as Fargate/EC2 (dropbox_connector.py,
MigrationRunner.run()). This does NOT go through Lambda's interactive HTTP
response-streaming path (the thing with the documented 6MB/2MB-per-second
ceiling from the 2026-07-24 research) -- it's invoked directly, does its work,
and returns a small JSON report, same shape as Fargate's stdout "RESULT" line
and EC2's Supabase migration_runs heartbeat. So this specifically tests
Lambda's compute/network/KMS characteristics for the ingest workload, not its
suitability as a file-serving endpoint (a separate, already-answered question).

Config is env-driven, same variable names as fargate_entrypoint.py, so the
exact same test harness/sample-file logic works across all three compute
tiers unchanged:
  XINSERE_BACKEND, AWS_REGION, XINSERE_S3_BUCKETS, XINSERE_MIGRATION_FOLDER,
  XINSERE_MIGRATION_OWNER, XINSERE_MIGRATION_ACTOR, XINSERE_MIGRATION_ROOT,
  XINSERE_MIGRATION_WORKERS, XINSERE_MIGRATION_INCLUDE_TOP,
  XINSERE_MIGRATION_LIMIT, XINSERE_MIGRATION_SAMPLE_FILE (a s3:// URI or a
  /tmp-local path already present in the image/layer).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, "/var/lambdas/pipeline")


def _load_supabase() -> None:
    import boto3
    region = os.environ.get("AWS_REGION", "us-east-1")
    sm = boto3.client("secretsmanager", region_name=region)
    s = json.loads(sm.get_secret_value(SecretId="xinsere/supabase/service-role")["SecretString"])
    os.environ["SUPABASE_URL"] = s["url"]
    os.environ["SUPABASE_SERVICE_ROLE_KEY"] = s["service_role_key"]
    os.environ["XINSERE_SUPABASE_SERVICE_KEY"] = s["service_role_key"]
    os.environ["SUPABASE_ANON_KEY"] = s.get("anon_key") or s["service_role_key"]


def _resolve_sample_file() -> str | None:
    """XINSERE_MIGRATION_SAMPLE_FILE may be an s3:// URI (uploaded by the launch
    script, mirroring the EC2 path) -- Lambda has no persistent volume, so pull
    it into /tmp (up to 10GB ephemeral storage per invocation) first."""
    env = os.environ.get("XINSERE_MIGRATION_SAMPLE_FILE", "")
    if not env:
        return None
    if env.startswith("s3://"):
        import boto3
        bucket, key = env[5:].split("/", 1)
        local = "/tmp/sample.json"
        boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1")).download_file(
            bucket, key, local)
        return local
    return env


def handler(event, context):
    _load_supabase()
    from dropbox_connector import DropboxAuth, DropboxClient, MigrationRunner, load_sample

    folder = os.environ.get("XINSERE_MIGRATION_FOLDER", "")
    workers = int(os.environ.get("XINSERE_MIGRATION_WORKERS", "4"))
    include_top = {s.strip() for s in
                   os.environ.get("XINSERE_MIGRATION_INCLUDE_TOP", "").split(",") if s.strip()}
    limit_env = os.environ.get("XINSERE_MIGRATION_LIMIT", "")
    limit = int(limit_env) if limit_env else None
    sample_path = _resolve_sample_file()
    sample_paths = load_sample(sample_path) if sample_path else None

    print(f">>> lambda ingest folder={folder!r} workers={workers} "
          f"include_top={sorted(include_top) or 'none'} limit={limit or 'unbounded'} "
          f"sample_file={sample_path or 'none'}"
          f"{f' ({len(sample_paths)} files)' if sample_paths is not None else ''}", flush=True)

    runner = MigrationRunner(DropboxClient(DropboxAuth()), include_top=include_top)
    rep = runner.run(folder, limit=limit, full=True, workers=workers, sample_paths=sample_paths)
    result = rep.as_dict(rep.sourced, 0)
    print("RESULT " + json.dumps(result), flush=True)
    return result
