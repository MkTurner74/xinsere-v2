"""Fargate entrypoint for the cloud-to-cloud Dropbox migration worker.

Runs the SAME connector as the CLI, but in-cloud (Dropbox -> this task -> S3), so the
bytes never transit anyone's laptop and throughput is real cloud bandwidth. Loads the
Supabase service key from Secrets Manager using the task role (Dropbox + KMS/tenant
secrets are read by the connector/pipeline the same way). All other config comes from
the task-definition environment.

Env (from task def): XINSERE_BACKEND=aws, XINSERE_S3_BUCKETS, AWS_REGION,
XINSERE_MIGRATION_OWNER, XINSERE_MIGRATION_ROOT, XINSERE_MIGRATION_ACTOR,
XINSERE_MIGRATION_FOLDER (default '' = whole non-personal team root, resume-skips done),
XINSERE_MIGRATION_WORKERS.
"""
import json
import os

import boto3


def _load_supabase() -> None:
    region = os.environ.get("AWS_REGION", "us-east-1")
    sm = boto3.client("secretsmanager", region_name=region)
    s = json.loads(sm.get_secret_value(SecretId="xinsere/supabase/service-role")["SecretString"])
    os.environ["SUPABASE_URL"] = s["url"]
    os.environ["SUPABASE_SERVICE_ROLE_KEY"] = s["service_role_key"]
    os.environ["XINSERE_SUPABASE_SERVICE_KEY"] = s["service_role_key"]
    # Do NOT alias the "anon" key to the service-role key (audit finding 11): that
    # silently makes the anon plane god-mode in this process. The gateway apikey
    # header just needs a VALID project key, and the anon key is public/safe — use
    # the REAL anon key (from the secret, else a task-def env). Only if neither is
    # available do we fall back to the service key, and we say so loudly.
    anon = s.get("anon_key") or os.environ.get("SUPABASE_ANON_KEY")
    if not anon:
        anon = s["service_role_key"]
        print("WARN: no anon key available — SUPABASE_ANON_KEY falls back to the "
              "service-role key. Add `anon_key` to the xinsere/supabase/service-role "
              "secret (or set SUPABASE_ANON_KEY in the task def) to remove this.", flush=True)
    os.environ["SUPABASE_ANON_KEY"] = anon


def main() -> None:
    _load_supabase()
    folder = os.environ.get("XINSERE_MIGRATION_FOLDER", "")
    workers = int(os.environ.get("XINSERE_MIGRATION_WORKERS", "16"))
    # Explicit, one-off opt-in to migrate a folder normally excluded as personal
    # content (EXCLUDE_TOP) -- e.g. XINSERE_MIGRATION_INCLUDE_TOP="Mark Turner".
    # Empty by default: the safety-by-default exclusion is untouched unless set.
    include_top = {s.strip() for s in
                   os.environ.get("XINSERE_MIGRATION_INCLUDE_TOP", "").split(",") if s.strip()}
    from dropbox_connector import MigrationRunner, DropboxClient, DropboxAuth, load_sample
    # Calibration-sample replay (2026-07-24, compute/storage comparison test
    # matrix): a path to a --sample-out manifest, mounted/copied into the
    # container, so this exact same host can be compared apples-to-apples
    # against every other compute config on the identical file set.
    sample_file = os.environ.get("XINSERE_MIGRATION_SAMPLE_FILE", "")
    sample_paths = load_sample(sample_file) if sample_file else None
    print(f">>> cloud-to-cloud migration folder={folder!r} workers={workers} "
          f"include_top={sorted(include_top) or 'none'} "
          f"sample_file={sample_file or 'none'}"
          f"{f' ({len(sample_paths)} files)' if sample_paths is not None else ''}", flush=True)
    runner = MigrationRunner(DropboxClient(DropboxAuth()), include_top=include_top)
    rep = runner.run(folder, limit=None, full=True, workers=workers, sample_paths=sample_paths)
    print("RESULT " + json.dumps(rep.as_dict(rep.sourced, 0)), flush=True)


if __name__ == "__main__":
    main()
