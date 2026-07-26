"""Deploy + invoke the Lambda batch-ingest compute-tier comparison test
(Cloud-Performance-Test-Matrix, 2026-07-26). Sibling of scripts/ec2_ingest/ --
same account guard, same env-var shape, same --sample-file replay mechanism,
different compute target.

Two explicit actions:

    python deploy_and_test.py --setup
        Idempotent: builds+pushes the Lambda container image (linux/amd64),
        creates the execution role (mirrors the EC2/Fargate role) + repo pull
        policy, creates/updates the Lambda function. Safe to re-run after any
        code change -- always rebuilds the image first.

    python deploy_and_test.py --invoke --root <node-id> [--sample-file ...] [--limit N] [--folder ...]
        Sets the function's environment for this run and invokes it
        synchronously (up to Lambda's 15-minute cap). Prints the JSON report.
        Refuses to run unbounded, same rule as the EC2 launcher.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid

import boto3

REGION = "us-east-1"
ACCOUNT_ID = "058264449111"
ROLE_NAME = "xinsere-dev-lambda-ingest-role"
FUNCTION_NAME = "xinsere-dev-ingest-test"
REPO_NAME = "xinsere-migrate"
IMAGE_TAG = "lambda-latest"
IMAGE_URI = f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/{REPO_NAME}:{IMAGE_TAG}"
STAGING_BUCKET = "xinsere-dev-staging"

S3_BUCKETS = ("xinsere-dev-frag-cac1-01,xinsere-dev-frag-cac1-02,xinsere-dev-frag-cac1-03,"
             "xinsere-dev-frag-cac1-04,xinsere-dev-frag-cac1-05,xinsere-dev-frag-cac1-06,"
             "xinsere-dev-frag-cac1-07")
MIGRATION_OWNER = "98b3cf84-88fa-4a35-9ee3-70ced1ba3c32"
MIGRATION_ACTOR = MIGRATION_OWNER

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))


def assert_correct_account() -> None:
    ident = boto3.client("sts", region_name=REGION).get_caller_identity()
    if ident["Account"] != ACCOUNT_ID:
        raise SystemExit(
            f"REFUSING TO PROCEED: active AWS credentials are account "
            f"{ident['Account']} ({ident['Arn']}), not the Xinsere dev account "
            f"{ACCOUNT_ID}. Pass --profile, or check for a shadowing "
            f"AWS_PROFILE/AWS_ACCESS_KEY_ID env var in this shell.")


def build_and_push_image() -> None:
    print(f"Building {IMAGE_URI} (linux/amd64) from {_REPO_ROOT} ...")
    subprocess.run(["aws", "ecr", "get-login-password", "--region", REGION], check=True,
                   stdout=subprocess.PIPE).stdout
    login = subprocess.run(["aws", "ecr", "get-login-password", "--region", REGION],
                           check=True, capture_output=True, text=True).stdout
    subprocess.run(["docker", "login", "--username", "AWS", "--password-stdin",
                    f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com"],
                   input=login, check=True, text=True)
    subprocess.run(["docker", "buildx", "build", "--platform", "linux/amd64",
                    "-f", os.path.join(_HERE, "Dockerfile"), "-t", IMAGE_URI,
                    "--push", _REPO_ROOT], check=True, cwd=_REPO_ROOT)
    print(f"Pushed {IMAGE_URI}")


def ensure_iam_role() -> str:
    assert_correct_account()
    iam = boto3.client("iam", region_name=REGION)
    with open(os.path.join(_HERE, "iam_trust_policy.json")) as f:
        trust = f.read()
    with open(os.path.join(_HERE, "iam_inline_policy.json")) as f:
        inline = f.read()
    try:
        iam.create_role(RoleName=ROLE_NAME, AssumeRolePolicyDocument=trust,
                        Description="Lambda compute-tier comparison for the Xinsere "
                                   "Dropbox ingest connector")
        print(f"created role {ROLE_NAME}")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"role {ROLE_NAME} already exists (ok)")
    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName="XinsereLambdaIngestAccess",
                        PolicyDocument=inline)
    iam.attach_role_policy(RoleName=ROLE_NAME,
                           PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    role_arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
    print("waiting ~10s for IAM propagation...")
    time.sleep(10)
    return role_arn


def ensure_repo_pull_policy() -> None:
    """Lambda's container-image support needs the ECR REPOSITORY to grant the
    Lambda service principal pull access -- separate from the function's own
    execution role, which never touches image pulling itself."""
    ecr = boto3.client("ecr", region_name=REGION)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "LambdaECRImageRetrievalPolicy",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            "Condition": {"StringLike": {
                "aws:sourceArn": f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{FUNCTION_NAME}"}},
        }],
    }
    ecr.set_repository_policy(repositoryName=REPO_NAME, policyText=json.dumps(policy))
    print("ECR repo pull policy set for the Lambda function")


def ensure_function(role_arn: str) -> None:
    lam = boto3.client("lambda", region_name=REGION)
    image_uri_digest = boto3.client("ecr", region_name=REGION).describe_images(
        repositoryName=REPO_NAME, imageIds=[{"imageTag": IMAGE_TAG}]
    )["imageDetails"][0]["imageDigest"]
    code = {"ImageUri": f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/{REPO_NAME}@{image_uri_digest}"}
    try:
        lam.create_function(
            FunctionName=FUNCTION_NAME, PackageType="Image", Code=code, Role=role_arn,
            Timeout=600, MemorySize=2048,
            Description="Compute-tier comparison: Dropbox ingest connector on Lambda "
                       "(Cloud-Performance-Test-Matrix, 2026-07-26)",
        )
        print(f"created function {FUNCTION_NAME}")
        print("waiting for function to become Active...")
        lam.get_waiter("function_active_v2").wait(FunctionName=FUNCTION_NAME)
    except lam.exceptions.ResourceConflictException:
        lam.update_function_code(FunctionName=FUNCTION_NAME, ImageUri=code["ImageUri"])
        print(f"updated function {FUNCTION_NAME} code")
        lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)


def upload_sample(local_path: str) -> str:
    s3 = boto3.client("s3", region_name=REGION)
    key = f"lambda-ingest-samples/{uuid.uuid4().hex}.json"
    s3.upload_file(local_path, STAGING_BUCKET, key)
    return f"s3://{STAGING_BUCKET}/{key}"


def invoke(*, root: str, folder: str, include_top: str, workers: int,
          limit: int | None, sample_file: str | None) -> dict:
    assert_correct_account()
    sample_s3_uri = upload_sample(sample_file) if sample_file else ""
    env = {
        "XINSERE_BACKEND": "aws", "AWS_REGION": REGION, "XINSERE_S3_BUCKETS": S3_BUCKETS,
        "XINSERE_MIGRATION_WORKERS": str(workers),
        "XINSERE_MIGRATION_LIMIT": str(limit) if limit is not None else "",
        "XINSERE_MIGRATION_FOLDER": folder, "XINSERE_MIGRATION_OWNER": MIGRATION_OWNER,
        "XINSERE_MIGRATION_ACTOR": MIGRATION_ACTOR, "XINSERE_MIGRATION_ROOT": root,
        "XINSERE_MIGRATION_INCLUDE_TOP": include_top,
        "XINSERE_MIGRATION_SAMPLE_FILE": sample_s3_uri,
    }
    lam = boto3.client("lambda", region_name=REGION)
    lam.update_function_configuration(FunctionName=FUNCTION_NAME, Environment={"Variables": env})
    lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)
    print(f"invoking {FUNCTION_NAME} (root={root}, sample={sample_s3_uri or 'none'}) ...")
    t0 = time.perf_counter()
    resp = lam.invoke(FunctionName=FUNCTION_NAME, InvocationType="RequestResponse",
                      Payload=b"{}")
    wall = time.perf_counter() - t0
    payload = json.loads(resp["Payload"].read())
    print(f"invoke round-trip (incl. any cold start): {wall:.1f}s")
    if resp.get("FunctionError"):
        print(f"FUNCTION ERROR: {resp['FunctionError']}\n{json.dumps(payload, indent=2)}")
    else:
        print(json.dumps(payload, indent=2))
    return payload


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setup", action="store_true",
                    help="Build+push the image, create/update role + function.")
    ap.add_argument("--invoke", action="store_true", help="Invoke the function.")
    ap.add_argument("--root", default=None, help="Xinsere destination folder node id (required for --invoke)")
    ap.add_argument("--folder", default="/Mark Turner")
    ap.add_argument("--include-top", default="Mark Turner")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--sample-file", default=None)
    ap.add_argument("--unbounded", action="store_true")
    args = ap.parse_args()

    if args.setup:
        assert_correct_account()
        build_and_push_image()
        role_arn = ensure_iam_role()
        ensure_function(role_arn)
        ensure_repo_pull_policy()
        return

    if args.invoke:
        if not args.root:
            ap.error("--root is required for --invoke")
        if args.limit is None and not args.sample_file and not args.unbounded:
            ap.error("refusing to run unbounded: pass --limit N, or --sample-file, or --unbounded")
        invoke(root=args.root, folder=args.folder, include_top=args.include_top,
              workers=args.workers, limit=args.limit, sample_file=args.sample_file)
        return

    ap.error("pass --setup or --invoke")


if __name__ == "__main__":
    main()
