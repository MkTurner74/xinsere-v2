"""Spin up a dedicated EC2 instance to run the Xinsere Dropbox-ingest connector,
as a compute-tier comparison against today's Fargate task (Cloud-Performance-
Test-Matrix / Dropbox-Ingest-Test-Program, 2026-07-24).

Reuses the EXACT SAME container image already built for Fargate
(Dockerfile.migrate / ECR repo xinsere-migrate) -- this is a pure infrastructure
comparison, no application code differs between configs.

Two explicit, separately-run actions (nothing happens by accident):

    python launch.py --setup-iam
        Idempotent: creates the xinsere-dev-ec2-ingest-role (if missing) with the
        same S3/KMS/DynamoDB/Secrets permissions the Fargate task role has, plus
        ECR pull and SSM (for shell access with no SSH key / open port needed).
        Safe to re-run.

    python launch.py --instance-type c7g.4xlarge [--sample-file sample.json]
        [--workers 48] [--auto-terminate] [--launch]
        Without --launch: prints the full plan (AMI, rendered user-data, cost
        estimate) and does nothing else. Pass --launch to actually call
        run_instances. Real EC2 spend starts only with --launch.

Requires the AWS CLI credentials already configured in this environment
(account 058264449111, region us-east-1 -- matches today's Fargate task).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import uuid

import boto3

REGION = "us-east-1"
ACCOUNT_ID = "058264449111"
VPC_ID = "vpc-0cd11975c13668b92"
SUBNET_ID = "subnet-039563fc23b21805a"          # us-east-1a
SECURITY_GROUP_ID = "sg-0d4db637febc049b1"       # default SG, outbound-only needed
ROLE_NAME = "xinsere-dev-ec2-ingest-role"
INSTANCE_PROFILE_NAME = "xinsere-dev-ec2-ingest-profile"
IMAGE_URI = f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/xinsere-migrate:latest"
STAGING_BUCKET = "xinsere-dev-staging"

# Mirrors the live Fargate task definition (xinsere-migrate:1), inspected
# 2026-07-24 -- same buckets/owner/actor/root so results are comparable and land
# in the same place a Fargate run would.
S3_BUCKETS = ("xinsere-dev-frag-cac1-01,xinsere-dev-frag-cac1-02,xinsere-dev-frag-cac1-03,"
             "xinsere-dev-frag-cac1-04,xinsere-dev-frag-cac1-05,xinsere-dev-frag-cac1-06,"
             "xinsere-dev-frag-cac1-07")
MIGRATION_OWNER = "98b3cf84-88fa-4a35-9ee3-70ced1ba3c32"
MIGRATION_ACTOR = MIGRATION_OWNER
MIGRATION_ROOT = "fld_11c55461f5b6"
OWNER_EMAILS = "mark.turner@xinsere.com,mark.turner@entertainmenttechnologists.com"

_HERE = os.path.dirname(os.path.abspath(__file__))

# Candidate machine types for the "dedicated multi-core box instead of Lambda/
# Fargate" comparison. Pricing is REAL on-demand us-east-1 Linux, queried via
# `aws pricing get-products` on 2026-07-24 -- re-check before relying on it much
# later. c7g/c7i are compute+network-optimized (no local NVMe); i4i adds local
# NVMe instance-store if the gateway-caching angle (not just ingest) matters.
INSTANCE_CATALOG = {
    "c7g.4xlarge":  {"arch": "arm64",  "vcpu": 16, "mem_gib": 32,  "network": "up to 15 Gbps", "hourly_usd": 0.580, "nvme": None},
    "c7g.8xlarge":  {"arch": "arm64",  "vcpu": 32, "mem_gib": 64,  "network": "15 Gbps",        "hourly_usd": 1.160, "nvme": None},
    "c7i.4xlarge":  {"arch": "x86_64", "vcpu": 16, "mem_gib": 32,  "network": "up to 12.5 Gbps","hourly_usd": 0.714, "nvme": None},
    "c7i.8xlarge":  {"arch": "x86_64", "vcpu": 32, "mem_gib": 64,  "network": "12.5 Gbps",       "hourly_usd": 1.428, "nvme": None},
    "i4i.4xlarge":  {"arch": "x86_64", "vcpu": 16, "mem_gib": 128, "network": "up to 25 Gbps",   "hourly_usd": 1.373, "nvme": "1x 3,750 GB NVMe"},
}


def ensure_iam_role() -> str:
    """Create the EC2 ingest role + instance profile if they don't exist yet.
    Idempotent -- safe to re-run. Returns the instance profile name."""
    iam = boto3.client("iam", region_name=REGION)
    with open(os.path.join(_HERE, "iam_trust_policy.json")) as f:
        trust = f.read()
    with open(os.path.join(_HERE, "iam_inline_policy.json")) as f:
        inline = f.read()

    try:
        iam.create_role(RoleName=ROLE_NAME, AssumeRolePolicyDocument=trust,
                        Description="EC2 compute-tier comparison for the Xinsere Dropbox "
                                   "ingest connector -- mirrors xinsere-dev-fargate-task-role")
        print(f"created role {ROLE_NAME}")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"role {ROLE_NAME} already exists (ok)")

    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName="XinsereEc2IngestAccess",
                        PolicyDocument=inline)
    iam.attach_role_policy(RoleName=ROLE_NAME,
                           PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    print("inline policy + SSM managed policy attached (idempotent)")

    try:
        iam.create_instance_profile(InstanceProfileName=INSTANCE_PROFILE_NAME)
        iam.add_role_to_instance_profile(InstanceProfileName=INSTANCE_PROFILE_NAME,
                                         RoleName=ROLE_NAME)
        print(f"created instance profile {INSTANCE_PROFILE_NAME}")
        print("waiting ~10s for IAM propagation before the profile is usable...")
        time.sleep(10)
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"instance profile {INSTANCE_PROFILE_NAME} already exists (ok)")

    return INSTANCE_PROFILE_NAME


def resolve_ami(arch: str) -> tuple[str, str]:
    """Latest Amazon Linux 2023 AMI for the given arch (x86_64|arm64), resolved
    live via describe-images rather than a hard-coded id that goes stale."""
    ec2 = boto3.client("ec2", region_name=REGION)
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[{"Name": "name", "Values": [f"al2023-ami-2023.*-{arch}"]},
                 {"Name": "state", "Values": ["available"]}])
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"])
    if not images:
        raise RuntimeError(f"no AL2023 AMI found for arch={arch}")
    latest = images[-1]
    return latest["ImageId"], latest["Name"]


def upload_sample(local_path: str) -> str:
    """Push a --sample-out manifest to the staging bucket so the instance (which
    only has S3/KMS/DynamoDB/Secrets/ECR access, not local-filesystem access to
    this machine) can pull it down during boot. Returns the s3:// URI."""
    s3 = boto3.client("s3", region_name=REGION)
    key = f"ec2-ingest-samples/{uuid.uuid4().hex}.json"
    s3.upload_file(local_path, STAGING_BUCKET, key)
    return f"s3://{STAGING_BUCKET}/{key}"


def render_user_data(*, workers: int, folder: str, include_top: str,
                     sample_s3_uri: str | None, auto_terminate: bool) -> str:
    with open(os.path.join(_HERE, "user_data.sh.tmpl")) as f:
        tmpl = f.read()
    if sample_s3_uri:
        sample_fetch = f"aws s3 cp {sample_s3_uri} /data/sample.json"
        sample_container_path = "/data/sample.json"
    else:
        sample_fetch = "# no --sample-file given -- full folder, not a calibration replay"
        sample_container_path = ""
    shutdown_line = ("shutdown -h now   # --auto-terminate: instance terminates when the job ends"
                     if auto_terminate else
                     "echo '>>> job done -- instance left running (no --auto-terminate); "
                     "terminate it manually when you are done comparing.'")
    return tmpl.format(
        aws_region=REGION, account_id=ACCOUNT_ID, s3_buckets=S3_BUCKETS,
        workers=workers, migration_folder=folder, migration_owner=MIGRATION_OWNER,
        migration_actor=MIGRATION_ACTOR, migration_root=MIGRATION_ROOT,
        owner_emails=OWNER_EMAILS, include_top=include_top,
        sample_file_fetch=sample_fetch, sample_file_container_path=sample_container_path,
        image_uri=IMAGE_URI, shutdown_line=shutdown_line,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setup-iam", action="store_true",
                    help="Create/update the EC2 ingest IAM role + instance profile, then exit.")
    ap.add_argument("--instance-type", choices=sorted(INSTANCE_CATALOG),
                    help="Which candidate machine type to launch.")
    ap.add_argument("--folder", default="", help="Team-root Dropbox path (default: whole tree)")
    ap.add_argument("--include-top", default="",
                    help='Comma-separated EXCLUDE_TOP override, e.g. "Mark Turner"')
    ap.add_argument("--workers", type=int, default=32,
                    help="XINSERE_MIGRATION_WORKERS -- push well past Fargate's 12 to see if "
                         "throughput scales with cores or hits an S3/KMS/DynamoDB ceiling first")
    ap.add_argument("--sample-file", default=None,
                    help="Local --sample-out manifest (from dropbox_connector.py "
                         "--sample-per-bucket) to replay on this instance for an "
                         "apples-to-apples comparison against other configs.")
    ap.add_argument("--auto-terminate", action="store_true",
                    help="Instance terminates itself when the ingest job exits -- use for "
                         "one-shot calibration runs so nothing is left running/billing.")
    ap.add_argument("--launch", action="store_true",
                    help="Actually call run_instances. Without this flag, only the plan "
                         "(AMI, user-data, cost estimate) is printed -- nothing is created.")
    args = ap.parse_args()

    if args.setup_iam:
        ensure_iam_role()
        return

    if not args.instance_type:
        ap.error("--instance-type is required (or use --setup-iam alone)")

    spec = INSTANCE_CATALOG[args.instance_type]
    ami_id, ami_name = resolve_ami(spec["arch"])
    sample_s3_uri = upload_sample(args.sample_file) if args.sample_file else None
    user_data = render_user_data(workers=args.workers, folder=args.folder,
                                 include_top=args.include_top, sample_s3_uri=sample_s3_uri,
                                 auto_terminate=args.auto_terminate)

    print("=" * 70)
    print(f"PLAN  instance_type={args.instance_type}  arch={spec['arch']}  "
          f"vcpu={spec['vcpu']}  mem={spec['mem_gib']}GiB  network={spec['network']}  "
          f"nvme={spec['nvme'] or 'none'}")
    print(f"      on-demand: ${spec['hourly_usd']:.3f}/hr (us-east-1, queried 2026-07-24 -- "
          f"re-check aws pricing before relying on this much later)")
    print(f"      AMI: {ami_id} ({ami_name})")
    print(f"      region={REGION} subnet={SUBNET_ID} sg={SECURITY_GROUP_ID}")
    if sample_s3_uri:
        print(f"      sample uploaded to {sample_s3_uri}")
    print("-" * 70)
    print(user_data)
    print("=" * 70)

    if not args.launch:
        print("(dry run -- no instance created. Re-run with --launch to actually spend money.)")
        return

    ec2 = boto3.client("ec2", region_name=REGION)
    resp = ec2.run_instances(
        ImageId=ami_id, InstanceType=args.instance_type, MinCount=1, MaxCount=1,
        SubnetId=SUBNET_ID, SecurityGroupIds=[SECURITY_GROUP_ID],
        IamInstanceProfile={"Name": INSTANCE_PROFILE_NAME},
        UserData=base64.b64encode(user_data.encode()).decode(),
        InstanceInitiatedShutdownBehavior="terminate" if args.auto_terminate else "stop",
        MetadataOptions={"HttpTokens": "required", "HttpPutResponseHopLimit": 2},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [
            {"Key": "Name", "Value": f"xinsere-ingest-test-{args.instance_type}"},
            {"Key": "Purpose", "Value": "cloud-performance-test-matrix-2026-07-24"},
        ]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    print(f"LAUNCHED {instance_id}")
    print(f"  progress: Admin > Imports dashboard (Supabase migration_runs), same as any Fargate run")
    print(f"  shell (no SSH key needed): aws ssm start-session --target {instance_id} --region {REGION}")
    print(f"  console log: aws ec2 get-console-output --instance-id {instance_id} --region {REGION}")
    print(f"  terminate when done: aws ec2 terminate-instances --instance-ids {instance_id} --region {REGION}")


if __name__ == "__main__":
    main()
