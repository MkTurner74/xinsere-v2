# EC2 ingest compute comparison

Run the exact same Dropbox-ingest connector on a dedicated, multi-core EC2
instance instead of Fargate, to answer: does a bigger/dedicated box actually
move throughput, or does something else (S3, KMS, DynamoDB/Supabase) become
the ceiling first? Part of `Cloud-Performance-Test-Matrix-2026-07-24.md` /
`Dropbox-Ingest-Test-Program-2026-07-24.md` (ai-brain docs repo).

**No new application code runs here.** Same container image already built for
Fargate (`Dockerfile.migrate`, ECR repo `xinsere-migrate`) — only the host
changes. This is a pure infrastructure comparison.

## Today's baseline, for reference (inspected 2026-07-24)

The live `xinsere-migrate:1` ECS task definition: **4 vCPU / 16 GB memory**,
`XINSERE_MIGRATION_WORKERS=12`. Task role `xinsere-dev-fargate-task-role`
(trusts `ecs-tasks.amazonaws.com` only — can't be reused directly on EC2,
hence the separate role below). Fragment buckets are named with a `cac1`
segment → **ca-central-1** (bucket-region routing in `aws.py`), while the task
itself runs in **us-east-1** — today's baseline is *already* cross-region for
storage. Worth keeping that in mind when comparing numbers; it's not a new
variable this EC2 test introduces.

## Instance options (real on-demand pricing, us-east-1, queried 2026-07-24 — re-check before relying on this much later)

| Type | vCPU | Mem | Network | Local NVMe | $/hr | Use for |
|---|---:|---:|---|---|---:|---|
| `c7g.4xlarge` | 16 | 32 GiB | up to 15 Gbps | — | $0.580 | Default: ~4x today's Fargate task, Graviton |
| `c7g.8xlarge` | 32 | 64 GiB | 15 Gbps | — | $1.160 | "Go big" — does throughput keep scaling? |
| `c7i.4xlarge` | 16 | 32 GiB | up to 12.5 Gbps | — | $0.714 | x86_64 twin of c7g.4xlarge (architecture isolation) |
| `c7i.8xlarge` | 32 | 64 GiB | 12.5 Gbps | — | $1.428 | x86_64 twin of c7g.8xlarge |
| `i4i.4xlarge` | 16 | 128 GiB | up to 25 Gbps | 3,750 GB NVMe | $1.373 | If the NVMe/gateway-caching angle matters too, not just ingest |

A calibration run against the stratified sample (a few thousand files, tens of
GB) costs low single-digit dollars even on the 8xlarge tier — this is cheap to
try several configs. `--auto-terminate` means nothing is left running/billing
after the job exits.

**A dedicated box mainly buys core count and RAM headroom to push
`XINSERE_MIGRATION_WORKERS` well past Fargate's 12 (try 32–96)** — the
pipeline's per-fragment thread pool is I/O-bound (KMS + S3 both release the
GIL), so more concurrent *files* in flight is where a bigger machine could
help; a single file's own fragment fan-out is capped at ≤16 regardless of host
size. Whether that scaling actually materializes — or whether KMS rate
limits, DynamoDB/Supabase write throughput, or Dropbox's own API rate limits
become the ceiling first — is exactly the open question this test answers.
`i4i`'s local NVMe is NOT automatically exploited by this connector on the
write path (bytes are fetched, encrypted, and PUT to S3 in memory — no disk
staging step exists); it's included mainly because the *read-back* half of
the test program could use it as a warm-fragment cache tier later.

## One-time setup

```bash
cd scripts/ec2_ingest
python launch.py --setup-iam
```

Idempotent — creates `xinsere-dev-ec2-ingest-role` + instance profile with the
same S3/KMS/DynamoDB/Secrets permissions the Fargate task role has (copied
into `iam_inline_policy.json`, not shared with the ECS role — different trust
principal), plus ECR pull and `AmazonSSMManagedInstanceCore` (shell access via
`aws ssm start-session`, no SSH key or open port 22 needed). Safe to re-run.

## Running a calibration sample on one instance type

```bash
# 1. Build the stratified sample once (from the repo's demo/ directory):
python dropbox_connector.py --folder "/Mark Turner" --include-top "Mark Turner" \
  --enumerate-only --sample-per-bucket 200 --sample-out sample.json

# 2. Try it on a candidate instance (dry run first -- prints the plan, spends nothing):
cd ../scripts/ec2_ingest
python launch.py --instance-type c7g.4xlarge --workers 32 \
  --folder "/Mark Turner" --include-top "Mark Turner" \
  --sample-file ../../demo/sample.json --auto-terminate

# 3. Same command + --launch to actually spend money and create the instance:
python launch.py --instance-type c7g.4xlarge --workers 32 \
  --folder "/Mark Turner" --include-top "Mark Turner" \
  --sample-file ../../demo/sample.json --auto-terminate --launch
```

Repeat step 3 for each instance type in the catalog, same sample file each
time — that's what makes the comparison fair (identical files, only the host
changes). Progress lands in Supabase `migration_runs` (Admin → Imports
dashboard) exactly like a Fargate run — no separate monitoring needed.

**Windows / Git Bash gotcha:** a leading-slash argument like `--folder
"/Mark Turner"` gets silently mangled into a Windows path by Git Bash's
automatic POSIX-path conversion (MSYS). Prefix the command with
`MSYS_NO_PATHCONV=1`, or run from PowerShell instead, and double-check the
printed plan's `XINSERE_MIGRATION_FOLDER=` line reads `/Mark Turner`, not
`C:/Program Files/Git/Mark Turner`, before passing `--launch`.

## Checking on / cleaning up a running instance

```bash
aws ssm start-session --target <instance-id> --region us-east-1   # shell, no SSH key
aws ec2 get-console-output --instance-id <instance-id> --region us-east-1
aws ec2 terminate-instances --instance-ids <instance-id> --region us-east-1
```

Without `--auto-terminate`, the instance stops itself but isn't deleted
(EBS-only cost, near-zero) — terminate manually when you're done comparing.
