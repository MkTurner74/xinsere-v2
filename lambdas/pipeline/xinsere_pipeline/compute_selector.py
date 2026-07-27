"""Compute-tier recommendation for a migration job: given how many files, how
big, and how big the largest one is, recommend EC2 / Fargate / Lambda and
explain why -- not just "biggest file wins," but capability (can this tier
even hold the file today) crossed with cost (spin-up overhead dominates short
jobs, amortizes to nothing on long ones).

Derived from real measurements, 2026-07-24/26 (see
projects/Xinsere/Fragment-Count-Bucket-Diversity-Findings-2026-07-26.md and
Compute-Tier-And-1TB-Cost-Model-2026-07-26.md in the ai-brain docs repo):

- Serial per-stream throughput from inside AWS: 13.2 MB/s, real EC2 test
  against real Dropbox-sourced media files. Used to estimate job duration.
- Today's whole-file-in-memory pipeline needs roughly 2-4x a file's own size
  in RAM per file *actively being processed at once* -- proven via the serial
  (workers=1, safe even at 7.14GB) vs. 4-way-concurrent (OOM'd everywhere)
  tests. This bounds the largest file each tier can safely process, at a
  given memory allocation.
- Lambda: 10GB memory hard cap, 15-minute execution hard cap (whichever binds
  first -- for typical throughput, timeout is looser than memory below ~3GB
  files, so memory is usually the real ceiling).
- Fargate: no execution timeout, memory configurable up to 120GB/task -- we
  have only actually PROVEN the 16GB/4vCPU config (the live task def).
- EC2: whatever instance you pick -- we have only actually PROVEN 32GB
  (c7i.4xlarge, $0.714/hr us-east-1).

This evaluates those three PROVEN configurations, not a fully right-sized
optimizer -- recommending an untested smaller instance/task size would be
overclaiming confidence past what's actually been measured. Right-sizing
within a tier is a reasonable next step once more configs are validated.
"""
from __future__ import annotations

from dataclasses import dataclass

MB = 1024 * 1024
GB = 1024 * MB

# Real measurement, 2026-07-26 serial EC2 test.
DEFAULT_THROUGHPUT_MB_S = 13.2

# Today's whole-file-in-memory pipeline's RAM need per file-in-flight, as a
# multiple of that file's own size (see module docstring).
MEMORY_MULTIPLIER = 3.0

LAMBDA_TIMEOUT_S = 900  # 15 minutes, hard AWS ceiling

# Ballpark spin-up/cold-start overhead per tier -- estimates, not measured
# this session. Dominates short jobs; amortizes to noise on long ones, which
# is exactly the tradeoff the recommendation is meant to surface.
SPINUP_OVERHEAD_S = {"lambda": 5.0, "fargate": 45.0, "ec2": 105.0}

# us-east-1 on-demand list prices, 2026-07-26 (see Compute-Tier-And-1TB-Cost-
# Model-2026-07-26.md for citations).
FARGATE_VCPU_HR = 0.04048
FARGATE_GB_HR = 0.004445
LAMBDA_GB_S = 0.0000166667
EC2_C7I_4XLARGE_HR = 0.714  # 16 vCPU / 32GB, the tier we've actually tested


@dataclass
class JobProfile:
    total_bytes: int
    file_count: int
    max_file_bytes: int


@dataclass
class TierPlan:
    tier: str
    capable: bool
    reason: str
    memory_gb: float
    est_wall_s: float | None = None
    est_cost_usd: float | None = None


def _safe_max_file_bytes(memory_gb: float, *, timeout_s: float | None,
                          throughput_mb_s: float) -> float:
    """The largest single file this tier can safely process today, at this
    memory allocation -- whichever binds first, the memory ceiling or (for
    Lambda) the execution timeout at the given throughput."""
    memory_bound = memory_gb * GB / MEMORY_MULTIPLIER
    if timeout_s is None:
        return memory_bound
    timeout_bound = throughput_mb_s * MB * timeout_s
    return min(memory_bound, timeout_bound)


def evaluate(
    job: JobProfile, *,
    throughput_mb_s: float = DEFAULT_THROUGHPUT_MB_S,
    lambda_memory_gb: float = 10.0,
    fargate_memory_gb: float = 16.0,
    fargate_vcpu: float = 4.0,
    ec2_memory_gb: float = 32.0,
    ec2_hourly_rate: float = EC2_C7I_4XLARGE_HR,
) -> list[TierPlan]:
    """Evaluate all three tiers against a job profile. Returns every tier
    (capable or not) with its cost/time estimate, cheapest-capable first."""
    duration_s = job.total_bytes / (throughput_mb_s * MB)
    plans: list[TierPlan] = []

    tiers = (
        ("lambda", lambda_memory_gb, LAMBDA_TIMEOUT_S),
        ("fargate", fargate_memory_gb, None),
        ("ec2", ec2_memory_gb, None),
    )
    for tier, memory_gb, timeout_s in tiers:
        safe_max = _safe_max_file_bytes(
            memory_gb, timeout_s=timeout_s, throughput_mb_s=throughput_mb_s)
        capable = job.max_file_bytes <= safe_max
        timeout_bound = (timeout_s is not None
                          and safe_max == throughput_mb_s * MB * timeout_s)
        reason = (
            f"largest file {job.max_file_bytes / GB:.2f}GB "
            f"{'<=' if capable else '>'} safe max {safe_max / GB:.2f}GB "
            f"at {memory_gb:.0f}GB memory"
            + (f" (timeout-bound: {timeout_s:.0f}s @ {throughput_mb_s}MB/s)"
               if timeout_bound else "")
        )

        wall_s = duration_s + SPINUP_OVERHEAD_S[tier] if capable else None
        cost_usd = None
        if capable:
            if tier == "lambda":
                cost_usd = lambda_memory_gb * wall_s * LAMBDA_GB_S
            elif tier == "fargate":
                hourly = fargate_vcpu * FARGATE_VCPU_HR + fargate_memory_gb * FARGATE_GB_HR
                cost_usd = hourly * wall_s / 3600
            else:
                cost_usd = ec2_hourly_rate * wall_s / 3600

        plans.append(TierPlan(tier, capable, reason, memory_gb, wall_s, cost_usd))

    plans.sort(key=lambda p: (not p.capable,
                              p.est_cost_usd if p.est_cost_usd is not None else float("inf")))
    return plans


def recommend(job: JobProfile, **kwargs) -> TierPlan:
    """The single best capable tier for this job (cheapest, spin-up included).
    Raises if NO tier can safely handle the largest file today -- that's a
    real answer (the job needs the streaming rearchitecture, or splitting),
    not something to silently paper over."""
    plans = evaluate(job, **kwargs)
    capable = [p for p in plans if p.capable]
    if not capable:
        max_gb = job.max_file_bytes / GB
        raise ValueError(
            f"no tier can safely handle a {max_gb:.2f}GB file today under the "
            "whole-file-in-memory architecture -- needs the streaming "
            "rearchitecture (see Streaming-Rearchitecture-Proposal-2026-07-26.md) "
            "or splitting this file out of the batch"
        )
    return capable[0]
