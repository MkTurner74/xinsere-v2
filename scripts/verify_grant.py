"""Automated on-chain grant test — verify a grant actually landed on the chain.

Read-only: reads the contract's verify() and (optionally) a transaction receipt.
Spends NO gas and does NOT load the signer private key — it recomputes the same
hashes the app uses (chain.file_hash / chain.grantee_hash) and calls the public
view function. Use it to self-check that "the API returned a tx" really produced
an active, mined grant — not just a hopeful response.

Usage:
    python scripts/verify_grant.py --file-id <xinsere_file_id> --party-id <uuid> \
        [--tx 0x...] [--rpc https://...] [--env .env.local] [--expect deny]

Exit code 0 = as expected (grant active, and tx mined ok if --tx given); non-zero
otherwise — so it drops straight into a CI/smoke step.

Needs the SAME tenant salt the grant was written with (XINSERE_TENANT_SALT, or the
tenant secret via AWS creds) — otherwise the recomputed grantee hash won't match.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
sys.path.insert(0, str(ROOT / "lambdas" / "pipeline"))


def load_env(path: str) -> None:
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"'))


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a Xinsere grant on-chain (read-only).")
    ap.add_argument("--file-id", required=True, help="Xinsere pipeline file_id (the on-chain fileHash preimage)")
    ap.add_argument("--party-id", required=True, help="Grantee profile uuid / party_id")
    ap.add_argument("--tx", help="Optional grant tx hash to confirm it mined with status 1")
    ap.add_argument("--rpc", help="Override RPC URL (default: XINSERE_RPC_URL / chain default)")
    ap.add_argument("--env", help="Optional .env file to load first (for salt/RPC)")
    ap.add_argument("--expect", choices=["allow", "deny"], default="allow",
                    help="Expected state (default allow) — controls the exit code")
    args = ap.parse_args()

    if args.env:
        load_env(args.env)

    import chain  # noqa: E402  (after path + env setup)
    from web3 import Web3

    rpc = args.rpc or chain.RPC_URL
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        print(f"✗ cannot reach RPC {rpc}", file=sys.stderr)
        return 3
    contract = w3.eth.contract(address=Web3.to_checksum_address(chain.CONTRACT), abi=chain.ABI)

    # Recompute the exact hashes the app writes, then read the public view fn.
    fh = chain.file_hash(args.file_id)
    gh = chain.grantee_hash(args.party_id)
    allowed, granted_at = contract.functions.verify(fh, gh).call()
    allowed = bool(allowed)

    print(f"contract      {chain.CONTRACT}")
    print(f"rpc           {rpc}")
    print(f"file_id       {args.file_id}")
    print(f"party_id      {args.party_id}")
    print(f"on-chain      {'ALLOWED' if allowed else 'DENIED'}"
          + (f'  (granted_at {granted_at})' if granted_at else ''))

    ok = allowed if args.expect == "allow" else not allowed

    if args.tx:
        try:
            r = w3.eth.get_transaction_receipt(args.tx)
            status = getattr(r, "status", None)
            print(f"tx {args.tx}  block {r.blockNumber}  status {status}")
            if status != 1:
                print("✗ tx did not succeed on-chain (status != 1)", file=sys.stderr)
                ok = False
        except Exception as exc:
            print(f"✗ could not read tx receipt: {exc}", file=sys.stderr)
            ok = False

    print("RESULT:", "PASS ✓" if ok else "FAIL ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
