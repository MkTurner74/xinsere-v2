"""Deploy a per-tenant XinserePermissions contract for one organization.

This is the "factory" action: it deploys a FRESH XinserePermissions instance from
the platform signer wallet (so the signer is its admin, exactly like the shared
contract), waits for the receipt, and records the new address on the org row
(organizations.contract_address). After that, with XINSERE_PER_TENANT_CONTRACTS=true,
all of that org's grant/verify/revoke traffic targets its OWN contract — no longer
co-mingled on the shared public page (security audit finding 14).

⚠️ SPENDS GAS and is IRREVERSIBLE on-chain. Run deliberately with a funded signer.
Dry-run by default; pass --confirm to actually deploy.

Usage:
    python scripts/deploy_org_contract.py --env .env.local --slug samsyn            # dry-run
    python scripts/deploy_org_contract.py --env .env.local --slug samsyn --confirm  # deploy + record

Reads the signer via the same path as the app (chain._load_key: XINSERE_PRIVATE_KEY
or the AWS secret). Recording the address needs the Supabase service-role env.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
sys.path.insert(0, str(ROOT / "lambdas" / "pipeline"))

DEPLOY_GAS = int(os.environ.get("XINSERE_DEPLOY_GAS_LIMIT", "2000000"))


def load_env(path: str) -> None:
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"'))


def _bytecode() -> str:
    bin_path = ROOT / "contracts" / "XinserePermissions_sol_XinserePermissions.bin"
    code = bin_path.read_text(encoding="utf-8").strip()
    return code if code.startswith("0x") else "0x" + code


def main() -> int:
    ap = argparse.ArgumentParser(description="Deploy a per-org XinserePermissions contract.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--slug", help="Organization slug to deploy for (e.g. samsyn)")
    g.add_argument("--org-id", help="Organization id (uuid)")
    ap.add_argument("--env", help="Optional .env file to load first")
    ap.add_argument("--confirm", action="store_true", help="Actually deploy (default: dry-run)")
    ap.add_argument("--no-record", action="store_true", help="Deploy but do NOT write the address to the org row")
    args = ap.parse_args()

    if args.env:
        load_env(args.env)

    import chain
    import orgs
    from web3 import Web3

    org = orgs.get_org_by_slug(args.slug) if args.slug else orgs.get_org(args.org_id)
    if not org:
        print("✗ organization not found", file=sys.stderr)
        return 2
    if org.get("contract_address"):
        print(f"✗ org '{org['slug']}' already has a contract: {org['contract_address']} — refusing to redeploy",
              file=sys.stderr)
        return 2

    w3 = Web3(Web3.HTTPProvider(chain.RPC_URL))
    if not w3.is_connected():
        print(f"✗ cannot reach RPC {chain.RPC_URL}", file=sys.stderr)
        return 3
    acct = w3.eth.account.from_key(chain._load_key())
    print(f"org        {org['slug']}  ({org['id']})")
    print(f"signer     {acct.address}")
    print(f"rpc        {chain.RPC_URL}  chainId {chain.CHAIN_ID}")
    print(f"gas        {DEPLOY_GAS} @ maxFee {chain.MAXFEE_GWEI} gwei "
          f"(~{DEPLOY_GAS * chain.MAXFEE_GWEI / 1e9:.4f} POL ceiling)")

    if not args.confirm:
        print("\nDRY-RUN — pass --confirm to deploy. Nothing sent.")
        return 0

    bal = w3.eth.get_balance(acct.address)
    need = DEPLOY_GAS * w3.to_wei(chain.MAXFEE_GWEI, "gwei")
    if bal < need:
        print(f"✗ signer balance {w3.from_wei(bal,'ether')} POL < ~{w3.from_wei(need,'ether')} POL needed",
              file=sys.stderr)
        return 4

    contract = w3.eth.contract(abi=chain.ABI, bytecode=_bytecode())
    tx = contract.constructor().build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": chain.CHAIN_ID,
        "maxPriorityFeePerGas": w3.to_wei(chain.PRIORITY_GWEI, "gwei"),
        "maxFeePerGas": w3.to_wei(chain.MAXFEE_GWEI, "gwei"),
        "gas": DEPLOY_GAS,
    })
    signed = w3.eth.account.sign_transaction(tx, acct.key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    print(f"\ndeploy tx  {h.hex() if not h.hex().startswith('0x') else h.hex()} — waiting for receipt…")
    receipt = w3.eth.wait_for_transaction_receipt(h, timeout=300)
    if getattr(receipt, "status", 0) != 1:
        print("✗ deploy reverted on-chain", file=sys.stderr)
        return 5
    addr = receipt.contractAddress
    print(f"✓ deployed  {addr}  (block {receipt.blockNumber})")

    if args.no_record:
        print("(--no-record) NOT writing to the org row. Set it manually:")
        print(f"    organizations.contract_address = {addr}  where id = {org['id']}")
        return 0
    orgs.set_org_contract(org["id"], addr)
    print(f"✓ recorded on org '{org['slug']}'. With XINSERE_PER_TENANT_CONTRACTS=true, "
          f"its grants now use {addr}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
