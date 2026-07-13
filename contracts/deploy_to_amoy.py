#!/usr/bin/env python3
"""Deploy XinserePermissions to Polygon Amoy and PROVE the batch-grant path live.

Deploys a fresh contract instance (does NOT touch the live app's current contract),
then runs a real on-chain roundtrip that proves the off-chain merkle.py agrees with
the deployed Solidity verifyBatch byte-for-byte:

  grantBatch(root) -> verifyBatch(real leaf) == True
                   -> verifyBatch(forged leaf) == False
                   -> verifyBatch(leaf, UNANCHORED root) == False  (fail-closed)

Signer = the admin key in Secrets Manager (same key chain.py uses), so grantBatch's
onlyAdmin passes. Prints the new address for the cutover step.

Usage:  python deploy_to_amoy.py
"""
import json
import os
import sys

from web3 import Web3

# Reuse the demo's chain module for the key loader + RPC/chain-id constants.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo"))
import chain as _chain  # noqa: E402
import merkle  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_artifacts():
    with open(os.path.join(HERE, "bytecode.txt")) as f:
        bytecode = f.read().strip()
    with open(os.path.join(HERE, "abi.json")) as f:
        abi = json.load(f)
    return bytecode, abi


def deploy(w3: Web3, acct, bytecode: str, abi: list) -> str:
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = Contract.constructor().build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": _chain.CHAIN_ID,
        "maxPriorityFeePerGas": w3.to_wei(_chain.PRIORITY_GWEI, "gwei"),
        "maxFeePerGas": w3.to_wei(_chain.MAXFEE_GWEI, "gwei"),
        # Runtime bytecode is ~7.7 KB -> code-deposit alone is ~1.54M gas; 1.5M
        # reverted out-of-gas. 2.2M is safe headroom (a limit only caps: unused gas
        # is refunded, so an ample limit costs nothing extra).
        "gas": 2_200_000,
    })
    signed = w3.eth.account.sign_transaction(tx, acct.key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    print(f"deploy tx: {h.hex()}  (waiting for receipt...)", flush=True)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=300)
    if rc.status != 1:
        raise SystemExit(f"deploy reverted: {h.hex()}")
    return Web3.to_checksum_address(rc.contractAddress)


def prove(address: str):
    """Live on/off-chain agreement proof against the freshly deployed contract."""
    os.environ["XINSERE_CONTRACT_ADDRESS"] = address
    # Fresh Chain bound to the new address (chain.CHAIN cached the old CONTRACT const).
    c = _chain.Chain()
    c._ensure()  # noqa: SLF001 — internal init is fine in this admin script
    # Rebind the cached contract object to the new address explicitly.
    from web3 import Web3 as _W3
    c._contract = c._w3.eth.contract(address=_W3.to_checksum_address(address), abi=_chain.ABI)

    # Build a small real tree (7 leaves — odd, exercises duplicate path).
    leaves = [merkle.leaf(_chain.file_hash(f"f{i}"), _chain.grantee_hash(f"u{i%3}"))
              for i in range(7)]
    root = merkle.root(leaves)
    print(f"\nanchoring root {merkle.hx(root)} (7 leaves)...", flush=True)
    tx = c.grant_batch(root, len(leaves))
    print(f"grantBatch tx: {tx}", flush=True)

    ok = c.verify_batch(leaves[3], root, merkle.proof(leaves, 3))
    forged = c.verify_batch(merkle.leaf(bytes(32), bytes(32)), root, merkle.proof(leaves, 3))
    unanchored = c.verify_batch(leaves[0], merkle.root(leaves[:3]), merkle.proof(leaves[:3], 0))
    anchored_ts = c.root_anchored(root)

    print("\n--- LIVE ON-CHAIN PROOF ---")
    print(f"  real leaf verifies       : {ok}          (expect True)")
    print(f"  forged leaf verifies     : {forged}          (expect False)")
    print(f"  unanchored root verifies : {unanchored}          (expect False)")
    print(f"  root anchored timestamp  : {anchored_ts}   (expect >0)")
    all_ok = ok and (not forged) and (not unanchored) and anchored_ts > 0
    print(f"  RESULT                   : {'PASS' if all_ok else 'FAIL'}")
    return all_ok


def main():
    bytecode, abi = _load_artifacts()
    w3 = Web3(Web3.HTTPProvider(_chain.RPC_URL))
    acct = w3.eth.account.from_key(_chain._load_key())  # noqa: SLF001
    bal = w3.from_wei(w3.eth.get_balance(acct.address), "ether")
    print(f"deployer: {acct.address}  balance: {bal} POL  chain: {_chain.CHAIN_ID}")
    if bal < 0.08:
        raise SystemExit("balance too low for deploy + proof (need ~0.08 POL)")

    address = deploy(w3, acct, bytecode, abi)
    print(f"\n[OK] XinserePermissions deployed at: {address}")
    passed = prove(address)
    print("\n" + "=" * 60)
    print(f"NEW CONTRACT: {address}")
    print(f"PROOF: {'PASS' if passed else 'FAIL'}")
    print("=" * 60)
    print("\nCutover (when ready): set XINSERE_CONTRACT_ADDRESS to the above in the")
    print("app env + lambdas/blockchain/src/config.ts, apply migration 0007.")


if __name__ == "__main__":
    main()
