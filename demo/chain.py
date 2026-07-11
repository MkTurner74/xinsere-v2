"""Real on-chain permission layer for the demo.

Grants and verifies file permissions against the deployed XinserePermissions
contract on Polygon Amoy — the SAME contract the blockchain service uses. This is
what makes the demo's access control genuinely blockchain-backed rather than a
local table: download access is decided by an on-chain `verify()` call.

Hashing matches the Node service:
  fileHash    = SHA-256(file_id)
  granteeHash = HMAC-SHA256(grantee_id, tenant_salt)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading

# NOTE: boto3 and web3 are heavy imports (~0.5-1s combined at cold start). They are
# imported lazily inside the functions that need them so endpoints that never touch
# the chain (login, tree, upload) don't pay for them on a cold serverless boot.

RPC_URL = os.environ.get("XINSERE_RPC_URL", "https://rpc-amoy.polygon.technology")
CHAIN_ID = int(os.environ.get("XINSERE_CHAIN_ID", "80002"))
CONTRACT = os.environ.get("XINSERE_CONTRACT_ADDRESS", "0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD")
SECRET_ID = os.environ.get("XINSERE_SECRET_ID", "xinsere/blockchain/polygon-amoy/private-key")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
# Amoy priority-fee floor is ~25 gwei. A grant uses ~113k gas, so 200k is safe
# headroom. Lower defaults shrink the reserve check (gas_limit x maxFee) so a
# near-empty wallet can still transact: 200k x 30 gwei = 0.006 POL/grant vs the
# old 300k x 50 = 0.015. Env-overridable.
PRIORITY_GWEI = int(os.environ.get("XINSERE_PRIORITY_FEE_GWEI", "26"))
MAXFEE_GWEI = int(os.environ.get("XINSERE_MAX_FEE_GWEI", "30"))
GAS_LIMIT = int(os.environ.get("XINSERE_GAS_LIMIT", "200000"))

ABI = [
    {"inputs": [{"type": "bytes32"}, {"type": "bytes32"}, {"type": "string"}, {"type": "uint256"}],
     "name": "grantPermission", "outputs": [{"type": "bytes32"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"type": "bytes32"}, {"type": "bytes32"}], "name": "revokePermission",
     "outputs": [{"type": "bytes32"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"type": "bytes32"}, {"type": "bytes32"}], "name": "verify",
     "outputs": [{"name": "hasPermission", "type": "bool"}, {"name": "grantedAt", "type": "uint256"}],
     "stateMutability": "view", "type": "function"},
]


def file_hash(file_id: str) -> bytes:
    return hashlib.sha256(file_id.encode()).digest()


def _tenant_salt() -> str:
    """The HMAC salt for grantee hashing. Env override wins; otherwise the
    canonical value from the tenant secret (so grants verify cross-service).
    QC note: confirm the Node blockchain service encodes this salt the same way
    (UTF-8 string vs hex bytes) — a mismatch would break cross-service verify()."""
    env = os.environ.get("XINSERE_TENANT_SALT")
    if env:
        return env
    try:
        from xinsere_pipeline.tenant import load_tenant_config
        salt = load_tenant_config().get("hmac_party_id_salt")
        if salt:
            return salt
    except Exception:
        pass
    return "dev-tenant-salt-change-me"  # local-only fallback


def grantee_hash(grantee_id: str) -> bytes:
    return hmac.new(_tenant_salt().encode(), grantee_id.encode(), hashlib.sha256).digest()


def _load_key() -> str:
    env = os.environ.get("XINSERE_PRIVATE_KEY")
    if env:
        return env if env.startswith("0x") else "0x" + env
    import boto3
    raw = boto3.client("secretsmanager", region_name=AWS_REGION).get_secret_value(
        SecretId=SECRET_ID)["SecretString"]
    m = re.search(r"private_?key[\"\s:]+\s*\"?(0x)?([0-9a-fA-F]{64})", raw, re.I)
    if not m:
        raise RuntimeError("no private key in secret")
    return "0x" + m.group(2)


class Chain:
    """Lazy, thread-safe on-chain permission client."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._w3 = None
        self._contract = None          # the shared/default contract
        self._acct = None
        self._by_addr: dict[str, object] = {}   # per-tenant contract cache

    def _ensure(self):
        if self._contract is not None:
            return
        with self._lock:
            if self._contract is not None:
                return
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(RPC_URL))
            acct = w3.eth.account.from_key(_load_key())
            self._contract = w3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT), abi=ABI)
            self._w3, self._acct = w3, acct

    def _contract_for(self, address: str | None):
        """Resolve the contract to act on. None / the shared address -> the default
        contract; any other address -> a cached per-tenant XinserePermissions
        instance (same ABI). This is the seam the per-tenant factory writes into —
        see docs/per-tenant-contracts.md. Backward-compatible: callers that pass
        nothing keep hitting the shared contract exactly as before."""
        self._ensure()
        if not address or address.lower() == CONTRACT.lower():
            return self._contract
        from web3 import Web3
        key = Web3.to_checksum_address(address)
        c = self._by_addr.get(key)
        if c is None:
            c = self._w3.eth.contract(address=key, abi=ABI)
            self._by_addr[key] = c
        return c

    @property
    def wallet(self) -> str:
        self._ensure()
        return self._acct.address

    def verify(self, file_id: str, grantee_id: str, contract_address: str | None = None) -> tuple[bool, int]:
        """Read the contract: does grantee currently have permission to file?
        contract_address selects a per-tenant contract (None = shared)."""
        has, granted_at = self._contract_for(contract_address).functions.verify(
            file_hash(file_id), grantee_hash(grantee_id)).call()
        return bool(has), int(granted_at)

    def status(self) -> dict:
        """Read-only wallet + gas health for capacity pre-flight — spends NO gas.
        Lets an integrator's UI warn *before* a grant dies on-stage for lack of
        dust (integrator feedback #2). Reports the signer address, POL balance,
        current network gas price, the per-grant cost ceiling the signer reserves
        (gas_limit x maxFee), and a conservative count of grants still affordable."""
        self._ensure()
        w3 = self._w3
        balance_wei = w3.eth.get_balance(self._acct.address)
        try:
            gas_price_wei = w3.eth.gas_price
        except Exception:
            gas_price_wei = w3.to_wei(MAXFEE_GWEI, "gwei")
        # Cost ceiling per write matches the reserve the signer commits to.
        per_tx_wei = GAS_LIMIT * w3.to_wei(MAXFEE_GWEI, "gwei")
        est = int(balance_wei // per_tx_wei) if per_tx_wei else 0
        return {
            "wallet": self._acct.address,
            "balance_pol": round(float(w3.from_wei(balance_wei, "ether")), 6),
            "gas_price_gwei": round(float(w3.from_wei(gas_price_wei, "gwei")), 2),
            "max_fee_gwei": MAXFEE_GWEI,
            "gas_limit": GAS_LIMIT,
            "per_grant_pol": round(float(w3.from_wei(per_tx_wei, "ether")), 6),
            "est_grants_remaining": est,
            "wallet_ok": est >= 1,
        }

    def _send(self, fn) -> str:
        """Sign, send, and await a contract write. Returns the transaction hash."""
        w3, acct = self._w3, self._acct
        tx = fn.build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": CHAIN_ID,
            "maxPriorityFeePerGas": w3.to_wei(PRIORITY_GWEI, "gwei"),  # Amoy >=25 gwei floor
            "maxFeePerGas": w3.to_wei(MAXFEE_GWEI, "gwei"),
            "gas": GAS_LIMIT,
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        h = tx_hash.hex()
        h = h if h.startswith("0x") else "0x" + h
        # A mined-but-reverted tx (status 0) must surface as failure — otherwise a
        # failed revoke would be logged/reported as a successful one (audit lie).
        if getattr(receipt, "status", 1) != 1:
            raise RuntimeError(f"transaction reverted on-chain: {h}")
        return h

    def grant(self, file_id: str, grantee_id: str, ptype: str = "read",
              contract_address: str | None = None) -> str:
        """Write an on-chain grant. Returns the real transaction hash.
        (Contract overwrites an existing record — re-granting is safe.)
        contract_address selects a per-tenant contract (None = shared)."""
        return self._send(self._contract_for(contract_address).functions.grantPermission(
            file_hash(file_id), grantee_hash(grantee_id), ptype, 0))

    def revoke(self, file_id: str, grantee_id: str, contract_address: str | None = None) -> str | None:
        """Write an on-chain revocation. Returns the transaction hash, or None
        if there was no active grant to revoke (no-op).

        verify() is checked first because the contract REVERTS when revoking an
        inactive/absent grant ("Permission not found or already revoked") — a
        blind revoke would burn gas on a predictable revert, and a retry after a
        partial folder revocation would brick on the already-revoked files."""
        has, _ = self.verify(file_id, grantee_id, contract_address)
        if not has:
            return None
        return self._send(self._contract_for(contract_address).functions.revokePermission(
            file_hash(file_id), grantee_hash(grantee_id)))


CHAIN = Chain()
