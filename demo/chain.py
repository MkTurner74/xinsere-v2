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

import boto3
from web3 import Web3

RPC_URL = os.environ.get("XINSERE_RPC_URL", "https://rpc-amoy.polygon.technology")
CHAIN_ID = int(os.environ.get("XINSERE_CHAIN_ID", "80002"))
CONTRACT = os.environ.get("XINSERE_CONTRACT_ADDRESS", "0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD")
SECRET_ID = os.environ.get("XINSERE_SECRET_ID", "xinsere/blockchain/polygon-mumbai/private-key")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
TENANT_SALT = os.environ.get("XINSERE_TENANT_SALT", "dev-tenant-salt-change-me")
PRIORITY_GWEI = int(os.environ.get("XINSERE_PRIORITY_FEE_GWEI", "30"))
MAXFEE_GWEI = int(os.environ.get("XINSERE_MAX_FEE_GWEI", "50"))

ABI = [
    {"inputs": [{"type": "bytes32"}, {"type": "bytes32"}, {"type": "string"}, {"type": "uint256"}],
     "name": "grantPermission", "outputs": [{"type": "bytes32"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"type": "bytes32"}, {"type": "bytes32"}], "name": "verify",
     "outputs": [{"name": "hasPermission", "type": "bool"}, {"name": "grantedAt", "type": "uint256"}],
     "stateMutability": "view", "type": "function"},
]


def file_hash(file_id: str) -> bytes:
    return hashlib.sha256(file_id.encode()).digest()


def grantee_hash(grantee_id: str) -> bytes:
    return hmac.new(TENANT_SALT.encode(), grantee_id.encode(), hashlib.sha256).digest()


def _load_key() -> str:
    env = os.environ.get("XINSERE_PRIVATE_KEY")
    if env:
        return env if env.startswith("0x") else "0x" + env
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
        self._contract = None
        self._acct = None

    def _ensure(self):
        if self._contract is not None:
            return
        with self._lock:
            if self._contract is not None:
                return
            w3 = Web3(Web3.HTTPProvider(RPC_URL))
            acct = w3.eth.account.from_key(_load_key())
            self._contract = w3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT), abi=ABI)
            self._w3, self._acct = w3, acct

    @property
    def wallet(self) -> str:
        self._ensure()
        return self._acct.address

    def verify(self, file_id: str, grantee_id: str) -> tuple[bool, int]:
        """Read the contract: does grantee currently have permission to file?"""
        self._ensure()
        has, granted_at = self._contract.functions.verify(
            file_hash(file_id), grantee_hash(grantee_id)).call()
        return bool(has), int(granted_at)

    def grant(self, file_id: str, grantee_id: str, ptype: str = "read") -> str:
        """Write an on-chain grant. Returns the real transaction hash."""
        self._ensure()
        w3, acct = self._w3, self._acct
        fn = self._contract.functions.grantPermission(
            file_hash(file_id), grantee_hash(grantee_id), ptype, 0)
        tx = fn.build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": CHAIN_ID,
            "maxPriorityFeePerGas": w3.to_wei(PRIORITY_GWEI, "gwei"),  # Amoy >=25 gwei floor
            "maxFeePerGas": w3.to_wei(MAXFEE_GWEI, "gwei"),
            "gas": 300000,
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw)
        w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        return tx_hash.hex()


CHAIN = Chain()
