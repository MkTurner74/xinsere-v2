"""Off-chain Merkle tree for the aggregate batch-grant path.

Must agree BYTE-FOR-BYTE with `XinserePermissions.verifyBatch`:

  leaf          = keccak256(fileHash ++ granteeHash)     # two bytes32 concatenated
  internal node = keccak256(sorted(a, b))                # commutative (OZ convention)

`fileHash`/`granteeHash` are the same 32-byte values chain.py already computes
(SHA-256(file_id) and HMAC-SHA256(grantee_id, tenant_salt)). Odd levels duplicate
the trailing node (hash it with itself) so the tree is total and unambiguous.

Security posture (see ADR-2026-07-13): the on-chain root is the source of truth;
these proofs are a rebuildable cache. `verify_like_contract()` is a faithful Python
model of the Solidity verifier, used by the tests to prove agreement before we ever
spend gas — the live redeploy test then confirms the model matches the deployed code.
"""
from __future__ import annotations

from typing import Sequence

# web3 is already a dependency (chain.py). Web3.keccak is the canonical keccak256.
from web3 import Web3

_keccak = Web3.keccak


def leaf(file_hash: bytes, grantee_hash: bytes) -> bytes:
    """keccak256(abi.encodePacked(fileHash, granteeHash)) — matches the contract.

    abi.encodePacked of two bytes32 is a plain 64-byte concatenation."""
    if len(file_hash) != 32 or len(grantee_hash) != 32:
        raise ValueError("file_hash and grantee_hash must each be 32 bytes")
    return _keccak(file_hash + grantee_hash)


def _hash_pair(a: bytes, b: bytes) -> bytes:
    """keccak256 of the two 32-byte children in ascending byte order (commutative)."""
    return _keccak(a + b) if a <= b else _keccak(b + a)


def build_levels(leaves: Sequence[bytes]) -> list[list[bytes]]:
    """Bottom-up levels [leaves, ..., [root]]. Trailing odd node is duplicated
    (paired with itself). Leaf order is preserved and is the caller's contract:
    the same order must be used to regenerate proofs at audit time."""
    if not leaves:
        raise ValueError("cannot build a tree over zero leaves")
    levels: list[list[bytes]] = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: list[bytes] = []
        for i in range(0, len(cur), 2):
            a = cur[i]
            b = cur[i + 1] if i + 1 < len(cur) else cur[i]  # duplicate trailing odd
            nxt.append(_hash_pair(a, b))
        levels.append(nxt)
    return levels


def root(leaves: Sequence[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]


def proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Sibling hashes from leaf `index` up to the root, in order."""
    levels = build_levels(leaves)
    out: list[bytes] = []
    idx = index
    for level in levels[:-1]:  # every level except the root
        sib = idx ^ 1  # sibling is the paired node
        if sib >= len(level):
            sib = idx  # lone trailing node was duplicated -> sibling is itself
        out.append(level[sib])
        idx //= 2
    return out


def verify_like_contract(the_leaf: bytes, the_root: bytes, the_proof: Sequence[bytes]) -> bool:
    """Faithful Python mirror of Solidity `verifyBatch`'s proof walk (excludes the
    on-chain anchored-root check). Lets tests prove proof/root self-consistency
    against the exact algorithm the contract runs."""
    computed = the_leaf
    for sib in the_proof:
        computed = _hash_pair(computed, sib)
    return computed == the_root


def hx(b: bytes) -> str:
    """0x-prefixed hex, the form the contract ABI and Supabase cache both use."""
    return "0x" + b.hex()
