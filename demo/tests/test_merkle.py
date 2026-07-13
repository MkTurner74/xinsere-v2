"""Merkle batch-grant unit tests.

These prove the off-chain builder is self-consistent with the EXACT algorithm the
contract's verifyBatch runs (modelled by merkle.verify_like_contract) across a range
of batch sizes, including the odd-node edge cases that break naive implementations.
The live redeploy test then confirms the model matches the deployed Solidity.
"""
import hashlib
import hmac

import pytest

import chain
import merkle


def _leaves(n: int) -> list[bytes]:
    """n realistic leaves using the SAME hashing chain.py uses on-chain:
    fileHash = SHA-256(file_id), granteeHash = HMAC-SHA256(grantee_id, salt)."""
    salt = "test-salt"
    out = []
    for i in range(n):
        fh = hashlib.sha256(f"file-{i}".encode()).digest()
        gh = hmac.new(salt.encode(), f"grantee-{i % 3}".encode(), hashlib.sha256).digest()
        out.append(merkle.leaf(fh, gh))
    return out


# Sizes chosen to hit: single leaf, powers of two, and several odd/duplicate cases.
@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 100, 1000])
def test_every_leaf_proof_reconstructs_the_root(n):
    leaves = _leaves(n)
    root = merkle.root(leaves)
    for i, lf in enumerate(leaves):
        pf = merkle.proof(leaves, i)
        assert merkle.verify_like_contract(lf, root, pf), f"leaf {i}/{n} failed"


def test_wrong_leaf_is_rejected():
    leaves = _leaves(50)
    root = merkle.root(leaves)
    pf = merkle.proof(leaves, 10)
    forged = merkle.leaf(hashlib.sha256(b"not-in-tree").digest(),
                         hashlib.sha256(b"nope").digest())
    assert not merkle.verify_like_contract(forged, root, pf)


def test_proof_from_another_tree_is_rejected():
    a = _leaves(20)
    b = _leaves(21)  # different tree
    root_a = merkle.root(a)
    pf_b = merkle.proof(b, 5)
    assert not merkle.verify_like_contract(b[5], root_a, pf_b)


def test_single_leaf_tree_has_empty_proof_and_leaf_is_root():
    leaves = _leaves(1)
    assert merkle.proof(leaves, 0) == []
    assert merkle.root(leaves) == leaves[0]
    assert merkle.verify_like_contract(leaves[0], merkle.root(leaves), [])


def test_pair_hash_is_commutative_and_cross_pair_order_matters():
    leaves = _leaves(8)
    # Commutative node hash: swapping siblings WITHIN a pair must NOT change root
    # (this is the documented OZ MerkleProof property, and it's safe here because
    # every (file,grantee) leaf is unique — you still can't prove a leaf not in the set).
    assert merkle._hash_pair(leaves[0], leaves[1]) == merkle._hash_pair(leaves[1], leaves[0])
    within_pair = [leaves[1], leaves[0]] + leaves[2:]
    assert merkle.root(leaves) == merkle.root(within_pair)
    # But moving a leaf ACROSS pairs changes the commitment.
    cross_pair = [leaves[0], leaves[2], leaves[1]] + leaves[3:]
    assert merkle.root(leaves) != merkle.root(cross_pair)


def test_leaf_matches_solidity_encodepacked():
    """leaf == keccak256(fileHash ++ granteeHash), 64-byte packed preimage."""
    from web3 import Web3
    fh = hashlib.sha256(b"file").digest()
    gh = hashlib.sha256(b"grantee").digest()
    assert merkle.leaf(fh, gh) == Web3.keccak(fh + gh)


def test_leaf_rejects_wrong_width():
    with pytest.raises(ValueError):
        merkle.leaf(b"short", hashlib.sha256(b"x").digest())


def test_real_chain_hashes_flow_through(monkeypatch):
    """The concrete chain.file_hash / chain.grantee_hash outputs are valid leaves."""
    monkeypatch.setenv("XINSERE_TENANT_SALT", "dev-tenant-salt")
    fh = chain.file_hash("file-abc")
    gh = chain.grantee_hash("user-xyz")
    lf = merkle.leaf(fh, gh)
    leaves = _leaves(9) + [lf]
    root = merkle.root(leaves)
    pf = merkle.proof(leaves, len(leaves) - 1)
    assert merkle.verify_like_contract(lf, root, pf)
