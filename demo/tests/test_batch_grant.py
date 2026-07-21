"""Batch-grant engine tests — the safety properties Mark asked for, proven without gas.

A fake chain models the contract's anchored-root + verifyBatch semantics exactly
(using the same merkle module), and a fake supa records what the cache would store.
We assert: capping bounds batch size, the read-back gate blocks a corrupt anchor,
failures are isolated per chunk, and downloads verify only for real grants.
"""
import pytest

import batch_grant
import merkle
from batch_grant import Grant


class FakeChain:
    """Models XinserePermissions batch semantics faithfully. `corrupt_root` forces
    an anchor to store a WRONG root (simulating a builder/anchor bug) so we can
    prove the read-back gate catches it and the batch is never trusted."""
    def __init__(self, corrupt=False):
        self.anchored: dict[bytes, int] = {}
        self.corrupt = corrupt
        self.tx_n = 0

    def grant_batch(self, root: bytes, size: int) -> str:
        self.tx_n += 1
        stored = bytes([b ^ 0xFF for b in root]) if self.corrupt else root  # bad anchor
        self.anchored[stored] = 1
        return f"0xtx{self.tx_n:03d}"

    def root_anchored(self, root: bytes) -> int:
        return self.anchored.get(root, 0)

    def verify_batch(self, leaf: bytes, root: bytes, proof) -> bool:
        if self.anchored.get(root, 0) == 0:
            return False  # fail closed on unanchored/revoked root
        return merkle.verify_like_contract(leaf, root, proof)


class FakeSupa:
    def __init__(self):
        self.batches: dict[str, dict] = {}
        self.grants: list[dict] = []
    def insert_permission_batch(self, token, merkle_root, leaf_count, source, scope,
                                not_before=0, not_after=0):
        self.batches[merkle_root] = {"leaf_count": leaf_count, "status": "pending",
                                     "not_before": not_before, "not_after": not_after}
        return self.batches[merkle_root]
    def set_batch_status(self, token, merkle_root, status, *, tx_hash=None, anchored_at=None):
        self.batches.setdefault(merkle_root, {})["status"] = status
    def insert_batch_grants(self, token, rows):
        self.grants.extend(rows)


def _grants(n, grantees=1):
    return [Grant(f"file-{i}", f"user-{j}") for i in range(n) for j in range(grantees)]


def test_caps_bound_the_batch_size():
    ch, sp = FakeChain(), FakeSupa()
    res = batch_grant.preserve(_grants(2500), supa=sp, token="t", source="dropbox",
                               scope="/Founders", cap=1000, chain_client=ch)
    assert res.batches == 3            # 1000 + 1000 + 500
    assert res.grants == 2500
    assert len(res.tx_hashes) == 3     # one flat-gas tx per batch, not per file
    assert all(b["status"] == "live" for b in sp.batches.values())


def test_corrupt_anchor_is_caught_and_never_trusted():
    ch, sp = FakeChain(corrupt=True), FakeSupa()
    res = batch_grant.preserve(_grants(50), supa=sp, token="t", source="dropbox",
                               scope="/x", cap=1000, chain_client=ch)
    assert res.batches == 0            # nothing trusted
    assert res.failed and "read-back" in res.failed[0][1]
    assert all(b["status"] == "failed" for b in sp.batches.values())


def test_one_bad_chunk_does_not_abort_the_rest():
    ch, sp = FakeChain(), FakeSupa()
    real_grant = ch.grant_batch
    calls = {"n": 0}
    def flaky(root, size):
        calls["n"] += 1
        if calls["n"] == 2:            # blow up the 2nd batch only
            raise RuntimeError("rpc hiccup")
        return real_grant(root, size)
    ch.grant_batch = flaky
    res = batch_grant.preserve(_grants(2500), supa=sp, token="t", source="dropbox",
                               scope="/x", cap=1000, chain_client=ch)
    assert res.batches == 2            # 1st and 3rd survived
    assert len(res.failed) == 1
    assert res.grants == 1500


def test_stored_proofs_verify_and_forged_leaf_is_denied():
    ch, sp = FakeChain(), FakeSupa()
    batch_grant.preserve(_grants(30), supa=sp, token="t", source="dropbox",
                         scope="/x", cap=1000, chain_client=ch)
    # Every cached proof validates on-chain (the download-gate path).
    for row in sp.grants:
        leaf = bytes.fromhex(row["leaf"][2:])
        root = bytes.fromhex(row["merkle_root"][2:])
        proof = [bytes.fromhex(p[2:]) for p in row["proof"]]
        assert ch.verify_batch(leaf, root, proof)
    # A leaf that was never granted cannot be proven under any anchored root.
    forged = merkle.leaf(bytes(32), bytes(32))
    root = bytes.fromhex(sp.grants[0]["merkle_root"][2:])
    proof = [bytes.fromhex(p[2:]) for p in sp.grants[0]["proof"]]
    assert not ch.verify_batch(forged, root, proof)


def test_duplicate_grants_are_deduped():
    ch, sp = FakeChain(), FakeSupa()
    dupes = [Grant("f1", "u1"), Grant("f1", "u1"), Grant("f2", "u1")]
    res = batch_grant.preserve(dupes, supa=sp, token="t", source="dropbox",
                               scope="/x", cap=1000, chain_client=ch)
    assert res.grants == 2             # (f1,u1) counted once


def test_folder_share_expands_to_leaf_per_file_per_grantee():
    ch, sp = FakeChain(), FakeSupa()
    res = batch_grant.preserve(_grants(100, grantees=2), supa=sp, token="t",
                               source="dropbox", scope="/x", cap=1000, chain_client=ch)
    assert res.grants == 200           # 100 files x 2 collaborators


def test_sample_indices_cover_edges():
    idx = batch_grant._sample_indices(1000, 8)
    assert idx[0] == 0 and idx[-1] == 999   # first + last (odd-node edges) always checked
    assert len(idx) <= 8
