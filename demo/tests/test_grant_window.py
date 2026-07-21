"""On-chain grant validity window (0020-expiry) — proven without gas.

A fake chain models XinserePermissions' windowed anchor + time-gated verifyBatch
(start/expiry per root), using the same merkle module the contract mirrors. We prove:

  * a windowed share anchors via grant_batch_windowed and records the window;
  * an expiry that has passed makes verifyBatch fail closed (no revoke needed);
  * a FUTURE start still anchors 'live' (read-back uses the off-chain proof walk,
    not the time-gated on-chain verify) and begins verifying once the start passes;
  * app._parse_window parses/validates the share dialog's start & expiry inputs.
"""
import pytest

import batch_grant
import merkle
from batch_grant import Grant


class WindowedFakeChain:
    """Models the windowed contract faithfully. `now` is the simulated block time;
    verify_batch fails closed outside [not_before, not_after] just like Solidity."""
    def __init__(self, now=1_000_000):
        self.now = now
        self.anchored: dict[bytes, int] = {}
        self.window: dict[bytes, tuple[int, int]] = {}
        self.tx_n = 0
        self.windowed_calls = 0
        self.plain_calls = 0

    def grant_batch(self, root: bytes, size: int) -> str:
        self.plain_calls += 1
        self.tx_n += 1
        self.anchored[root] = self.now
        self.window[root] = (0, 0)
        return f"0xtx{self.tx_n:03d}"

    def grant_batch_windowed(self, root: bytes, size: int, nb: int, na: int) -> str:
        self.windowed_calls += 1
        self.tx_n += 1
        self.anchored[root] = self.now
        self.window[root] = (nb, na)
        return f"0xtx{self.tx_n:03d}"

    def root_anchored(self, root: bytes) -> int:
        return self.anchored.get(root, 0)

    def verify_batch(self, leaf: bytes, root: bytes, proof) -> bool:
        if self.anchored.get(root, 0) == 0:
            return False
        nb, na = self.window.get(root, (0, 0))
        if nb and self.now < nb:
            return False   # not valid yet
        if na and self.now > na:
            return False   # expired
        return merkle.verify_like_contract(leaf, root, proof)


class FakeSupa:
    def __init__(self):
        self.batches, self.grants = {}, []

    def insert_permission_batch(self, token, merkle_root, leaf_count, source, scope,
                                not_before=0, not_after=0):
        self.batches[merkle_root] = {"leaf_count": leaf_count, "status": "pending",
                                     "not_before": not_before, "not_after": not_after}
        return self.batches[merkle_root]

    def set_batch_status(self, token, merkle_root, status, *, tx_hash=None, anchored_at=None):
        self.batches.setdefault(merkle_root, {})["status"] = status

    def insert_batch_grants(self, token, rows):
        self.grants.extend(rows)


def _leaf(g: Grant) -> bytes:
    import chain
    return merkle.leaf_typed(chain.file_hash(g.file_id), chain.grantee_hash(g.grantee_id),
                             g.grant_type)


def test_expiry_makes_verify_fail_closed_with_no_revoke():
    ch, sp = WindowedFakeChain(now=1_000_000), FakeSupa()
    g = Grant("file-x", "user-1")
    na = 1_000_500          # expires shortly after anchor
    res = batch_grant.preserve([g], supa=sp, token="t", source="share", scope="node-1",
                               chain_client=ch, not_after=na)
    assert res.batches == 1 and ch.windowed_calls == 1 and ch.plain_calls == 0
    root = bytes.fromhex(res.roots[0][2:])
    proof = merkle.proof([_leaf(g)], 0)
    # Within the window: verifies. After expiry: fails closed — no revoke tx sent.
    assert ch.verify_batch(_leaf(g), root, proof) is True
    ch.now = na + 1
    assert ch.verify_batch(_leaf(g), root, proof) is False


def test_future_start_anchors_live_then_activates():
    ch, sp = WindowedFakeChain(now=1_000_000), FakeSupa()
    g = Grant("file-y", "user-2")
    nb = 1_005_000          # starts in the future
    # Read-back must not require the (not-yet-open) on-chain verify to pass.
    res = batch_grant.preserve([g], supa=sp, token="t", source="share", scope="node-2",
                               chain_client=ch, not_before=nb)
    assert res.batches == 1 and ch.windowed_calls == 1
    assert sp.batches[res.roots[0]]["status"] == "live"
    root = bytes.fromhex(res.roots[0][2:])
    proof = merkle.proof([_leaf(g)], 0)
    assert ch.verify_batch(_leaf(g), root, proof) is False   # not valid yet
    ch.now = nb + 1
    assert ch.verify_batch(_leaf(g), root, proof) is True    # window opened


def test_no_window_uses_plain_grant_batch():
    ch, sp = WindowedFakeChain(), FakeSupa()
    batch_grant.preserve([Grant("f", "u")], supa=sp, token="t", source="share",
                         scope="n", chain_client=ch)
    assert ch.plain_calls == 1 and ch.windowed_calls == 0


# --- app._parse_window (share dialog input validation) ----------------------

def test_parse_window_blank_is_unbounded():
    import app
    assert app._parse_window(None, None) == (0, 0)
    assert app._parse_window("", "") == (0, 0)


def test_parse_window_rejects_inverted_range():
    import app
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        app._parse_window("2000", "1000")


def test_parse_window_rejects_past_expiry():
    import app
    import time
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        app._parse_window(None, str(int(time.time()) - 10))
