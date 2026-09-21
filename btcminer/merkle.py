"""Merkle roots, both from a full transaction list and from a Stratum branch."""

from __future__ import annotations

from typing import Iterable, Sequence

from .hashing import sha256d


def merkle_root(txids: Sequence[bytes]) -> bytes:
    """Merkle root over internal-order txids.

    Bitcoin duplicates the last hash when a level has an odd number of nodes.
    """
    if not txids:
        raise ValueError("a block always contains at least the coinbase")
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_root_from_branch(coinbase_hash: bytes, branch: Iterable[bytes]) -> bytes:
    """Fold a coinbase hash through the branch a pool sends in mining.notify.

    The coinbase is always leftmost, so every step concatenates on the right.
    """
    root = coinbase_hash
    for node in branch:
        if len(node) != 32:
            raise ValueError("merkle branch nodes must be 32 bytes")
        root = sha256d(root + node)
    return root


def merkle_branch(txids: Sequence[bytes]) -> list[bytes]:
    """The branch proving the first (coinbase) leaf, as a pool would publish it."""
    if not txids:
        raise ValueError("need at least one txid")
    branch: list[bytes] = []
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return branch
