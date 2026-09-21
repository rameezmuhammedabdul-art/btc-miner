"""The 80-byte Bitcoin block header: the thing a miner actually hashes."""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace

from .hashing import bits_to_target, hash_to_hex, hash_to_int, hex_to_hash, sha256d

HEADER_SIZE = 80
# Everything before the 4-byte nonce; a miner rebuilds only the last 4 bytes.
PREFIX_SIZE = 76


@dataclass(frozen=True)
class BlockHeader:
    """Header fields in their *internal* representation.

    ``prev_hash`` and ``merkle_root`` are the little-endian byte strings that go
    into the header verbatim, i.e. the reverse of what an explorer shows.
    """

    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int = 0

    def __post_init__(self) -> None:
        if len(self.prev_hash) != 32:
            raise ValueError("prev_hash must be 32 bytes")
        if len(self.merkle_root) != 32:
            raise ValueError("merkle_root must be 32 bytes")

    @classmethod
    def from_display(
        cls,
        version: int,
        prev_hash_hex: str,
        merkle_root_hex: str,
        timestamp: int,
        bits: int,
        nonce: int = 0,
    ) -> "BlockHeader":
        """Build a header from the big-endian hex strings explorers and RPC use."""
        return cls(
            version=version,
            prev_hash=hex_to_hash(prev_hash_hex),
            merkle_root=hex_to_hash(merkle_root_hex),
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
        )

    def prefix(self) -> bytes:
        """The first 76 bytes: constant while the nonce is scanned."""
        return (
            struct.pack("<i", self.version)
            + self.prev_hash
            + self.merkle_root
            + struct.pack("<III", self.timestamp, self.bits, 0)[:8]
        )

    def serialize(self) -> bytes:
        return self.prefix() + struct.pack("<I", self.nonce)

    @classmethod
    def deserialize(cls, raw: bytes) -> "BlockHeader":
        if len(raw) != HEADER_SIZE:
            raise ValueError(f"a header is {HEADER_SIZE} bytes, got {len(raw)}")
        version, timestamp, bits, nonce = (
            struct.unpack("<i", raw[0:4])[0],
            *struct.unpack("<III", raw[68:80]),
        )
        return cls(version, raw[4:36], raw[36:68], timestamp, bits, nonce)

    def with_nonce(self, nonce: int) -> "BlockHeader":
        return replace(self, nonce=nonce)

    def with_timestamp(self, timestamp: int) -> "BlockHeader":
        return replace(self, timestamp=timestamp)

    def hash(self) -> bytes:
        return sha256d(self.serialize())

    def hash_hex(self) -> str:
        return hash_to_hex(self.hash())

    def target(self) -> int:
        return bits_to_target(self.bits)

    def is_valid_pow(self, target: int | None = None) -> bool:
        """Consensus rule: the header hash, read little-endian, must be <= target."""
        if target is None:
            target = self.target()
        return hash_to_int(self.hash()) <= target
