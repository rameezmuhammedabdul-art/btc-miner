"""SHA-256d and the compact-target arithmetic Bitcoin uses for proof of work."""

from __future__ import annotations

import hashlib

# The easiest target the network allows: difficulty 1, compact form 0x1d00ffff.
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET_BITS = 0x1D00FFFF


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double SHA-256, the hash under every block header and txid."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_to_int(block_hash: bytes) -> int:
    """Interpret a 32-byte hash the way consensus does: as a little-endian integer."""
    return int.from_bytes(block_hash, "little")


def hash_to_hex(block_hash: bytes) -> str:
    """Render an internal hash in the big-endian order block explorers display."""
    return block_hash[::-1].hex()


def hex_to_hash(value: str) -> bytes:
    """Inverse of :func:`hash_to_hex`: display hex -> internal little-endian bytes."""
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"expected a 32-byte hash, got {len(raw)} bytes")
    return raw[::-1]


def bits_to_target(bits: int) -> int:
    """Expand the 4-byte compact encoding in a header into a full 256-bit target.

    This is decoding only. Whether the result is *allowed* on mainnet is a
    separate question -- see :func:`exceeds_pow_limit` -- because local mining at
    an easier-than-difficulty-1 target is a perfectly reasonable thing to ask for.
    """
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        raise ValueError("negative compact targets are invalid in block headers")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target >= 1 << 256:
        raise ValueError(f"compact target 0x{bits:08x} overflows 256 bits")
    return target


def exceeds_pow_limit(target: int) -> bool:
    """True if a target is easier than consensus allows (easier than difficulty 1)."""
    return target > MAX_TARGET


def target_to_bits(target: int) -> int:
    """Compact-encode a target. Round-trips values that came from bits_to_target."""
    if target <= 0:
        raise ValueError("target must be positive")
    raw = target.to_bytes(32, "big").lstrip(b"\x00")
    if raw[0] & 0x80:  # keep the sign bit clear by borrowing another byte
        raw = b"\x00" + raw
    exponent = len(raw)
    mantissa = int.from_bytes(raw[:3].ljust(3, b"\x00"), "big")
    return (exponent << 24) | mantissa


def difficulty_to_target(difficulty: float) -> int:
    """Pool/network difficulty -> target. Difficulty 1 is MAX_TARGET."""
    if difficulty <= 0:
        raise ValueError("difficulty must be positive")
    return int(MAX_TARGET / difficulty)


def target_to_difficulty(target: int) -> float:
    if target <= 0:
        raise ValueError("target must be positive")
    return MAX_TARGET / target


def expected_hashes(target: int) -> float:
    """Mean number of hashes needed to find one solution at this target."""
    return 2 ** 256 / (target + 1)
