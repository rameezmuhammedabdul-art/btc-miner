"""Minimal block-template construction: a coinbase transaction and a header to grind."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from .hashing import hash_to_hex, hex_to_hash, sha256d
from .header import BlockHeader
from .merkle import merkle_root


def varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def push_data(data: bytes) -> bytes:
    """Script push of a short byte string (enough for coinbase scriptSigs)."""
    if len(data) > 75:
        raise ValueError("use a longer push opcode for data over 75 bytes")
    return bytes([len(data)]) + data


def encode_height(height: int) -> bytes:
    """BIP34 requires the block height as the first push of the coinbase script."""
    if height < 0:
        raise ValueError("height must not be negative")
    if height == 0:
        return push_data(b"")
    raw = height.to_bytes((height.bit_length() + 7) // 8, "little")
    if raw[-1] & 0x80:  # keep it a positive CScriptNum
        raw += b"\x00"
    return push_data(raw)


@dataclass
class Coinbase:
    """The one transaction a miner is free to write, and so the one it mutates."""

    height: int
    value: int  # satoshis: subsidy + fees
    script_pubkey: bytes
    tag: bytes = b"/btc-miner/"
    extranonce: bytes = b"\x00\x00\x00\x00"
    sequence: int = 0xFFFFFFFF
    locktime: int = 0

    def script_sig(self) -> bytes:
        return encode_height(self.height) + push_data(self.extranonce) + push_data(self.tag)

    def serialize(self) -> bytes:
        script_sig = self.script_sig()
        return b"".join(
            [
                struct.pack("<i", 1),           # version
                varint(1),                      # one input
                bytes(32),                      # null outpoint hash
                struct.pack("<I", 0xFFFFFFFF),  # null outpoint index
                varint(len(script_sig)),
                script_sig,
                struct.pack("<I", self.sequence),
                varint(1),                      # one output
                struct.pack("<q", self.value),
                varint(len(self.script_pubkey)),
                self.script_pubkey,
                struct.pack("<I", self.locktime),
            ]
        )

    def txid(self) -> bytes:
        return sha256d(self.serialize())

    def with_extranonce(self, extranonce: int) -> "Coinbase":
        return Coinbase(
            height=self.height,
            value=self.value,
            script_pubkey=self.script_pubkey,
            tag=self.tag,
            extranonce=extranonce.to_bytes(4, "little"),
            sequence=self.sequence,
            locktime=self.locktime,
        )


def block_subsidy(height: int) -> int:
    """50 BTC, halving every 210,000 blocks, in satoshis."""
    halvings = height // 210_000
    if halvings >= 64:
        return 0
    return (50 * 100_000_000) >> halvings


@dataclass
class BlockTemplate:
    """Enough of a template to build headers; transactions beyond the coinbase are opaque."""

    height: int
    prev_hash: bytes
    bits: int
    coinbase: Coinbase
    txids: list[bytes] = field(default_factory=list)  # excluding the coinbase
    version: int = 0x20000000
    timestamp: int = field(default_factory=lambda: int(time.time()))

    @classmethod
    def demo(
        cls,
        height: int = 900_000,
        bits: int = 0x1D00FFFF,
        prev_hash_hex: str | None = None,
        tag: bytes = b"/btc-miner/",
    ) -> "BlockTemplate":
        """A self-consistent local template, for exercising the miner without a node."""
        prev = (
            hex_to_hash(prev_hash_hex)
            if prev_hash_hex
            else sha256d(b"btc-miner demo parent %d" % height)
        )
        coinbase = Coinbase(
            height=height,
            value=block_subsidy(height),
            # OP_RETURN <tag>: provably unspendable, so nobody mistakes this for a payout.
            script_pubkey=b"\x6a" + push_data(tag),
            tag=tag,
        )
        return cls(height=height, prev_hash=prev, bits=bits, coinbase=coinbase)

    def merkle_root(self) -> bytes:
        return merkle_root([self.coinbase.txid()] + list(self.txids))

    def header(self, timestamp: int | None = None) -> BlockHeader:
        return BlockHeader(
            version=self.version,
            prev_hash=self.prev_hash,
            merkle_root=self.merkle_root(),
            timestamp=self.timestamp if timestamp is None else timestamp,
            bits=self.bits,
        )

    def roll_extranonce(self, extranonce: int) -> "BlockTemplate":
        """Fresh coinbase -> fresh merkle root -> a whole new 4-billion nonce space."""
        return BlockTemplate(
            height=self.height,
            prev_hash=self.prev_hash,
            bits=self.bits,
            coinbase=self.coinbase.with_extranonce(extranonce),
            txids=list(self.txids),
            version=self.version,
            timestamp=self.timestamp,
        )

    def describe(self) -> str:
        return (
            f"height={self.height} prev={hash_to_hex(self.prev_hash)[:16]}... "
            f"bits=0x{self.bits:08x} coinbase_txid={hash_to_hex(self.coinbase.txid())[:16]}... "
            f"reward={self.coinbase.value / 1e8:.8f} BTC"
        )
