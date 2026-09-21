"""The search loop: scan the nonce space for a header hash that beats the target."""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .header import PREFIX_SIZE, BlockHeader
from .hashing import hash_to_hex

NONCE_SPACE = 1 << 32
# How many nonces a worker grinds before it checks the stop flag and reports.
BATCH = 1 << 16


@dataclass
class MiningResult:
    """Outcome of a search. ``nonce is None`` means the range was exhausted."""

    nonce: Optional[int]
    header: Optional[BlockHeader]
    hashes: int
    elapsed: float

    @property
    def found(self) -> bool:
        return self.nonce is not None

    @property
    def hashrate(self) -> float:
        return self.hashes / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def block_hash(self) -> Optional[str]:
        return self.header.hash_hex() if self.header is not None else None


def search(
    prefix: bytes,
    target: int,
    start: int,
    count: int,
    should_stop: Optional[Callable[[], bool]] = None,
) -> tuple[Optional[int], int]:
    """Grind nonces ``start .. start+count`` over a 76-byte header prefix.

    Returns ``(winning_nonce_or_None, hashes_tried)``.

    Two tricks keep the inner loop tight: the first 64 bytes of the header are a
    whole SHA-256 block, so their state is hashed once and copied per attempt;
    and when the target is below 2**224 the top four bytes of the digest must be
    zero, which is an exact and much cheaper rejection than a bignum compare.
    """
    if len(prefix) != PREFIX_SIZE:
        raise ValueError(f"prefix must be {PREFIX_SIZE} bytes, got {len(prefix)}")
    if count < 0:
        raise ValueError("count must not be negative")

    midstate = hashlib.sha256(prefix[:64])
    tail = prefix[64:]
    sha256 = hashlib.sha256
    cheap_reject = target < (1 << 224)
    zero4 = b"\x00\x00\x00\x00"

    nonce = start
    end = start + count
    while nonce < end:
        chunk_end = min(nonce + BATCH, end)
        while nonce < chunk_end:
            ctx = midstate.copy()
            ctx.update(tail + nonce.to_bytes(4, "little"))
            digest = sha256(ctx.digest()).digest()
            if cheap_reject and digest[28:] != zero4:
                nonce += 1
                continue
            if int.from_bytes(digest, "little") <= target:
                return nonce, nonce - start + 1
            nonce += 1
        if should_stop is not None and should_stop():
            break
    return None, nonce - start


def _worker(
    prefix: bytes,
    target: int,
    start: int,
    count: int,
    stop: "mp.Event",  # type: ignore[name-defined]
    results: "mp.Queue",  # type: ignore[name-defined]
    progress: "mp.Queue",  # type: ignore[name-defined]
) -> None:
    """Child process: scan a slice, reporting progress so the parent can total it."""
    done = 0
    nonce = start
    remaining = count
    try:
        while remaining > 0 and not stop.is_set():
            step = min(BATCH, remaining)
            found, tried = search(prefix, target, nonce, step)
            done += tried
            nonce += step
            remaining -= step
            progress.put(tried)
            if found is not None:
                results.put(found)
                stop.set()
                return
    finally:
        results.put(None)


def mine(
    header: BlockHeader,
    target: Optional[int] = None,
    processes: Optional[int] = None,
    nonce_start: int = 0,
    nonce_count: int = NONCE_SPACE,
    on_progress: Optional[Callable[[int, float], None]] = None,
) -> MiningResult:
    """Mine ``header`` across every core until a nonce beats ``target``.

    The nonce range is split into one contiguous slice per process. Exhausting it
    without a win is normal and expected at real difficulty: the caller should
    then roll the timestamp or extranonce and come back for another 4 billion.
    """
    if target is None:
        target = header.target()
    if processes is None:
        processes = os.cpu_count() or 1
    processes = max(1, min(processes, nonce_count)) if nonce_count else 1
    prefix = header.prefix()

    started = time.monotonic()
    if processes == 1:
        nonce, hashes = search(prefix, target, nonce_start, nonce_count)
        elapsed = time.monotonic() - started
        if on_progress is not None:
            on_progress(hashes, elapsed)
        winner = header.with_nonce(nonce) if nonce is not None else None
        return MiningResult(nonce, winner, hashes, elapsed)

    ctx = mp.get_context("spawn" if os.name == "nt" else "fork")
    stop = ctx.Event()
    results: "mp.Queue" = ctx.Queue()
    progress: "mp.Queue" = ctx.Queue()

    slice_size, extra = divmod(nonce_count, processes)
    workers = []
    cursor = nonce_start
    for i in range(processes):
        size = slice_size + (1 if i < extra else 0)
        worker = ctx.Process(
            target=_worker,
            args=(prefix, target, cursor, size, stop, results, progress),
            daemon=True,
        )
        worker.start()
        workers.append(worker)
        cursor += size

    nonce: Optional[int] = None
    finished = 0
    hashes = 0
    try:
        while finished < len(workers):
            item = results.get()
            if item is None:
                finished += 1
                continue
            nonce = item
            stop.set()
        while not progress.empty():
            hashes += progress.get_nowait()
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker.terminate()

    elapsed = time.monotonic() - started
    if on_progress is not None:
        on_progress(hashes, elapsed)
    winner = header.with_nonce(nonce) if nonce is not None else None
    return MiningResult(nonce, winner, hashes, elapsed)


def _bench_worker(seconds: float, offset: int, results: "mp.Queue") -> None:  # type: ignore[name-defined]
    header = BlockHeader(0x20000000, bytes(32), bytes(32), int(time.time()), 0x1D00FFFF)
    prefix = header.prefix()
    started = time.monotonic()
    hashes = 0
    # Target 0 is unreachable, so the search only ever ends on the clock.
    while time.monotonic() - started < seconds:
        _, tried = search(prefix, 0, offset + hashes, BATCH)
        hashes += tried
    results.put((hashes, time.monotonic() - started))


def benchmark(seconds: float = 5.0, processes: Optional[int] = None) -> float:
    """Measure real aggregate hashrate by grinding an impossible target on every core."""
    if processes is None:
        processes = os.cpu_count() or 1
    processes = max(1, processes)

    if processes == 1:
        results: "mp.Queue" = mp.get_context("fork").Queue() if os.name != "nt" else mp.Queue()
        _bench_worker(seconds, 0, results)
        hashes, elapsed = results.get()
        return hashes / elapsed if elapsed else 0.0

    ctx = mp.get_context("spawn" if os.name == "nt" else "fork")
    results = ctx.Queue()
    workers = [
        ctx.Process(target=_bench_worker, args=(seconds, i << 32 // processes, results), daemon=True)
        for i in range(processes)
    ]
    for worker in workers:
        worker.start()
    total = 0.0
    for _ in workers:
        hashes, elapsed = results.get()
        total += hashes / elapsed if elapsed else 0.0
    for worker in workers:
        worker.join(timeout=5)
    return total


def describe_hashrate(rate: float) -> str:
    for unit, scale in (("TH/s", 1e12), ("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if rate >= scale:
            return f"{rate / scale:.2f} {unit}"
    return f"{rate:.0f} H/s"


__all__ = [
    "MiningResult",
    "benchmark",
    "describe_hashrate",
    "hash_to_hex",
    "mine",
    "search",
    "NONCE_SPACE",
]
