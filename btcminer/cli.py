"""Command line interface: verify, bench, mine (local), pool (Stratum), odds."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import Optional

from .hashing import (
    bits_to_target,
    exceeds_pow_limit,
    difficulty_to_target,
    expected_hashes,
    hash_to_hex,
    target_to_difficulty,
)
from .header import BlockHeader
from .miner import benchmark, describe_hashrate, mine
from .stratum import Job, StratumClient, check_share, iter_extranonce2
from .template import BlockTemplate

# Two mainnet blocks whose headers are public record; they prove the hasher works.
KNOWN_BLOCKS = [
    (
        "genesis (block 0)",
        BlockHeader.from_display(
            1,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            1231006505,
            0x1D00FFFF,
            2083236893,
        ),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ),
    (
        "block 125552",
        BlockHeader.from_display(
            1,
            "00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81",
            "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
            1305998791,
            0x1A44B9F2,
            2504433986,
        ),
        "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d",
    ),
]


def humanize_seconds(seconds: float) -> str:
    if seconds != seconds or seconds == float("inf"):
        return "never"
    for unit, scale in (
        ("years", 365.25 * 86400),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
    ):
        if seconds >= scale:
            return f"{seconds / scale:,.1f} {unit}"
    return f"{seconds:.1f} seconds"


def cmd_verify(args: argparse.Namespace) -> int:
    ok = True
    for name, header, expected in KNOWN_BLOCKS:
        actual = header.hash_hex()
        valid = header.is_valid_pow() and not exceeds_pow_limit(header.target())
        matched = actual == expected and valid
        ok = ok and matched
        print(f"{'PASS' if matched else 'FAIL'}  {name}")
        print(f"      hash   {actual}")
        print(f"      target 0x{header.target():064x}")
        print(f"      pow    {'valid' if valid else 'INVALID'}")
    print("\nall known blocks verified" if ok else "\nverification FAILED")
    return 0 if ok else 1


def cmd_bench(args: argparse.Namespace) -> int:
    processes = args.processes or os.cpu_count() or 1
    print(f"hashing on {processes} process(es) for {args.seconds:.0f}s ...")
    rate = benchmark(seconds=args.seconds, processes=processes)
    print(f"hashrate: {describe_hashrate(rate)} ({rate:,.0f} H/s)")
    per_core = rate / processes if processes else rate
    print(f"per core: {describe_hashrate(per_core)}")
    if args.difficulty:
        target = difficulty_to_target(args.difficulty)
        print(
            f"\nat difficulty {args.difficulty:,.0f} a solution needs "
            f"{expected_hashes(target):.3e} hashes on average"
        )
        print(f"expected time to a block: {humanize_seconds(expected_hashes(target) / rate)}")
    return 0


def cmd_odds(args: argparse.Namespace) -> int:
    target = difficulty_to_target(args.difficulty)
    need = expected_hashes(target)
    print(f"network difficulty : {args.difficulty:,.0f}")
    print(f"target             : 0x{target:064x}")
    print(f"hashes per block   : {need:.3e} on average")
    print()
    for label, rate in (
        ("this CPU (~1 MH/s/core x 4)", 4e6),
        ("high-end GPU (~1 GH/s)", 1e9),
        ("Antminer S21 (200 TH/s)", 2e14),
        ("1% of the whole network", need / 600 * 0.01),
    ):
        seconds = need / rate
        print(f"{label:<30} {describe_hashrate(rate):>10}  ->  {humanize_seconds(seconds)}")
    return 0


def cmd_mine(args: argparse.Namespace) -> int:
    """Mine locally-built templates: real headers and real proof of work, chosen difficulty."""
    bits = int(args.bits, 16) if args.bits else None
    target = bits_to_target(bits) if bits is not None else difficulty_to_target(args.difficulty)
    if bits is None:
        # Keep the header's own bits consistent with the target we are searching for.
        from .hashing import target_to_bits

        bits = target_to_bits(target)

    template = BlockTemplate.demo(height=args.height, bits=bits)
    processes = args.processes or os.cpu_count() or 1

    print(f"mining {args.blocks} block(s) at difficulty {target_to_difficulty(target):,.4f}")
    print(f"target   0x{target:064x}")
    print(f"expected {expected_hashes(target):,.0f} hashes per block, {processes} process(es)")
    print(f"template {template.describe()}\n")

    found = 0
    total_hashes = 0
    started = time.monotonic()
    extranonce = 0
    while found < args.blocks:
        candidate = template.roll_extranonce(extranonce)
        header = candidate.header(timestamp=int(time.time()))
        result = mine(header, target=target, processes=processes)
        total_hashes += result.hashes
        if result.found and result.header is not None:
            found += 1
            elapsed = time.monotonic() - started
            print(f"block {found} found in {elapsed:,.1f}s")
            print(f"  hash       {result.header.hash_hex()}")
            print(f"  nonce      {result.nonce} (extranonce {extranonce})")
            print(f"  merkle     {hash_to_hex(candidate.merkle_root())}")
            print(f"  hashes     {total_hashes:,} @ {describe_hashrate(result.hashrate)}")
            print(f"  header     {result.header.serialize().hex()}")
            print(f"  valid pow  {result.header.is_valid_pow(target)}\n")
        else:
            # 4 billion nonces gone: change the coinbase and the search starts over.
            print(f"  nonce space exhausted at extranonce {extranonce}, rolling coinbase")
        extranonce += 1

    elapsed = time.monotonic() - started
    print(
        f"done: {found} block(s), {total_hashes:,} hashes in {elapsed:,.1f}s "
        f"({describe_hashrate(total_hashes / elapsed if elapsed else 0)})"
    )
    return 0


def cmd_pool(args: argparse.Namespace) -> int:
    """Mine for a real Stratum pool. This connects out to the host you name."""
    client = StratumClient(args.host, args.port, timeout=args.timeout)
    current: dict[str, Optional[Job]] = {"job": None}
    shares = {"accepted": 0, "rejected": 0, "blocks": 0}

    def on_job(job: Job) -> None:
        current["job"] = job
        print(f"[job] {job.job_id} clean={job.clean_jobs} nbits={job.nbits}")

    def on_difficulty(difficulty: float) -> None:
        print(f"[diff] pool difficulty now {difficulty:g}")

    client.on_job = on_job
    client.on_difficulty = on_difficulty

    print(f"connecting to {args.host}:{args.port} ...")
    with client:
        extranonce1, extranonce2_size = client.subscribe()
        print(f"subscribed: extranonce1={extranonce1} extranonce2_size={extranonce2_size}")
        if not client.authorize(args.user, args.password):
            print("pool rejected the worker credentials", file=sys.stderr)
            return 1
        print(f"authorized as {args.user}")

        deadline = time.monotonic() + args.timeout
        while current["job"] is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if current["job"] is None:
            print("no job arrived from the pool", file=sys.stderr)
            return 1

        processes = args.processes or os.cpu_count() or 1
        extranonce2s = iter_extranonce2(extranonce2_size)
        while True:
            job = current["job"]
            assert job is not None
            extranonce2 = next(extranonce2s)
            ntime = f"{int(time.time()):08x}"
            header = job.header(extranonce2, ntime=ntime)
            share_target = client.share_target()
            result = mine(header, target=share_target, processes=processes)
            latest = current["job"]
            if latest is not job and latest is not None and latest.clean_jobs:
                continue  # a clean job arrived: work on the old one is stale
            if not result.found or result.header is None:
                continue
            is_share, is_block = check_share(result.header, share_target)
            if is_block:
                shares["blocks"] += 1
                print(f"*** BLOCK CANDIDATE *** {result.header.hash_hex()}")
            if is_share:
                accepted = client.submit(args.user, job.job_id, extranonce2, ntime, result.nonce)
                shares["accepted" if accepted else "rejected"] += 1
                print(
                    f"[share] {'accepted' if accepted else 'REJECTED'} "
                    f"nonce={result.nonce:08x} hash={result.header.hash_hex()} "
                    f"({shares['accepted']} ok / {shares['rejected']} bad) "
                    f"{describe_hashrate(result.hashrate)}"
                )
            if args.shares and shares["accepted"] + shares["rejected"] >= args.shares:
                return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="btcminer",
        description="A SHA-256d Bitcoin miner: real proof of work, honest arithmetic.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="re-hash known mainnet blocks to prove correctness")
    verify.set_defaults(func=cmd_verify)

    bench = sub.add_parser("bench", help="measure this machine's hashrate")
    bench.add_argument("--seconds", type=float, default=5.0)
    bench.add_argument("--processes", type=int, default=None)
    bench.add_argument("--difficulty", type=float, default=None, help="also report expected time")
    bench.set_defaults(func=cmd_bench)

    mine_cmd = sub.add_parser("mine", help="mine local block templates at a chosen difficulty")
    mine_cmd.add_argument("--difficulty", type=float, default=0.0005)
    mine_cmd.add_argument("--bits", type=str, default=None, help="compact target, e.g. 1d00ffff")
    mine_cmd.add_argument("--blocks", type=int, default=1)
    mine_cmd.add_argument("--height", type=int, default=900_000)
    mine_cmd.add_argument("--processes", type=int, default=None)
    mine_cmd.set_defaults(func=cmd_mine)

    pool = sub.add_parser("pool", help="mine for a Stratum v1 pool (connects to the network)")
    pool.add_argument("--host", required=True)
    pool.add_argument("--port", type=int, required=True)
    pool.add_argument("--user", required=True, help="usually <payout-address>.<worker>")
    pool.add_argument("--password", default="x")
    pool.add_argument("--processes", type=int, default=None)
    pool.add_argument("--timeout", type=float, default=30.0)
    pool.add_argument("--shares", type=int, default=0, help="stop after N shares (0 = forever)")
    pool.set_defaults(func=cmd_pool)

    odds = sub.add_parser("odds", help="expected time to find a block, for various hashrates")
    odds.add_argument("--difficulty", type=float, default=126_000_000_000_000.0)
    odds.set_defaults(func=cmd_odds)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
