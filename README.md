# btc-miner

A Bitcoin miner in pure Python: real SHA-256d proof of work, real block headers,
real Stratum. It verifies itself against mainnet blocks, mines local templates at
whatever difficulty you ask for, and will connect to a live pool if you point it
at one.

It will not make you money. [The arithmetic is below](#about-actually-mining-bitcoin).

```console
$ python3 -m btcminer verify
PASS  genesis (block 0)
      hash   000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
      pow    valid
PASS  block 125552
      hash   00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d
      pow    valid
```

Those are the real hashes of those two mainnet blocks, recomputed from their
header fields by this code. If the hasher were wrong in any detail — a byte
order, a field width — they would not come out.

## Mining

```console
$ python3 -m btcminer mine --difficulty 0.0008 --blocks 3
mining 3 block(s) at difficulty 0.0008
target   0x000004e1fb1e0000000000000000000000000000000000000000000000000000
expected 3,436,026 hashes per block, 4 process(es)

block 1 found in 0.1s
  hash       00000091e1a400e17704a36488afb0b2af024c86c00284ad5625e37993ea7a4d
  nonce      24967 (extranonce 0)
  hashes     221,576 @ 2.00 MH/s
  valid pow  True
```

The proof of work is genuine: a real 80-byte header over a real coinbase
transaction, hashed until the digest came in under the target. The only thing
lowered is the target. The template is built locally rather than pulled from a
node, and its coinbase pays to `OP_RETURN`, so these blocks are provably not
worth anything and could never be relayed — they are the mining loop, honestly
exercised.

Raise the difficulty to feel the wall. Each factor of ten costs ten times the
work; mainnet is roughly `--difficulty 150000000000000`.

## Commands

| Command | What it does |
| --- | --- |
| `verify` | Re-hash known mainnet blocks to prove the hasher is correct |
| `bench` | Measure this machine's hashrate across all cores |
| `mine` | Mine local block templates at a difficulty you choose |
| `pool` | Mine for a real Stratum v1 pool (opens an outbound connection) |
| `odds` | Expected time to a block, for a range of hardware |

```console
$ python3 -m btcminer bench --seconds 3
hashrate: 4.03 MH/s (4,027,974 H/s)
per core: 1.01 MH/s
```

### Pointing it at a real pool

```console
$ python3 -m btcminer pool --host pool.example.com --port 3333 \
    --user <your-payout-address>.worker1 --password x
```

This speaks Stratum v1: `mining.subscribe`, `mining.authorize`, then headers
built from each `mining.notify` and shares submitted with `mining.submit`. It
tracks `mining.set_difficulty` and submits anything that clears the pool's share
target, flagging any hash that clears the network target as a block candidate.

It connects to whatever host you name and mines under whatever worker name you
give it — supply your own pool and your own payout address.

## About actually mining Bitcoin

Being straight with you, since the repo is named `btc-miner`:

```console
$ python3 -m btcminer odds --difficulty 150000000000000
hashes per block   : 6.443e+23 on average

this CPU (~1 MH/s/core x 4)     4.00 MH/s  ->  5,103,801,659.1 years
high-end GPU (~1 GH/s)          1.00 GH/s  ->  20,415,206.6 years
Antminer S21 (200 TH/s)        200.00 TH/s  ->  102.1 years
```

A block needs about 6.4 × 10²³ hashes at that difficulty. This code does about
4 × 10⁶ per second, so a solo CPU would expect to wait on the order of billions
of years — several times the age of the universe — and Python is roughly a
million times slower per core than the ASICs it would be competing against.
Pooled mining replaces one impossible jackpot with a proportional share of a
small one, which for a CPU rounds to nothing and costs more in electricity than
it returns.

What this repository is actually good for: understanding exactly what a miner
does, because every step is here and none of it is hand-waved — the 80-byte
header, the compact target encoding, the merkle branch a pool hands you, the
nonce grind, and the Stratum conversation around it.

## Layout

| Module | Contents |
| --- | --- |
| `btcminer/hashing.py` | SHA-256d, compact-bits ↔ target, difficulty math |
| `btcminer/header.py` | The 80-byte block header and its proof-of-work check |
| `btcminer/merkle.py` | Merkle roots, and the coinbase branch pools send |
| `btcminer/template.py` | Coinbase construction, subsidy schedule, templates |
| `btcminer/miner.py` | The nonce search and its multi-process driver |
| `btcminer/stratum.py` | Stratum v1 client, job → header, share classification |
| `btcminer/cli.py` | Command line interface |

### Implementation notes

Two details account for most of the speed. The first 64 bytes of a header are a
complete SHA-256 block, so their midstate is computed once per job and copied
per nonce rather than rehashed. And whenever the target is below 2²²⁴ — which
every real target is — a hash can only win if the top four bytes of its digest
are zero, so the loop checks those four bytes before doing any bignum
comparison. `tests/test_miner.py` proves that shortcut agrees with a full
comparison rather than taking it on trust.

The byte-order conventions, which is where Stratum implementations usually go
wrong, are documented at the top of `btcminer/stratum.py` and pinned down by
tests: scalars byte-reversed, `prevhash` word-swapped, merkle root left exactly
as the folding produces it.

## Tests

```console
$ python3 -m unittest discover -s tests -v
```

93 tests, no dependencies beyond the standard library. They check the hasher
against real mainnet blocks (genesis, 125552), the merkle code against block 170
— the Satoshi-to-Hal transaction — the BIP34 height encoding against the example
in the BIP itself, and the Stratum client end to end against a fake pool on
loopback.

`TestSolutionRate` covers the failure mode a miner is most likely to hide: a
comparison bug in the hot loop still emits plausible-looking hashes, and each
one it reports may even verify — what goes wrong is how *often* it finds them.
So one test enumerates every winning nonce in a range and demands exact
agreement with a plain-`hashlib` brute force, and another measures
hashes-per-solution over 32 trials and checks it against `2**256/target`. Both
draw a fixed sample, so neither can flake. Mutating the loop to be 2x, 16x too
lucky, to read the digest big-endian, or to return the wrong nonce is caught by
both.

## Requirements

Python 3.9+. No dependencies.
