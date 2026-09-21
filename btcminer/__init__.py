"""A working SHA-256d Bitcoin miner: block headers, proof of work, and Stratum."""

from .hashing import bits_to_target, difficulty_to_target, sha256d, target_to_difficulty
from .header import BlockHeader
from .merkle import merkle_branch, merkle_root, merkle_root_from_branch
from .miner import MiningResult, benchmark, mine, search
from .stratum import Job, StratumClient
from .template import BlockTemplate, Coinbase, block_subsidy

__version__ = "0.1.0"

__all__ = [
    "BlockHeader",
    "BlockTemplate",
    "Coinbase",
    "Job",
    "MiningResult",
    "StratumClient",
    "benchmark",
    "bits_to_target",
    "block_subsidy",
    "difficulty_to_target",
    "merkle_branch",
    "merkle_root",
    "merkle_root_from_branch",
    "mine",
    "search",
    "sha256d",
    "target_to_difficulty",
    "__version__",
]
