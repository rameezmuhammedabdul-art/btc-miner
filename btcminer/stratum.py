"""Stratum v1 client: the protocol every pool speaks over a plain TCP socket.

Endianness is where Stratum implementations usually go wrong, so the rules this
module follows are spelled out:

* ``version``, ``nbits`` and ``ntime`` arrive as big-endian hex and are byte
  reversed to go into the little-endian header fields.
* ``prevhash`` arrives with its 32-bit words individually byte-reversed (the
  order inherited from getwork), so it is word-swapped back to header order.
* The merkle root is used exactly as the double-SHA folding produces it; it is
  never reversed.
* ``nonce``, ``ntime`` and the extranonce2 go back to the pool as big-endian hex,
  in the same form they were received.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional

from .hashing import hash_to_int, sha256d
from .header import BlockHeader
from .merkle import merkle_root_from_branch


def swap_words(data: bytes) -> bytes:
    """Reverse the bytes inside each 4-byte word, keeping word order."""
    if len(data) % 4:
        raise ValueError("input must be a whole number of 4-byte words")
    return b"".join(data[i : i + 4][::-1] for i in range(0, len(data), 4))


@dataclass
class Job:
    """One ``mining.notify``: everything needed to build headers until the next one."""

    job_id: str
    prev_hash: str
    coinb1: str
    coinb2: str
    merkle_branch: list[str]
    version: str
    nbits: str
    ntime: str
    clean_jobs: bool
    extranonce1: str
    extranonce2_size: int

    @classmethod
    def from_notify(cls, params: list[Any], extranonce1: str, extranonce2_size: int) -> "Job":
        if len(params) < 9:
            raise ValueError(f"mining.notify needs 9 parameters, got {len(params)}")
        return cls(
            job_id=params[0],
            prev_hash=params[1],
            coinb1=params[2],
            coinb2=params[3],
            merkle_branch=list(params[4]),
            version=params[5],
            nbits=params[6],
            ntime=params[7],
            clean_jobs=bool(params[8]),
            extranonce1=extranonce1,
            extranonce2_size=extranonce2_size,
        )

    def coinbase(self, extranonce2: bytes) -> bytes:
        if len(extranonce2) != self.extranonce2_size:
            raise ValueError(
                f"extranonce2 must be {self.extranonce2_size} bytes, got {len(extranonce2)}"
            )
        return (
            bytes.fromhex(self.coinb1)
            + bytes.fromhex(self.extranonce1)
            + extranonce2
            + bytes.fromhex(self.coinb2)
        )

    def merkle_root(self, extranonce2: bytes) -> bytes:
        branch = [bytes.fromhex(node) for node in self.merkle_branch]
        return merkle_root_from_branch(sha256d(self.coinbase(extranonce2)), branch)

    def header(self, extranonce2: bytes, ntime: Optional[str] = None) -> BlockHeader:
        """Assemble the header this job implies for a given extranonce2."""
        return BlockHeader(
            version=int.from_bytes(bytes.fromhex(self.version)[::-1], "little", signed=True),
            prev_hash=swap_words(bytes.fromhex(self.prev_hash)),
            merkle_root=self.merkle_root(extranonce2),
            timestamp=int(ntime or self.ntime, 16),
            bits=int(self.nbits, 16),
        )

    def target(self) -> int:
        from .hashing import bits_to_target

        return bits_to_target(int(self.nbits, 16))


class StratumError(RuntimeError):
    """The pool answered a request with an error, or hung up on us."""


class StratumClient:
    """A line-delimited JSON-RPC connection to a mining pool.

    Reading happens on a background thread: notifications (``mining.notify``,
    ``mining.set_difficulty``) are dispatched through callbacks while responses
    are matched to their request id.
    """

    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.extranonce1: str = ""
        self.extranonce2_size: int = 4
        self.difficulty: float = 1.0
        self.on_job: Optional[Callable[[Job], None]] = None
        self.on_difficulty: Optional[Callable[[float], None]] = None
        self._sock: Optional[socket.socket] = None
        self._buffer = b""
        self._next_id = 1
        self._responses: dict[int, Any] = {}
        self._errors: dict[int, Any] = {}
        self._lock = threading.Lock()
        self._event = threading.Condition(self._lock)
        self._reader: Optional[threading.Thread] = None
        self._closed = False

    # -- connection ---------------------------------------------------------
    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(None)
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._closed = True
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
        with self._event:
            self._event.notify_all()

    def __enter__(self) -> "StratumClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- plumbing -----------------------------------------------------------
    def _send(self, payload: dict[str, Any]) -> None:
        if self._sock is None:
            raise StratumError("not connected")
        self._sock.sendall(json.dumps(payload).encode() + b"\n")

    def call(self, method: str, params: list[Any], timeout: Optional[float] = None) -> Any:
        """Issue a request and block until the pool answers it."""
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        self._send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + (timeout or self.timeout)
        with self._event:
            while request_id not in self._responses and request_id not in self._errors:
                if self._closed:
                    raise StratumError(f"connection closed while waiting for {method}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StratumError(f"timed out waiting for a reply to {method}")
                self._event.wait(remaining)
            if request_id in self._errors:
                raise StratumError(f"{method} failed: {self._errors.pop(request_id)!r}")
            return self._responses.pop(request_id)

    def _read_loop(self) -> None:
        try:
            while not self._closed and self._sock is not None:
                chunk = self._sock.recv(65536)
                if not chunk:
                    break
                self._buffer += chunk
                while b"\n" in self._buffer:
                    line, self._buffer = self._buffer.split(b"\n", 1)
                    if line.strip():
                        self._dispatch(json.loads(line.decode()))
        except (OSError, ValueError):
            pass
        finally:
            self._closed = True
            with self._event:
                self._event.notify_all()

    def _dispatch(self, message: dict[str, Any]) -> None:
        if message.get("method"):
            self._handle_notification(message)
            return
        message_id = message.get("id")
        with self._event:
            if message.get("error"):
                self._errors[message_id] = message["error"]
            else:
                self._responses[message_id] = message.get("result")
            self._event.notify_all()

    def _handle_notification(self, message: dict[str, Any]) -> None:
        method = message["method"]
        params = message.get("params") or []
        if method == "mining.notify" and self.on_job is not None:
            self.on_job(Job.from_notify(params, self.extranonce1, self.extranonce2_size))
        elif method == "mining.set_difficulty" and params:
            self.difficulty = float(params[0])
            if self.on_difficulty is not None:
                self.on_difficulty(self.difficulty)

    # -- protocol -----------------------------------------------------------
    def subscribe(self, user_agent: str = "btc-miner/0.1.0") -> tuple[str, int]:
        result = self.call("mining.subscribe", [user_agent])
        if not isinstance(result, list) or len(result) < 3:
            raise StratumError(f"unexpected mining.subscribe result: {result!r}")
        self.extranonce1 = result[1]
        self.extranonce2_size = int(result[2])
        return self.extranonce1, self.extranonce2_size

    def authorize(self, username: str, password: str = "x") -> bool:
        return bool(self.call("mining.authorize", [username, password]))

    def submit(
        self, username: str, job_id: str, extranonce2: bytes, ntime: str, nonce: int
    ) -> bool:
        """Submit a share. Nonce and extranonce2 go up as big-endian hex."""
        return bool(
            self.call(
                "mining.submit",
                [username, job_id, extranonce2.hex(), ntime, f"{nonce:08x}"],
            )
        )

    def share_target(self) -> int:
        from .hashing import difficulty_to_target

        return difficulty_to_target(self.difficulty)


def iter_extranonce2(size: int) -> Iterator[bytes]:
    """Every extranonce2 of the pool's chosen width, in order."""
    for value in range(1 << (8 * size)):
        yield value.to_bytes(size, "little")


def check_share(header: BlockHeader, share_target: int) -> tuple[bool, bool]:
    """Return ``(is_share, is_block)`` for a candidate header."""
    value = hash_to_int(header.hash())
    return value <= share_target, value <= header.target()
