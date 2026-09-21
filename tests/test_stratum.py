import json
import socket
import threading
import time
import unittest

from btcminer.hashing import hash_to_hex, hex_to_hash, sha256d
from btcminer.header import BlockHeader
from btcminer.merkle import merkle_branch, merkle_root
from btcminer.stratum import (
    Job,
    StratumClient,
    StratumError,
    check_share,
    iter_extranonce2,
    swap_words,
)

EXTRANONCE1 = "0a1b2c3d"
EXTRANONCE2_SIZE = 4


def build_job(prev_display, version=0x20000000, bits=0x1D00FFFF, ntime=1_700_000_000,
              branch=()):
    """A mining.notify built the way a pool builds one, from known header fields."""
    prev_internal = hex_to_hash(prev_display)
    return Job(
        job_id="deadbeef",
        # Pools send prevhash with each 4-byte word reversed; swap_words undoes it.
        prev_hash=swap_words(prev_internal).hex(),
        coinb1="01000000010000000000000000000000000000000000000000000000000000000000000000"
               "ffffffff0e03a086010e",
        coinb2="0e2f6274632d6d696e65722f00000000ffffffff0100f2052a01000000"
               "066a04746573740000000000",
        merkle_branch=[node.hex() for node in branch],
        version=f"{version:08x}",
        nbits=f"{bits:08x}",
        ntime=f"{ntime:08x}",
        clean_jobs=True,
        extranonce1=EXTRANONCE1,
        extranonce2_size=EXTRANONCE2_SIZE,
    )


class TestWordSwap(unittest.TestCase):
    def test_swaps_within_words_only(self):
        self.assertEqual(swap_words(bytes.fromhex("01020304aabbccdd")),
                         bytes.fromhex("04030201ddccbbaa"))

    def test_is_its_own_inverse(self):
        data = bytes(range(32))
        self.assertEqual(swap_words(swap_words(data)), data)

    def test_requires_word_alignment(self):
        with self.assertRaises(ValueError):
            swap_words(b"\x00" * 6)


class TestJobToHeader(unittest.TestCase):
    """Stratum's fields are byte-order minefields; these pin the conventions down."""

    def setUp(self):
        self.prev = "00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81"
        self.job = build_job(self.prev)
        self.header = self.job.header(b"\x00" * EXTRANONCE2_SIZE)

    def test_prev_hash_lands_in_header_order(self):
        self.assertEqual(self.header.prev_hash, hex_to_hash(self.prev))
        self.assertEqual(hash_to_hex(self.header.prev_hash), self.prev)

    def test_scalar_fields_are_byte_reversed(self):
        self.assertEqual(self.header.version, 0x20000000)
        self.assertEqual(self.header.bits, 0x1D00FFFF)
        self.assertEqual(self.header.timestamp, 1_700_000_000)

    def test_ntime_can_be_rolled(self):
        rolled = self.job.header(b"\x00" * EXTRANONCE2_SIZE, ntime="65f00000")
        self.assertEqual(rolled.timestamp, 0x65F00000)

    def test_header_is_80_bytes_and_hashes(self):
        self.assertEqual(len(self.header.serialize()), 80)
        self.assertEqual(len(self.header.hash()), 32)

    def test_coinbase_splices_both_extranonces(self):
        extranonce2 = b"\xde\xad\xbe\xef"
        coinbase = self.job.coinbase(extranonce2)
        self.assertIn(bytes.fromhex(EXTRANONCE1) + extranonce2, coinbase)
        self.assertTrue(coinbase.startswith(bytes.fromhex(self.job.coinb1)))
        self.assertTrue(coinbase.endswith(bytes.fromhex(self.job.coinb2)))

    def test_merkle_root_is_the_coinbase_hash_without_a_branch(self):
        extranonce2 = b"\x01\x02\x03\x04"
        self.assertEqual(
            self.job.merkle_root(extranonce2), sha256d(self.job.coinbase(extranonce2))
        )

    def test_merkle_root_folds_the_branch(self):
        others = [sha256d(b"tx1"), sha256d(b"tx2"), sha256d(b"tx3")]
        extranonce2 = b"\x00" * EXTRANONCE2_SIZE
        coinbase_hash = sha256d(build_job(self.prev).coinbase(extranonce2))
        branch = merkle_branch([coinbase_hash] + others)
        job = build_job(self.prev, branch=branch)
        self.assertEqual(
            job.merkle_root(extranonce2), merkle_root([coinbase_hash] + others)
        )

    def test_extranonce2_width_is_enforced(self):
        with self.assertRaises(ValueError):
            self.job.coinbase(b"\x00" * 3)

    def test_different_extranonce2_gives_a_different_header(self):
        a = self.job.header(b"\x00\x00\x00\x00")
        b = self.job.header(b"\x00\x00\x00\x01")
        self.assertNotEqual(a.merkle_root, b.merkle_root)

    def test_from_notify_parses_the_wire_format(self):
        params = [
            "job1", self.job.prev_hash, self.job.coinb1, self.job.coinb2,
            [], "20000000", "1d00ffff", "65f00000", True,
        ]
        job = Job.from_notify(params, EXTRANONCE1, EXTRANONCE2_SIZE)
        self.assertEqual(job.job_id, "job1")
        self.assertTrue(job.clean_jobs)
        self.assertEqual(job.extranonce1, EXTRANONCE1)

    def test_from_notify_rejects_truncated_params(self):
        with self.assertRaises(ValueError):
            Job.from_notify(["job1"], EXTRANONCE1, EXTRANONCE2_SIZE)

    def test_job_target_matches_nbits(self):
        self.assertEqual(
            self.job.target(),
            0x00000000FFFF0000000000000000000000000000000000000000000000000000,
        )


class TestShareClassification(unittest.TestCase):
    def test_share_but_not_block(self):
        header = BlockHeader(1, b"\x00" * 32, b"\x00" * 32, 1, 0x1D00FFFF, 0)
        is_share, is_block = check_share(header, 2 ** 256 - 1)  # every hash clears this
        self.assertTrue(is_share)
        self.assertFalse(is_block)

    def test_neither(self):
        header = BlockHeader(1, b"\x00" * 32, b"\x00" * 32, 1, 0x1D00FFFF, 0)
        self.assertEqual(check_share(header, 1), (False, False))

    def test_a_real_block_is_both(self):
        genesis = BlockHeader.from_display(
            1, "00" * 32,
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            1231006505, 0x1D00FFFF, 2083236893,
        )
        self.assertEqual(check_share(genesis, genesis.target()), (True, True))


class TestExtranonce2(unittest.TestCase):
    def test_width_and_order(self):
        values = [v for _, v in zip(range(3), iter_extranonce2(4))]
        self.assertEqual(values, [b"\x00\x00\x00\x00", b"\x01\x00\x00\x00", b"\x02\x00\x00\x00"])

    def test_space_is_bounded_by_size(self):
        self.assertEqual(len(list(iter_extranonce2(1))), 256)


class FakePool(threading.Thread):
    """A loopback Stratum server, just enough of one to drive the client."""

    def __init__(self):
        super().__init__(daemon=True)
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.submissions = []
        self.ready = threading.Event()

    def run(self):
        conn, _ = self.server.accept()
        buffer = b""
        with conn:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    request = json.loads(line)
                    conn.sendall(self._respond(request))

    def _respond(self, request):
        method, request_id = request["method"], request["id"]
        if method == "mining.subscribe":
            result = [[["mining.notify", "sub1"]], EXTRANONCE1, EXTRANONCE2_SIZE]
            reply = json.dumps({"id": request_id, "result": result, "error": None}) + "\n"
            notify = json.dumps(
                {
                    "id": None,
                    "method": "mining.notify",
                    "params": [
                        "job1", "00" * 32, "01000000", "00000000", [],
                        "20000000", "1d00ffff", "65f00000", True,
                    ],
                }
            ) + "\n"
            difficulty = json.dumps(
                {"id": None, "method": "mining.set_difficulty", "params": [512]}
            ) + "\n"
            return (reply + difficulty + notify).encode()
        if method == "mining.authorize":
            return (json.dumps({"id": request_id, "result": True, "error": None}) + "\n").encode()
        if method == "mining.submit":
            self.submissions.append(request["params"])
            return (json.dumps({"id": request_id, "result": True, "error": None}) + "\n").encode()
        return (
            json.dumps({"id": request_id, "result": None, "error": [20, "unknown", None]}) + "\n"
        ).encode()


class TestClientAgainstFakePool(unittest.TestCase):
    """End-to-end over a real socket on loopback: no outside network involved."""

    def setUp(self):
        self.pool = FakePool()
        self.pool.start()
        self.client = StratumClient("127.0.0.1", self.pool.port, timeout=10)
        self.jobs = []
        self.difficulties = []
        self.client.on_job = self.jobs.append
        self.client.on_difficulty = self.difficulties.append
        self.client.connect()
        self.addCleanup(self.client.close)

    def test_full_session(self):
        extranonce1, size = self.client.subscribe()
        self.assertEqual((extranonce1, size), (EXTRANONCE1, EXTRANONCE2_SIZE))
        self.assertTrue(self.client.authorize("worker.1", "x"))

        waited = 0.0
        while not self.jobs and waited < 5.0:  # notifications arrive on the reader thread
            time.sleep(0.05)
            waited += 0.05
        self.assertTrue(self.jobs, "the pool's mining.notify should have been dispatched")
        self.assertEqual(self.jobs[0].job_id, "job1")
        self.assertEqual(self.client.difficulty, 512)
        self.assertEqual(self.difficulties, [512])

        # Share target follows the pool's difficulty, not the header's bits.
        self.assertEqual(self.client.share_target(), self.jobs[0].target() // 512)

        self.assertTrue(
            self.client.submit("worker.1", "job1", b"\x00\x01\x02\x03", "65f00000", 0xDEADBEEF)
        )
        self.assertEqual(
            self.pool.submissions[0],
            ["worker.1", "job1", "00010203", "65f00000", "deadbeef"],
        )

    def test_unknown_method_raises(self):
        with self.assertRaises(StratumError):
            self.client.call("mining.nonsense", [])

    def test_call_on_closed_connection_raises(self):
        self.client.close()
        with self.assertRaises(StratumError):
            self.client.subscribe()


if __name__ == "__main__":
    unittest.main()
