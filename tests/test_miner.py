import unittest

from btcminer.hashing import hash_to_int
from btcminer.header import BlockHeader
from btcminer.miner import describe_hashrate, mine, search

EASY = 2 ** 244   # ~1 in 4,000 hashes
HARD = 2 ** 236   # ~1 in a million hashes


def header(nonce=0, seed=b"\x01"):
    return BlockHeader(0x20000000, seed * 32, b"\x02" * 32, 1_700_000_000, 0x1D00FFFF, nonce)


class TestSearch(unittest.TestCase):
    def test_finds_a_valid_nonce(self):
        base = header()
        nonce, tried = search(base.prefix(), EASY, 0, 1_000_000)
        self.assertIsNotNone(nonce)
        self.assertTrue(base.with_nonce(nonce).is_valid_pow(EASY))
        self.assertEqual(tried, nonce + 1)

    def test_returns_the_first_valid_nonce(self):
        base = header()
        nonce, _ = search(base.prefix(), EASY, 0, 1_000_000)
        brute = next(
            n for n in range(nonce + 1) if hash_to_int(base.with_nonce(n).hash()) <= EASY
        )
        self.assertEqual(nonce, brute)

    def test_exhausted_range_reports_no_winner(self):
        # Target 0 is unreachable, so the whole range is scanned and counted.
        nonce, tried = search(header().prefix(), 0, 0, 5_000)
        self.assertIsNone(nonce)
        self.assertEqual(tried, 5_000)

    def test_respects_the_start_of_the_range(self):
        base = header()
        first, _ = search(base.prefix(), EASY, 0, 1_000_000)
        second, _ = search(base.prefix(), EASY, first + 1, 1_000_000)
        self.assertGreater(second, first)
        self.assertTrue(base.with_nonce(second).is_valid_pow(EASY))

    def test_cheap_rejection_agrees_with_full_comparison(self):
        # The digest[28:] prefilter is exact only below 2**224; prove it here.
        base = header(seed=b"\x07")
        tiny = 2 ** 223
        found, _ = search(base.prefix(), tiny, 0, 20_000)
        brute = [
            n for n in range(20_000) if hash_to_int(base.with_nonce(n).hash()) <= tiny
        ]
        self.assertEqual(found, brute[0] if brute else None)

    def test_rejects_wrong_prefix_length(self):
        with self.assertRaises(ValueError):
            search(b"\x00" * 75, EASY, 0, 10)

    def test_zero_count_is_a_no_op(self):
        self.assertEqual(search(header().prefix(), 2 ** 255, 0, 0), (None, 0))


class TestMine(unittest.TestCase):
    def test_single_process(self):
        base = header(seed=b"\x03")
        result = mine(base, target=EASY, processes=1, nonce_count=2_000_000)
        self.assertTrue(result.found)
        self.assertTrue(result.header.is_valid_pow(EASY))
        self.assertGreater(result.hashes, 0)
        self.assertGreater(result.hashrate, 0)
        # A 2**244 target zeroes the top 12 bits, i.e. three leading hex zeros.
        self.assertTrue(result.block_hash.startswith("000"))

    def test_multiple_processes(self):
        base = header(seed=b"\x04")
        result = mine(base, target=HARD, processes=4, nonce_count=1 << 24)
        self.assertTrue(result.found)
        self.assertTrue(result.header.is_valid_pow(HARD))

    def test_unsolvable_range_terminates(self):
        result = mine(header(), target=0, processes=2, nonce_count=20_000)
        self.assertFalse(result.found)
        self.assertIsNone(result.header)
        self.assertIsNone(result.block_hash)

    def test_target_defaults_to_header_bits(self):
        # bits 0x1d00ffff over a short range: no solution, but it must not crash.
        result = mine(header(), processes=1, nonce_count=1_000)
        self.assertFalse(result.found)


class TestFormatting(unittest.TestCase):
    def test_units(self):
        self.assertEqual(describe_hashrate(500), "500 H/s")
        self.assertEqual(describe_hashrate(1_500), "1.50 kH/s")
        self.assertEqual(describe_hashrate(2.5e6), "2.50 MH/s")
        self.assertEqual(describe_hashrate(3.25e9), "3.25 GH/s")
        self.assertEqual(describe_hashrate(1e14), "100.00 TH/s")


if __name__ == "__main__":
    unittest.main()
