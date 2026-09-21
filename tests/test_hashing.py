import unittest

from btcminer.hashing import (
    MAX_TARGET,
    bits_to_target,
    difficulty_to_target,
    exceeds_pow_limit,
    expected_hashes,
    hash_to_hex,
    hash_to_int,
    hex_to_hash,
    sha256d,
    target_to_bits,
    target_to_difficulty,
)

GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


class TestSha256d(unittest.TestCase):
    def test_known_vector(self):
        # sha256d("hello") is a widely published value.
        self.assertEqual(
            sha256d(b"hello").hex(),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50",
        )

    def test_empty_input(self):
        self.assertEqual(len(sha256d(b"")), 32)


class TestHashOrder(unittest.TestCase):
    def test_display_round_trip(self):
        self.assertEqual(hash_to_hex(hex_to_hash(GENESIS_HASH)), GENESIS_HASH)

    def test_display_is_byte_reversed(self):
        internal = hex_to_hash(GENESIS_HASH)
        self.assertTrue(internal.endswith(b"\x00\x00\x00\x00"))  # leading zeros move to the end

    def test_int_is_little_endian(self):
        self.assertEqual(hash_to_int(b"\x01" + bytes(31)), 1)
        self.assertEqual(hash_to_int(bytes(31) + b"\x01"), 1 << 248)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            hex_to_hash("00" * 31)


class TestCompactTarget(unittest.TestCase):
    def test_difficulty_one(self):
        self.assertEqual(bits_to_target(0x1D00FFFF), MAX_TARGET)
        self.assertAlmostEqual(target_to_difficulty(MAX_TARGET), 1.0)

    def test_block_125552_bits(self):
        self.assertEqual(
            bits_to_target(0x1A44B9F2),
            0x00000000000044B9F20000000000000000000000000000000000000000000000,
        )

    def test_small_exponent(self):
        self.assertEqual(bits_to_target(0x01003456), 0x00)
        self.assertEqual(bits_to_target(0x02008000), 0x80)
        self.assertEqual(bits_to_target(0x04123456), 0x12345600)

    def test_round_trip(self):
        for bits in (0x1D00FFFF, 0x1A44B9F2, 0x170B98F2, 0x1B0404CB, 0x04123456):
            self.assertEqual(target_to_bits(bits_to_target(bits)), bits)

    def test_rejects_negative_mantissa(self):
        with self.assertRaises(ValueError):
            bits_to_target(0x01800000)  # sign bit set: a malformed encoding

    def test_rejects_overflow(self):
        with self.assertRaises(ValueError):
            bits_to_target(0xFF00FFFF)  # shifts past 256 bits

    def test_decodes_but_flags_targets_easier_than_consensus_allows(self):
        # Decoding is not validation: local mining uses easier targets on purpose.
        easy = bits_to_target(0x1E00FFFF)
        self.assertGreater(easy, MAX_TARGET)
        self.assertTrue(exceeds_pow_limit(easy))
        self.assertFalse(exceeds_pow_limit(MAX_TARGET))
        self.assertFalse(exceeds_pow_limit(bits_to_target(0x1A44B9F2)))

    def test_difficulty_scales_inversely(self):
        self.assertEqual(difficulty_to_target(1), MAX_TARGET)
        self.assertAlmostEqual(target_to_difficulty(difficulty_to_target(4096)), 4096, places=3)
        self.assertLess(difficulty_to_target(1000), difficulty_to_target(10))

    def test_difficulty_must_be_positive(self):
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                difficulty_to_target(bad)

    def test_expected_hashes_matches_difficulty(self):
        # Difficulty 1 is ~2**32 hashes per solution, by construction.
        self.assertAlmostEqual(expected_hashes(MAX_TARGET) / 2 ** 32, 1.0, places=3)


if __name__ == "__main__":
    unittest.main()
