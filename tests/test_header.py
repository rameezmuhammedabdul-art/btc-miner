import unittest

from btcminer.header import HEADER_SIZE, PREFIX_SIZE, BlockHeader

GENESIS = BlockHeader.from_display(
    1,
    "00" * 32,
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    1231006505,
    0x1D00FFFF,
    2083236893,
)
BLOCK_125552 = BlockHeader.from_display(
    1,
    "00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81",
    "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
    1305998791,
    0x1A44B9F2,
    2504433986,
)


class TestRealBlocks(unittest.TestCase):
    def test_genesis_hash(self):
        self.assertEqual(
            GENESIS.hash_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )

    def test_block_125552_hash(self):
        self.assertEqual(
            BLOCK_125552.hash_hex(),
            "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d",
        )

    def test_real_blocks_satisfy_their_own_target(self):
        self.assertTrue(GENESIS.is_valid_pow())
        self.assertTrue(BLOCK_125552.is_valid_pow())

    def test_genesis_serialization(self):
        self.assertTrue(GENESIS.serialize().hex().startswith("0100000000000000"))
        self.assertEqual(len(GENESIS.serialize()), HEADER_SIZE)


class TestSerialization(unittest.TestCase):
    def test_round_trip(self):
        for header in (GENESIS, BLOCK_125552):
            self.assertEqual(BlockHeader.deserialize(header.serialize()), header)

    def test_prefix_excludes_nonce(self):
        self.assertEqual(len(GENESIS.prefix()), PREFIX_SIZE)
        self.assertEqual(GENESIS.prefix(), GENESIS.with_nonce(12345).prefix())
        self.assertEqual(GENESIS.serialize()[:PREFIX_SIZE], GENESIS.prefix())

    def test_deserialize_rejects_short_input(self):
        with self.assertRaises(ValueError):
            BlockHeader.deserialize(b"\x00" * 79)

    def test_rejects_bad_field_widths(self):
        with self.assertRaises(ValueError):
            BlockHeader(1, b"\x00" * 31, b"\x00" * 32, 0, 0x1D00FFFF)
        with self.assertRaises(ValueError):
            BlockHeader(1, b"\x00" * 32, b"\x00" * 33, 0, 0x1D00FFFF)

    def test_negative_version_survives_round_trip(self):
        # Version is signed in consensus code; overt ASICBoost blocks set the high bit.
        header = BlockHeader(-0x7FFFFFFF, b"\x11" * 32, b"\x22" * 32, 1, 0x1D00FFFF, 9)
        self.assertEqual(BlockHeader.deserialize(header.serialize()).version, -0x7FFFFFFF)


class TestProofOfWork(unittest.TestCase):
    def test_wrong_nonce_fails(self):
        self.assertFalse(GENESIS.with_nonce(GENESIS.nonce + 1).is_valid_pow())

    def test_mutation_changes_hash(self):
        self.assertNotEqual(GENESIS.hash(), GENESIS.with_timestamp(1231006506).hash())

    def test_explicit_target_overrides_bits(self):
        self.assertTrue(GENESIS.is_valid_pow(target=2 ** 255))
        self.assertFalse(GENESIS.is_valid_pow(target=1))

    def test_immutability(self):
        rolled = GENESIS.with_nonce(1)
        self.assertEqual(GENESIS.nonce, 2083236893)
        self.assertEqual(rolled.nonce, 1)


if __name__ == "__main__":
    unittest.main()
