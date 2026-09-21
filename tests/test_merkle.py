import hashlib
import unittest

from btcminer.hashing import hash_to_hex, hex_to_hash, sha256d
from btcminer.merkle import merkle_branch, merkle_root, merkle_root_from_branch

# Block 170: the coinbase plus the first person-to-person payment ever made.
BLOCK_170_TXIDS = [
    hex_to_hash("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"),
    hex_to_hash("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"),
]
BLOCK_170_ROOT = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"


def fake_txids(count):
    return [hashlib.sha256(f"tx{i}".encode()).digest() for i in range(count)]


class TestMerkleRoot(unittest.TestCase):
    def test_real_block_170(self):
        self.assertEqual(hash_to_hex(merkle_root(BLOCK_170_TXIDS)), BLOCK_170_ROOT)

    def test_single_transaction_is_its_own_root(self):
        only = fake_txids(1)
        self.assertEqual(merkle_root(only), only[0])

    def test_odd_level_duplicates_last_hash(self):
        a, b, c = fake_txids(3)
        expected = sha256d(sha256d(a + b) + sha256d(c + c))
        self.assertEqual(merkle_root([a, b, c]), expected)

    def test_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            merkle_root([])

    def test_order_matters(self):
        txids = fake_txids(4)
        self.assertNotEqual(merkle_root(txids), merkle_root(list(reversed(txids))))

    def test_input_is_not_mutated(self):
        txids = fake_txids(3)
        merkle_root(txids)
        self.assertEqual(len(txids), 3)


class TestMerkleBranch(unittest.TestCase):
    def test_branch_reproduces_root(self):
        for count in range(1, 18):
            txids = fake_txids(count)
            with self.subTest(count=count):
                self.assertEqual(
                    merkle_root_from_branch(txids[0], merkle_branch(txids)),
                    merkle_root(txids),
                )

    def test_branch_length_is_tree_depth(self):
        self.assertEqual(len(merkle_branch(fake_txids(1))), 0)
        self.assertEqual(len(merkle_branch(fake_txids(2))), 1)
        self.assertEqual(len(merkle_branch(fake_txids(5))), 3)

    def test_real_block_170_branch(self):
        branch = merkle_branch(BLOCK_170_TXIDS)
        self.assertEqual(
            hash_to_hex(merkle_root_from_branch(BLOCK_170_TXIDS[0], branch)), BLOCK_170_ROOT
        )

    def test_branch_nodes_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            merkle_root_from_branch(fake_txids(1)[0], [b"\x00" * 31])

    def test_changing_coinbase_changes_root(self):
        txids = fake_txids(4)
        branch = merkle_branch(txids)
        other = hashlib.sha256(b"different coinbase").digest()
        self.assertNotEqual(
            merkle_root_from_branch(txids[0], branch), merkle_root_from_branch(other, branch)
        )


if __name__ == "__main__":
    unittest.main()
