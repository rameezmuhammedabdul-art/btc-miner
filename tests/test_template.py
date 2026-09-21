import unittest

from btcminer.hashing import sha256d
from btcminer.merkle import merkle_root
from btcminer.template import BlockTemplate, Coinbase, block_subsidy, encode_height, varint


class TestSubsidy(unittest.TestCase):
    def test_halving_schedule(self):
        self.assertEqual(block_subsidy(0), 50 * 10 ** 8)
        self.assertEqual(block_subsidy(209_999), 50 * 10 ** 8)
        self.assertEqual(block_subsidy(210_000), 25 * 10 ** 8)
        self.assertEqual(block_subsidy(630_000), 625_000_000)
        self.assertEqual(block_subsidy(840_000), 312_500_000)

    def test_subsidy_eventually_zero(self):
        self.assertEqual(block_subsidy(210_000 * 64), 0)
        self.assertEqual(block_subsidy(210_000 * 100), 0)


class TestEncoding(unittest.TestCase):
    def test_varint_boundaries(self):
        self.assertEqual(varint(0), b"\x00")
        self.assertEqual(varint(0xFC), b"\xfc")
        self.assertEqual(varint(0xFD), b"\xfd\xfd\x00")
        self.assertEqual(varint(0x10000), b"\xfe\x00\x00\x01\x00")
        self.assertEqual(varint(0x100000000), b"\xff" + (0x100000000).to_bytes(8, "little"))

    def test_bip34_height_encoding(self):
        # The canonical example from BIP34 itself: height 227,836.
        self.assertEqual(encode_height(227836).hex(), "03fc7903")
        self.assertEqual(encode_height(1).hex(), "0101")

    def test_height_keeps_sign_bit_clear(self):
        self.assertEqual(encode_height(0x80).hex(), "028000")

    def test_negative_height_rejected(self):
        with self.assertRaises(ValueError):
            encode_height(-1)


class TestCoinbase(unittest.TestCase):
    def setUp(self):
        self.coinbase = Coinbase(height=900_000, value=block_subsidy(900_000),
                                 script_pubkey=b"\x6a\x04test")

    def test_serialization_shape(self):
        raw = self.coinbase.serialize()
        self.assertEqual(raw[:4], b"\x01\x00\x00\x00")       # version 1
        self.assertEqual(raw[4], 1)                           # one input
        self.assertEqual(raw[5:37], bytes(32))                # null outpoint
        self.assertEqual(raw[37:41], b"\xff\xff\xff\xff")     # outpoint index -1
        self.assertEqual(raw[-4:], b"\x00\x00\x00\x00")       # locktime

    def test_txid_is_double_sha(self):
        self.assertEqual(self.coinbase.txid(), sha256d(self.coinbase.serialize()))

    def test_extranonce_changes_txid(self):
        self.assertNotEqual(self.coinbase.txid(), self.coinbase.with_extranonce(1).txid())

    def test_script_sig_starts_with_height(self):
        self.assertTrue(self.coinbase.script_sig().startswith(encode_height(900_000)))


class TestBlockTemplate(unittest.TestCase):
    def test_root_is_coinbase_txid_when_alone(self):
        template = BlockTemplate.demo()
        self.assertEqual(template.merkle_root(), template.coinbase.txid())

    def test_root_covers_other_transactions(self):
        template = BlockTemplate.demo()
        template.txids = [sha256d(b"tx1"), sha256d(b"tx2")]
        self.assertEqual(
            template.merkle_root(), merkle_root([template.coinbase.txid()] + template.txids)
        )

    def test_header_matches_template_fields(self):
        template = BlockTemplate.demo(height=800_000, bits=0x1D00FFFF)
        header = template.header(timestamp=1_700_000_000)
        self.assertEqual(header.prev_hash, template.prev_hash)
        self.assertEqual(header.merkle_root, template.merkle_root())
        self.assertEqual(header.bits, 0x1D00FFFF)
        self.assertEqual(header.timestamp, 1_700_000_000)
        self.assertEqual(header.nonce, 0)

    def test_rolling_extranonce_gives_a_new_search_space(self):
        template = BlockTemplate.demo()
        rolled = template.roll_extranonce(7)
        self.assertNotEqual(template.merkle_root(), rolled.merkle_root())
        self.assertEqual(template.height, rolled.height)
        self.assertEqual(template.prev_hash, rolled.prev_hash)

    def test_demo_reward_is_unspendable(self):
        # OP_RETURN output: nobody should mistake the demo for a real payout.
        self.assertEqual(BlockTemplate.demo().coinbase.script_pubkey[0], 0x6A)


if __name__ == "__main__":
    unittest.main()
