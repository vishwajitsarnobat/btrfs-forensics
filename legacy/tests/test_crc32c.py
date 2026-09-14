# tests/test_crc32c.py
# Verify the pure-Python CRC32c implementation against known test vectors.

import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crc32c import crc32c


class TestCRC32c(unittest.TestCase):
    """Test CRC32c (Castagnoli) against known test vectors."""

    def test_empty(self):
        """CRC32c of empty data should be 0x00000000."""
        self.assertEqual(crc32c(b""), 0x00000000)

    def test_zeros_32(self):
        """CRC32c of 32 zero bytes."""
        self.assertEqual(crc32c(b"\x00" * 32), 0x8A9136AA)

    def test_ones_32(self):
        """CRC32c of 32 0xFF bytes."""
        self.assertEqual(crc32c(b"\xff" * 32), 0x62A8AB43)

    def test_incrementing_32(self):
        """CRC32c of bytes 0x00..0x1F (32 incrementing bytes)."""
        data = bytes(range(32))
        self.assertEqual(crc32c(data), 0x46DD794E)

    def test_decrementing_32(self):
        """CRC32c of bytes 0x1F..0x00 (32 decrementing bytes)."""
        data = bytes(range(31, -1, -1))
        self.assertEqual(crc32c(data), 0x113FDB5C)

    def test_canonical_vector(self):
        """CRC32c of '123456789' — the canonical SCTP/iSCSI test vector."""
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_single_byte(self):
        """CRC32c of a single byte is a valid 32-bit value."""
        result = crc32c(b"\x01")
        self.assertIsInstance(result, int)
        self.assertTrue(0 <= result <= 0xFFFFFFFF)

    def test_deterministic(self):
        """Same input always produces same output."""
        data = b"btrfs forensics crc32c test"
        self.assertEqual(crc32c(data), crc32c(data))


if __name__ == "__main__":
    unittest.main()
