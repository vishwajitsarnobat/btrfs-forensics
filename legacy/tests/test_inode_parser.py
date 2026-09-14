# tests/test_inode_parser.py
# Unit tests for the inode_parser module.

import unittest
import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.inode_parser import parse_inode_item


class TestParseInodeItem(unittest.TestCase):
    """Test btrfs_inode_item parsing with hand-crafted 160-byte fixtures."""

    def _make_inode(self, **overrides):
        """
        Build a 160-byte btrfs_inode_item matching the on-disk layout.

        Layout (from inode_parser.py):
            0x00  8  generation
            0x08  8  transid
            0x10  8  size
            0x18  8  nbytes
            0x20  8  block_group
            0x28  4  nlink
            0x2C  4  uid
            0x30  4  gid
            0x34  4  mode
            0x38  8  rdev
            0x40  8  flags
            0x48  8  sequence
            0x50 12  atime (sec:8 + nsec:4)
            0x5C 12  ctime (sec:8 + nsec:4)
            0x68 12  mtime (sec:8 + nsec:4)
            0x74 12  otime (sec:8 + nsec:4)
            0x80 32  reserved
            Total: 0xA0 = 160 bytes
        """
        defaults = {
            "generation": 10, "transid": 10, "size": 1024, "nbytes": 1024,
            "block_group": 0, "nlink": 1, "uid": 1000, "gid": 1000,
            "mode": 0o100644, "rdev": 0, "flags": 0, "sequence": 1,
            "atime_sec": 1700000000, "atime_nsec": 123456789,
            "ctime_sec": 1700000000, "ctime_nsec": 123456789,
            "mtime_sec": 1700000000, "mtime_nsec": 123456789,
            "otime_sec": 1700000000, "otime_nsec": 123456789,
        }
        defaults.update(overrides)
        d = defaults

        # Build exactly 160 bytes matching the parser's struct offsets
        buf = bytearray(160)
        struct.pack_into("<Q", buf, 0x00, d["generation"])
        struct.pack_into("<Q", buf, 0x08, d["transid"])
        struct.pack_into("<Q", buf, 0x10, d["size"])
        struct.pack_into("<Q", buf, 0x18, d["nbytes"])
        struct.pack_into("<Q", buf, 0x20, d["block_group"])
        struct.pack_into("<I", buf, 0x28, d["nlink"])
        struct.pack_into("<I", buf, 0x2C, d["uid"])
        struct.pack_into("<I", buf, 0x30, d["gid"])
        struct.pack_into("<I", buf, 0x34, d["mode"])
        struct.pack_into("<Q", buf, 0x38, d["rdev"])
        struct.pack_into("<Q", buf, 0x40, d["flags"])
        struct.pack_into("<Q", buf, 0x48, d["sequence"])
        # Timestamps use signed sec (q) + unsigned nsec (I)
        struct.pack_into("<qI", buf, 0x50, d["atime_sec"], d["atime_nsec"])
        struct.pack_into("<qI", buf, 0x5C, d["ctime_sec"], d["ctime_nsec"])
        struct.pack_into("<qI", buf, 0x68, d["mtime_sec"], d["mtime_nsec"])
        struct.pack_into("<qI", buf, 0x74, d["otime_sec"], d["otime_nsec"])
        # 0x80..0x9F = reserved (already zero)
        return bytes(buf)

    def test_basic_parse(self):
        """Parse a well-formed inode item and check basic fields."""
        data = self._make_inode(size=4096, nlink=2, uid=1000, gid=1000)
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertEqual(result["size"], 4096)
        self.assertEqual(result["nlink"], 2)
        self.assertEqual(result["uid"], 1000)
        self.assertEqual(result["gid"], 1000)
        self.assertEqual(result["mode"], 0o100644)

    def test_timestamps(self):
        """Verify timestamp parsing produces valid ISO strings."""
        data = self._make_inode(mtime_sec=1700000000, mtime_nsec=500000000)
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertEqual(result["mtime"]["sec"], 1700000000)
        self.assertEqual(result["mtime"]["nsec"], 500000000)
        self.assertIn("2023", result["mtime"]["iso"])  # 1700000000 is Nov 2023

    def test_zero_size_file(self):
        """Parse inode with size=0 (empty file)."""
        data = self._make_inode(size=0, nlink=1)
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertEqual(result["size"], 0)

    def test_directory_mode(self):
        """Parse inode with directory mode."""
        data = self._make_inode(mode=0o040755)
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertEqual(result["mode"], 0o040755)

    def test_short_data_returns_none(self):
        """Parsing truncated data should return None."""
        data = b"\x00" * 100  # only 100 bytes, need 160
        result = parse_inode_item(data)
        self.assertIsNone(result)

    def test_zero_timestamps(self):
        """Inodes with sec=0 should produce epoch timestamps."""
        data = self._make_inode(
            atime_sec=0, atime_nsec=0,
            ctime_sec=0, ctime_nsec=0,
            mtime_sec=0, mtime_nsec=0,
            otime_sec=0, otime_nsec=0,
        )
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertEqual(result["mtime"]["sec"], 0)
        self.assertIn("1970", result["mtime"]["iso"])

    def test_large_timestamp(self):
        """Inodes with unreasonably large timestamps should be marked invalid."""
        # Use a value that overflows datetime but fits in int64
        data = self._make_inode(otime_sec=2**62)
        result = parse_inode_item(data)

        self.assertIsNotNone(result)
        self.assertIn("invalid", result["otime"]["iso"])

    def test_all_fields_present(self):
        """All expected fields should be present in result."""
        data = self._make_inode()
        result = parse_inode_item(data)

        expected_keys = {
            "generation", "transid", "size", "nbytes", "block_group",
            "nlink", "uid", "gid", "mode", "rdev", "flags", "sequence",
            "atime", "ctime", "mtime", "otime",
        }
        self.assertEqual(set(result.keys()), expected_keys)


if __name__ == "__main__":
    unittest.main()
