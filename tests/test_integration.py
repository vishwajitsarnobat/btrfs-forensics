# tests/test_integration.py
# Integration test: run the full pipeline against sandbox.img.

import unittest
import json
import os
import shutil
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SANDBOX_IMG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sandbox.img"
)
TEST_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_output_integration"
)


@unittest.skipUnless(os.path.exists(SANDBOX_IMG),
                     "sandbox.img not found — skipping integration test")
class TestFullPipeline(unittest.TestCase):
    """Run the full recovery pipeline against the sandbox image."""

    @classmethod
    def setUpClass(cls):
        """Run the pipeline once for all tests."""
        if os.path.exists(TEST_OUTPUT):
            shutil.rmtree(TEST_OUTPUT)

        from utils.superblock import parse_superblock
        from utils.btree import sweep_for_orphans
        from utils.recovery_report import RecoveryReport

        os.makedirs(TEST_OUTPUT, exist_ok=True)
        cls.report = RecoveryReport(TEST_OUTPUT)
        cls.sb_data = parse_superblock(SANDBOX_IMG)
        cls.inode_map = sweep_for_orphans(
            SANDBOX_IMG, cls.sb_data, cls.report,
            output_dir=TEST_OUTPUT, scan_current_gen=True
        )
        cls.report.save_json_report()

        # Load the JSON report
        report_path = os.path.join(TEST_OUTPUT, "recovery_report.json")
        with open(report_path) as f:
            cls.json_report = json.load(f)

    @classmethod
    def tearDownClass(cls):
        """Clean up test output."""
        if os.path.exists(TEST_OUTPUT):
            shutil.rmtree(TEST_OUTPUT)

    def test_superblock_parsed(self):
        """Superblock should parse successfully."""
        self.assertIsNotNone(self.sb_data)
        self.assertIn("fsid", self.sb_data)
        self.assertIn("generation", self.sb_data)
        self.assertIn("nodesize", self.sb_data)
        self.assertEqual(self.sb_data["nodesize"], 16384)

    def test_orphan_nodes_found(self):
        """Should find orphaned nodes."""
        self.assertGreater(self.report.orphan_nodes_found, 0)

    def test_no_false_positive_checksums(self):
        """All legitimate nodes should pass CRC32c validation.
        At most a tiny number of checksum failures from data blocks
        that happen to contain the FSID bytes."""
        self.assertLessEqual(self.report.checksum_failures, 5)

    def test_recovered_files(self):
        """Should recover at least one inline and one regular extent."""
        self.assertGreaterEqual(self.report.inline_files_recovered, 1)
        self.assertGreaterEqual(self.report.regular_extents_recovered, 1)

    def test_target_file_recovered(self):
        """The inline 'target_file.txt' should be recovered."""
        inline_path = os.path.join(
            TEST_OUTPUT, "target_file.txt_gen11_valid_inline.bin"
        )
        self.assertTrue(os.path.exists(inline_path))
        with open(inline_path, "rb") as f:
            content = f.read()
        self.assertEqual(len(content), 31)

    def test_large_target_recovered(self):
        """The regular extent 'large_target.txt' should be recovered."""
        extent_path = os.path.join(
            TEST_OUTPUT, "large_target.txt_gen13_valid_extent.bin"
        )
        self.assertTrue(os.path.exists(extent_path))
        with open(extent_path, "rb") as f:
            content = f.read()
        self.assertEqual(len(content), 5242880)  # 5 MiB

    def test_deduplication(self):
        """Only 1 extent file should be written (not 4 duplicates)."""
        extent_files = [
            f for f in os.listdir(TEST_OUTPUT)
            if "extent.bin" in f
        ]
        self.assertEqual(len(extent_files), 1)

    def test_leaf_slacks_found(self):
        """Should find leaf slack regions."""
        self.assertGreater(self.report.leaf_slacks_found, 0)

    def test_inode_metadata(self):
        """Should recover inode metadata."""
        self.assertGreater(len(self.report.inode_metadata), 0)

    def test_json_report_valid(self):
        """JSON report should contain expected top-level keys."""
        self.assertIn("stats", self.json_report)
        self.assertIn("recovered_files", self.json_report)
        self.assertIn("inode_metadata", self.json_report)
        self.assertIn("extent_backrefs", self.json_report)
        self.assertIn("orphan_child_ptrs", self.json_report)
        self.assertIn("move_artifacts", self.json_report)
        self.assertIn("device_info", self.json_report)

    def test_json_numeric_types(self):
        """Numeric values in metadata should remain numeric, not strings."""
        for key, meta in self.json_report["inode_metadata"].items():
            self.assertIsInstance(meta["size"], int)
            self.assertIsInstance(meta["nlink"], int)
            if meta.get("mtime"):
                self.assertIsInstance(meta["mtime"]["sec"], int)
                self.assertIsInstance(meta["mtime"]["nsec"], int)


if __name__ == "__main__":
    unittest.main()
