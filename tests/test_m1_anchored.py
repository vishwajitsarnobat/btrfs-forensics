# tests/test_m1_anchored.py
# M1: superblock backup roots + anchored historical walking.
#
# Verifies that the 4 backup-root entries are parsed and CRC-validated, that
# the historical fs trees they reference are walked into file inventories,
# and that sweep-recovered artifacts get anchored provenance.

import unittest
import os
import shutil
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.superblock import parse_superblock
from utils.backup_roots import parse_backup_roots
from utils.anchored_walk import (
    get_current_fs_tree_root, collect_fs_tree_state, analyze_historical_states,
)
from utils.btree import sweep_for_orphans
from utils.recovery_report import RecoveryReport

SANDBOX_IMG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sandbox.img"
)
TEST_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_output_m1"
)


@unittest.skipUnless(os.path.exists(SANDBOX_IMG),
                     "sandbox.img not found — skipping integration tests")
class TestBackupRoots(unittest.TestCase):
    """Backup-root parsing and validation on sandbox.img."""

    @classmethod
    def setUpClass(cls):
        cls.sb = parse_superblock(SANDBOX_IMG)
        cls.backups = parse_backup_roots(SANDBOX_IMG, cls.sb)

    def test_four_backup_roots_parsed(self):
        self.assertEqual(len(self.backups), 4)

    def test_all_backup_roots_valid(self):
        for b in self.backups:
            self.assertTrue(b.get("valid_roots"),
                            f"backup at slot 0x{b['slot']:X} has no valid roots")
            self.assertIn("fs_root", b["valid_roots"])
            self.assertIn("tree_root", b["valid_roots"])

    def test_total_bytes_matches_image(self):
        for b in self.backups:
            self.assertEqual(b["total_bytes"], 268435456)

    def test_generations_span_history(self):
        gens = {b["gen"] for b in self.backups}
        self.assertIn(11, gens)
        self.assertIn(13, gens)
        # fs roots must be distinct historical states
        fs_roots = {b["fs_root"] for b in self.backups}
        self.assertEqual(len(fs_roots), 4)

    def test_current_backup_matches_superblock(self):
        # The newest backup's tree_root equals the live root tree address.
        newest = max(self.backups, key=lambda b: b["gen"])
        self.assertEqual(newest["tree_root"], self.sb["root_tree_addr"])


@unittest.skipUnless(os.path.exists(SANDBOX_IMG),
                     "sandbox.img not found — skipping integration tests")
class TestAnchoredWalking(unittest.TestCase):
    """Walking historical fs trees + provenance tagging."""

    @classmethod
    def setUpClass(cls):
        cls.sb = parse_superblock(SANDBOX_IMG)
        cls.out = TEST_OUT
        if os.path.exists(cls.out):
            shutil.rmtree(cls.out)
        os.makedirs(cls.out)

        # Full pipeline: sweep (finds artifacts) then anchored analysis.
        cls.report = RecoveryReport(cls.out)
        sweep_for_orphans(SANDBOX_IMG, cls.sb, cls.report,
                          output_dir=cls.out, scan_current_gen=True)
        cls.backups = parse_backup_roots(SANDBOX_IMG, cls.sb)
        cls.states = analyze_historical_states(
            SANDBOX_IMG, cls.sb, cls.backups, cls.report)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.out):
            shutil.rmtree(cls.out)

    def test_states_walked(self):
        self.assertEqual(len(self.states), 4)

    def test_gen11_state_has_target_file(self):
        state = next(s for s in self.states if s["gen"] == 11)
        ino257 = next(f for f in state["files"] if f["inode"] == 257)
        self.assertEqual(ino257["filename"], "target_file.txt")
        self.assertEqual(ino257["size"], 31)
        self.assertTrue(ino257["has_data"])

    def test_gen13_state_has_large_target(self):
        state = next(s for s in self.states if s["gen"] == 13)
        ino257 = next(f for f in state["files"] if f["inode"] == 257)
        self.assertEqual(ino257["filename"], "large_target.txt")
        self.assertEqual(ino257["size"], 5242880)
        self.assertTrue(ino257["has_data"])

    def test_gen14_state_is_empty_of_files(self):
        # Between gen 13 and gen 14 the file was deleted.
        state = next(s for s in self.states if s["gen"] == 14)
        self.assertEqual(state["file_count"], 1)  # only the root dir inode
        self.assertNotIn(257, [f["inode"] for f in state["files"]])

    def test_deleted_since_detected(self):
        self.assertGreaterEqual(self.report.deleted_since_backup, 2)
        deleted_names = {
            df["filename"] for s in self.states for df in s["deleted_since"]
        }
        self.assertIn("target_file.txt", deleted_names)
        self.assertIn("large_target.txt", deleted_names)

    def test_anchored_provenance_tagged(self):
        self.assertGreaterEqual(self.report.anchored_files_confirmed, 5)
        for entry in self.report.recovered_files:
            self.assertEqual(entry.get("provenance"), "anchored")

    def test_current_fs_tree_discovered(self):
        root = get_current_fs_tree_root(SANDBOX_IMG, self.sb)
        self.assertIsNotNone(root)
        inv = collect_fs_tree_state(SANDBOX_IMG, self.sb, root,
                                    self.sb["generation"])
        self.assertIn(256, inv)  # root dir inode present in live tree


if __name__ == "__main__":
    unittest.main()
