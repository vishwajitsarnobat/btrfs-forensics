# tests/test_targeted_scan.py
# M2: structure-directed targeted scan.
#
# Verifies that the targeted scan (candidate regions derived from the typed
# chunk map) finds exactly the same orphaned nodes as the legacy full-image
# sweep, and that no orphan falls outside the candidate regions.

import unittest
import os
import shutil
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.superblock import parse_superblock
from utils.chunk_parser import build_scan_regions
from utils.btree import sweep_for_orphans
from utils.recovery_report import RecoveryReport
from utils.constants import SUPERBLOCK_OFFSET, BTRFS_BLOCK_GROUP_DATA

SANDBOX_IMG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sandbox.img"
)
TEST_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_output_targeted"
)


def _region_blocks(regions, nodesize):
    return sum((end - start) // nodesize for start, end in regions)


class TestRegionBuilder(unittest.TestCase):
    """Unit tests for build_scan_regions."""

    def setUp(self):
        self.sb = parse_superblock(SANDBOX_IMG)
        self.nodesize = self.sb["nodesize"]
        self.image_size = os.path.getsize(SANDBOX_IMG)
        self.regions = build_scan_regions(
            self.sb["chunk_map"], self.nodesize, self.image_size,
            include_data=False)

    def test_regions_node_aligned(self):
        for start, end in self.regions:
            self.assertEqual(start % self.nodesize, 0)
            self.assertEqual(end % self.nodesize, 0)
            self.assertLess(start, end)

    def test_regions_inside_image(self):
        for start, end in self.regions:
            self.assertGreaterEqual(start, SUPERBLOCK_OFFSET + self.nodesize)
            self.assertLessEqual(end, self.image_size)

    def test_no_overlap_with_data_chunks(self):
        data_ranges = [
            (c["physical_start"], c["physical_start"] + c["chunk_length"])
            for c in self.sb["chunk_map"]
            if (c.get("type", 0) & 0x7) == BTRFS_BLOCK_GROUP_DATA
        ]
        self.assertTrue(data_ranges, "expected at least one DATA chunk")
        for rs, re_ in self.regions:
            for ds, de in data_ranges:
                overlap = max(rs, ds) < min(re_, de)
                self.assertFalse(overlap, f"region [{rs:#x},{re_:#x}) overlaps "
                                          f"DATA [{ds:#x},{de:#x})")

    def test_coverage_accounting(self):
        """targeted blocks + skipped DATA blocks == full-sweep blocks."""
        full_blocks = _region_blocks(
            [(SUPERBLOCK_OFFSET + self.nodesize, self.image_size)],
            self.nodesize)
        targeted_blocks = _region_blocks(self.regions, self.nodesize)
        data_blocks = _region_blocks(
            [(c["physical_start"], c["physical_start"] + c["chunk_length"])
             for c in self.sb["chunk_map"]
             if (c.get("type", 0) & 0x7) == BTRFS_BLOCK_GROUP_DATA],
            self.nodesize)
        self.assertEqual(targeted_blocks + data_blocks, full_blocks)

    def test_include_data_flag_adds_blocks(self):
        with_data = build_scan_regions(
            self.sb["chunk_map"], self.nodesize, self.image_size,
            include_data=True)
        self.assertGreater(_region_blocks(with_data, self.nodesize),
                           _region_blocks(self.regions, self.nodesize))


@unittest.skipUnless(os.path.exists(SANDBOX_IMG),
                     "sandbox.img not found — skipping integration tests")
class TestTargetedScanParity(unittest.TestCase):
    """Targeted scan must match the full sweep exactly on sandbox.img."""

    @classmethod
    def setUpClass(cls):
        cls.sb = parse_superblock(SANDBOX_IMG)
        cls.nodesize = cls.sb["nodesize"]
        cls.image_size = os.path.getsize(SANDBOX_IMG)
        cls.regions = build_scan_regions(
            cls.sb["chunk_map"], cls.nodesize, cls.image_size,
            include_data=False)

        cls.out_legacy = TEST_OUT + "_legacy"
        cls.out_targeted = TEST_OUT + "_targeted"
        for d in (cls.out_legacy, cls.out_targeted):
            if os.path.exists(d):
                shutil.rmtree(d)
            os.makedirs(d)

        cls.legacy_report = RecoveryReport(cls.out_legacy)
        cls.targeted_report = RecoveryReport(cls.out_targeted)

        sweep_for_orphans(SANDBOX_IMG, cls.sb, cls.legacy_report,
                          output_dir=cls.out_legacy, scan_current_gen=True,
                          scan_regions=None)
        sweep_for_orphans(SANDBOX_IMG, cls.sb, cls.targeted_report,
                          output_dir=cls.out_targeted, scan_current_gen=True,
                          scan_regions=cls.regions)

    @classmethod
    def tearDownClass(cls):
        for d in (cls.out_legacy, cls.out_targeted):
            if os.path.exists(d):
                shutil.rmtree(d)

    def test_same_orphan_count(self):
        self.assertEqual(self.targeted_report.orphan_nodes_found,
                         self.legacy_report.orphan_nodes_found)

    def test_same_orphan_offsets(self):
        self.assertEqual(set(self.targeted_report.orphan_offsets),
                         set(self.legacy_report.orphan_offsets))

    def test_no_orphans_outside_regions(self):
        def covered(off):
            return any(s <= off < e for s, e in self.regions)
        outside = [o for o in self.targeted_report.orphan_offsets
                   if not covered(o)]
        self.assertEqual(outside, [])

    def test_targeted_recovers_same_files(self):
        legacy_files = {f for f in os.listdir(self.out_legacy)
                        if f.endswith(".bin")}
        targeted_files = {f for f in os.listdir(self.out_targeted)
                          if f.endswith(".bin")}
        # Targeted mode must recover the same recovered files (inline + extent)
        self.assertTrue(any("target_file.txt" in f for f in targeted_files))
        self.assertTrue(any("large_target.txt" in f for f in targeted_files))
        # Every recovered data file in legacy mode should exist in targeted mode
        for f in legacy_files:
            if "extent.bin" in f or "inline.bin" in f:
                self.assertIn(f, targeted_files, f"missing in targeted mode")

    def test_scan_reduction_accounted(self):
        """targeted + skipped DATA blocks == full sweep blocks (boot excluded
        from both by construction)."""
        full_blocks = _region_blocks(
            [(SUPERBLOCK_OFFSET + self.nodesize, self.image_size)],
            self.nodesize)
        targeted_blocks = _region_blocks(self.regions, self.nodesize)
        data_blocks = _region_blocks(
            [(c["physical_start"], c["physical_start"] + c["chunk_length"])
             for c in self.sb["chunk_map"]
             if (c.get("type", 0) & 0x7) == BTRFS_BLOCK_GROUP_DATA],
            self.nodesize)
        self.assertEqual(targeted_blocks + data_blocks, full_blocks)
        # The targeted scan actually examined fewer blocks than the full sweep
        self.assertLess(self.targeted_report.nodes_scanned,
                        self.legacy_report.nodes_scanned)


if __name__ == "__main__":
    unittest.main()
