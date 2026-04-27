# main.py
# Btrfs Deleted File Recovery Tool — Brute-Force Scanner
#
# Scans a raw Btrfs disk image for orphaned CoW nodes and recovers
# deleted file data (inline extents and regular extents).
#
# Based on:
#   - "Forensic analysis of B-tree file system (Btrfs)" (Bhat & Wani, 2018)
#   - "Anti-forensic capabilities of B-tree file system" (Wani et al., 2020)

import argparse
import os
import sys

from utils.superblock import parse_superblock
from utils.btree import sweep_for_orphans
from utils.recovery_report import RecoveryReport


def run_recovery_engine(image_file, output_dir, scan_current_gen=True):
    """
    Main recovery pipeline:
        1. Parse the superblock to get filesystem metadata & chunk map
        2. Brute-force sweep for orphaned B-tree nodes
        3. Extract inline data and regular extents
        4. Generate recovery report
    """
    # Validate the image file exists
    if not os.path.isfile(image_file):
        print(f"[!] Error: Image file '{image_file}' not found.")
        return

    file_size = os.path.getsize(image_file)
    print(f"[*] Image: {image_file} ({file_size / (1024*1024):.1f} MiB)")
    print()

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Initialize the recovery report
    report = RecoveryReport(output_dir)

    # ── Stage 1: Superblock Analysis ──
    sb_data = parse_superblock(image_file)
    if not sb_data:
        print("[!] Aborting: Could not establish filesystem state.")
        return

    # ── Stage 2 & 3: Node Sweep + Orphan-Item Analysis + Extraction ──
    inode_map = sweep_for_orphans(image_file, sb_data, report,
                                  scan_current_gen=scan_current_gen)

    # ── Stage 4: Report ──
    report.print_summary()
    report.save_json_report()


def main():
    parser = argparse.ArgumentParser(
        description="Btrfs Deleted File Recovery Tool (Brute-Force Scanner)",
        epilog="Example: python main.py sandbox.img -o recovered_files/",
    )
    parser.add_argument(
        "image",
        nargs="?",
        default="sandbox.img",
        help="Path to the raw Btrfs disk image (default: sandbox.img)",
    )
    parser.add_argument(
        "-o", "--output",
        default="recovery_output",
        help="Output directory for recovered files (default: recovery_output)",
    )
    parser.add_argument(
        "--no-current-gen",
        action="store_true",
        help="Skip scanning current-generation nodes for Orphan-Items",
    )

    args = parser.parse_args()

    # Update the btree module's output directory
    import utils.btree as btree_module
    btree_module.OUTPUT_DIR = args.output

    run_recovery_engine(
        image_file=args.image,
        output_dir=args.output,
        scan_current_gen=not args.no_current_gen,
    )


if __name__ == "__main__":
    main()
