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

    # ── Boot sector extraction (B2) ──
    # The first 64 KiB (0x0000–0xFFFF) is reserved by Btrfs and never written to.
    # It may contain data from a prior filesystem.
    from utils.constants import SUPERBLOCK_OFFSET
    with open(image_file, "rb") as f_boot:
        boot_bytes = f_boot.read(SUPERBLOCK_OFFSET)  # 0x10000 = 65536 bytes

    if any(b != 0 for b in boot_bytes):
        boot_path = os.path.join(output_dir, "boot_sector.bin")
        with open(boot_path, "wb") as bf:
            bf.write(boot_bytes)
        print(f"[+] Boot sector non-zero — saved to {boot_path}")
    else:
        print("[*] Boot sector is all zeros (no pre-filesystem data)")

    # ── Stage 1: Superblock Analysis ──
    sb_data = parse_superblock(image_file)
    if not sb_data:
        print("[!] Aborting: Could not establish filesystem state.")
        return

    # ── Stage 2 & 3: Node Sweep + Orphan-Item Analysis + Extraction ──
    inode_map = sweep_for_orphans(image_file, sb_data, report,
                                  output_dir=output_dir,
                                  scan_current_gen=scan_current_gen)

    # ── Volume slack extraction (D2) ──
    # Bytes after the last node-aligned offset may contain residual data.
    nodesize = sb_data["nodesize"]
    aligned_end = (file_size // nodesize) * nodesize
    if aligned_end < file_size:
        with open(image_file, "rb") as f_vs:
            f_vs.seek(aligned_end)
            vol_slack = f_vs.read(file_size - aligned_end)
        if any(b != 0 for b in vol_slack):
            vs_path = os.path.join(output_dir, "volume_slack.bin")
            with open(vs_path, "wb") as vf:
                vf.write(vol_slack)
            print(f"[+] Volume slack {len(vol_slack)} bytes → {vs_path}")

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

    run_recovery_engine(
        image_file=args.image,
        output_dir=args.output,
        scan_current_gen=not args.no_current_gen,
    )


if __name__ == "__main__":
    main()
