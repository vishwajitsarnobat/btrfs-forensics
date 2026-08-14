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

from utils.superblock import parse_superblock
from utils.btree import sweep_for_orphans
from utils.recovery_report import RecoveryReport
from utils.chunk_parser import build_scan_regions
from utils.orphan_scan import get_live_metadata_blocks
from utils.backup_roots import parse_backup_roots
from utils.anchored_walk import analyze_historical_states


def _region_blocks(regions, nodesize):
    """Number of node-sized blocks covered by a list of (start, end) regions."""
    return sum((end - start) // nodesize for start, end in regions)


def _count_orphans_outside_regions(orphan_offsets, regions):
    """How many recorded orphan offsets fall outside the candidate regions."""
    if not regions:
        return len(orphan_offsets)
    covered = 0
    for off in orphan_offsets:
        for start, end in regions:
            if start <= off < end:
                covered += 1
                break
    return len(orphan_offsets) - covered


def run_recovery_engine(image_file, output_dir, scan_current_gen=True,
                        full_sweep=False, scan_data_chunks=False,
                        scan_anchored=True):
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

    nodesize = sb_data["nodesize"]

    # ── Structure-directed scan planning (M2) ──
    # Candidate regions = METADATA/SYSTEM chunks + unmapped gaps left by
    # relocated/removed chunks, minus the boot region. DATA chunks can never
    # contain metadata nodes, so they are skipped (unless --scan-data-chunks).
    scan_regions = None
    live_metadata_blocks = None
    if not full_sweep:
        scan_regions = build_scan_regions(
            sb_data["chunk_map"], nodesize, file_size,
            include_data=scan_data_chunks)
        live_metadata_blocks, _ = get_live_metadata_blocks(image_file, sb_data)

        report.scan_mode = "targeted"
        report.targeted_blocks_scanned = _region_blocks(scan_regions, nodesize)
        report.full_sweep_blocks = _region_blocks(
            [(SUPERBLOCK_OFFSET + nodesize, file_size)], nodesize)
        report.boot_blocks_skipped = (SUPERBLOCK_OFFSET + nodesize) // nodesize
        report.live_metadata_blocks = len(live_metadata_blocks)
        if not scan_data_chunks:
            report.data_chunk_blocks_skipped = _region_blocks(
                [(c["physical_start"],
                  c["physical_start"] + c["chunk_length"])
                 for c in sb_data["chunk_map"]
                 if (c.get("type", 0) & 0x7) == 0x1],  # DATA
                nodesize)
    else:
        report.scan_mode = "full"
        report.full_sweep_blocks = _region_blocks(
            [(SUPERBLOCK_OFFSET + nodesize, file_size)], nodesize)

    print(f"[*] Scan plan: mode={report.scan_mode}, "
          f"{report.targeted_blocks_scanned or report.full_sweep_blocks} "
          f"candidate block(s) of {report.full_sweep_blocks} total")

    # ── Stage 2 & 3: Node Sweep + Orphan-Item Analysis + Extraction ──
    inode_map = sweep_for_orphans(image_file, sb_data, report,
                                  output_dir=output_dir,
                                  scan_current_gen=scan_current_gen,
                                  scan_regions=scan_regions,
                                  live_metadata_blocks=live_metadata_blocks)

    # ── Coverage check: no orphan may fall outside the candidate regions ──
    # (only meaningful in targeted mode; a full sweep examines every block)
    if scan_regions is not None:
        report.orphans_outside_regions = _count_orphans_outside_regions(
            report.orphan_offsets, scan_regions)
        if report.orphans_outside_regions > 0:
            print(f"[!] {report.orphans_outside_regions} orphaned node(s) fell "
                  "outside the candidate regions — widen the regions "
                  "(--scan-data-chunks) or use --full-sweep.")

    # ── Stage 2b: Anchored historical walking (M1) ──
    # Backup roots preserve whole historical tree states (one per transaction
    # boundary). Walking them confirms recovered artifacts with structural
    # provenance and reveals files deleted since each recorded generation.
    if scan_anchored:
        print("\n[*] Anchored historical analysis (superblock backup roots)...")
        backups = parse_backup_roots(image_file, sb_data)
        analyze_historical_states(image_file, sb_data, backups, report)

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
    parser.add_argument(
        "--full-sweep",
        action="store_true",
        help="Use the legacy full-image linear sweep instead of the "
             "structure-directed targeted scan",
    )
    parser.add_argument(
        "--scan-data-chunks",
        action="store_true",
        help="Include DATA chunk regions in the targeted scan "
             "(paranoid; normally skipped since nodes cannot live there)",
    )
    parser.add_argument(
        "--no-anchored",
        action="store_true",
        help="Skip the anchored historical analysis (superblock backup roots)",
    )

    args = parser.parse_args()

    run_recovery_engine(
        image_file=args.image,
        output_dir=args.output,
        scan_current_gen=not args.no_current_gen,
        full_sweep=args.full_sweep,
        scan_data_chunks=args.scan_data_chunks,
        scan_anchored=not args.no_anchored,
    )


if __name__ == "__main__":
    main()
