# utils/superblock.py
# Parses the Btrfs superblock to extract filesystem metadata needed
# for recovery operations.
#
# Reference: https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html#superblock

import struct
import uuid
from .constants import (
    SUPERBLOCK_OFFSET, MAGIC_NUMBER,
    SB_FSID, SB_MAGIC, SB_GENERATION, SB_ROOT_TREE_ADDR,
    SB_CHUNK_TREE_ADDR, SB_TOTAL_BYTES, SB_BYTES_USED,
    SB_SECTORSIZE, SB_NODESIZE, SB_ROOT_LEVEL,
    SB_ROOT_DIR_OBJID,
)
from .chunk_parser import parse_chunk_map, parse_chunk_tree


def parse_superblock(image_path):
    """
    Reads and validates the primary Btrfs superblock (at 64 KiB).

    Returns a dictionary of filesystem metadata or None on failure.
    The returned dict includes the chunk map needed for logical → physical
    address translation.
    """
    print(f"[*] Parsing Superblock for {image_path}...")

    with open(image_path, "rb") as f:
        f.seek(SUPERBLOCK_OFFSET)
        # Read 4096 bytes — enough to cover the entire superblock structure
        # (superblock is 0x1000 = 4096 bytes total)
        raw_sb = f.read(4096)

        if len(raw_sb) < 4096:
            print("[!] Error: File too small to contain a Btrfs Superblock.")
            return None

        # ── Validate magic number ──
        magic = raw_sb[SB_MAGIC:SB_MAGIC + 8]
        if magic != MAGIC_NUMBER:
            print("[!] Error: Not a valid Btrfs Superblock (magic mismatch).")
            return None

        # ── Parse essential fields ──
        raw_fsid      = raw_sb[SB_FSID:SB_FSID + 16]
        fsid          = uuid.UUID(bytes=raw_fsid)
        generation    = struct.unpack_from("<Q", raw_sb, SB_GENERATION)[0]
        root_tree_addr= struct.unpack_from("<Q", raw_sb, SB_ROOT_TREE_ADDR)[0]
        chunk_tree_addr=struct.unpack_from("<Q", raw_sb, SB_CHUNK_TREE_ADDR)[0]
        total_bytes   = struct.unpack_from("<Q", raw_sb, SB_TOTAL_BYTES)[0]
        bytes_used    = struct.unpack_from("<Q", raw_sb, SB_BYTES_USED)[0]
        root_dir_objid= struct.unpack_from("<Q", raw_sb, SB_ROOT_DIR_OBJID)[0]
        sectorsize    = struct.unpack_from("<I", raw_sb, SB_SECTORSIZE)[0]
        nodesize      = struct.unpack_from("<I", raw_sb, SB_NODESIZE)[0]
        root_level    = raw_sb[SB_ROOT_LEVEL]

        # ── Build the Chunk Map from sys_chunk_array (bootstrap) ──
        bootstrap_map = parse_chunk_map(raw_sb)

        # ── Parse the full chunk tree for DATA/METADATA chunks ──
        print(f"    - Bootstrap Chunks: {len(bootstrap_map)}")
        chunk_map = parse_chunk_tree(image_path, chunk_tree_addr, nodesize,
                                     bootstrap_map)

        # ── Display ──
        print("[+] Superblock Parsed Successfully!")
        print(f"    - FSID:             {fsid}")
        print(f"    - Generation:       {generation}")
        print(f"    - Node Size:        {nodesize} bytes")
        print(f"    - Sector Size:      {sectorsize} bytes")
        print(f"    - Total Size:       {total_bytes / (1024*1024):.1f} MiB")
        print(f"    - Bytes Used:       {bytes_used / (1024*1024):.2f} MiB")
        print(f"    - Root Tree Addr:   0x{root_tree_addr:X} (logical)")
        print(f"    - Chunk Tree Addr:  0x{chunk_tree_addr:X} (logical)")
        print(f"    - Root Level:       {root_level}")
        print(f"    - Root Dir ObjID:   {root_dir_objid}")
        print(f"    - Total Chunks:     {len(chunk_map)}\n")

        return {
            "fsid":             raw_fsid,
            "generation":       generation,
            "nodesize":         nodesize,
            "sectorsize":       sectorsize,
            "total_bytes":      total_bytes,
            "bytes_used":       bytes_used,
            "root_tree_addr":   root_tree_addr,
            "chunk_tree_addr":  chunk_tree_addr,
            "root_dir_objid":   root_dir_objid,
            "root_level":       root_level,
            "chunk_map":        chunk_map,
        }

