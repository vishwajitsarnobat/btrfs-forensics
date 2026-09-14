# utils/chunk_parser.py
# Parses Btrfs chunk mapping data to translate logical → physical addresses.
#
# Two sources of chunk data:
#   1. sys_chunk_array in the superblock (bootstrap — SYSTEM chunks only)
#   2. The chunk tree on disk (contains ALL chunks including DATA and METADATA)
#
# Reference: https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html

import struct
from .constants import (
    SB_SYS_CHUNK_ARRAY_SIZE, SB_SYS_CHUNK_ARRAY,
    BTRFS_CHUNK_ITEM_KEY,
    CHUNK_ITEM_TYPE_OFFSET,
    BTRFS_BLOCK_GROUP_DATA,
    SUPERBLOCK_OFFSET,
    NODE_HEADER_SIZE, ITEM_POINTER_SIZE,
    NH_LEVEL, NH_NRITEMS,
)


def parse_chunk_map(raw_sb):
    """
    Parses the sys_chunk_array inside the Btrfs superblock.
    Returns a list of dictionaries mapping Logical → Physical addresses.

    This only contains SYSTEM chunks (enough to bootstrap reading the
    chunk tree itself).
    """
    chunk_map = []

    array_size = struct.unpack_from("<I", raw_sb, SB_SYS_CHUNK_ARRAY_SIZE)[0]

    pointer = SB_SYS_CHUNK_ARRAY          # 0x32B = 811
    end_pointer = pointer + array_size

    while pointer < end_pointer:
        if pointer + 17 > len(raw_sb):
            break

        key_data = raw_sb[pointer:pointer + 17]
        obj_id, item_type, logical_start = struct.unpack("<QBQ", key_data)
        pointer += 17

        if item_type != BTRFS_CHUNK_ITEM_KEY:
            break

        if pointer + 48 > len(raw_sb):
            break

        chunk_header = raw_sb[pointer:pointer + 48]
        chunk_length = struct.unpack_from("<Q", chunk_header, 0)[0]
        chunk_type    = struct.unpack_from("<Q", chunk_header, CHUNK_ITEM_TYPE_OFFSET)[0]
        num_stripes = struct.unpack_from("<H", chunk_header, 44)[0]
        pointer += 48

        for s in range(num_stripes):
            if pointer + 32 > len(raw_sb):
                break

            stripe_data = raw_sb[pointer:pointer + 32]
            physical_start = struct.unpack_from("<Q", stripe_data, 8)[0]
            pointer += 32

            chunk_map.append({
                "logical_start":  logical_start,
                "logical_end":    logical_start + chunk_length,
                "physical_start": physical_start,
                "chunk_length":   chunk_length,
                "type":           chunk_type,
            })

    return chunk_map


def parse_chunk_tree(image_path, chunk_tree_logical, nodesize, bootstrap_map):
    """
    Reads the chunk tree from disk to get the FULL chunk map
    (including DATA and METADATA chunks not in sys_chunk_array).

    Args:
        image_path:          Path to the raw disk image
        chunk_tree_logical:  Logical address of chunk tree root (from superblock)
        nodesize:            Node size in bytes
        bootstrap_map:       The bootstrap chunk map from sys_chunk_array

    Returns:
        A complete chunk map list covering all chunk types.
    """
    full_map = list(bootstrap_map)  # start with bootstrap entries

    # Translate the chunk tree root's logical address to physical
    phys_addr = translate_logical_to_physical(chunk_tree_logical, bootstrap_map)
    if phys_addr is None:
        print("    [!] Could not locate chunk tree root on disk!")
        return full_map

    with open(image_path, "rb") as f:
        # Recursively walk the chunk tree
        _walk_chunk_tree_node(f, phys_addr, nodesize, full_map)

    # Deduplicate: prefer entries we found in the chunk tree over bootstrap
    # (they should be identical, but just in case)
    return _deduplicate_chunks(full_map)


def _walk_chunk_tree_node(f, phys_offset, nodesize, chunk_map):
    """
    Recursively walk a chunk tree node (internal or leaf) and extract
    CHUNK_ITEM entries into chunk_map.
    """
    f.seek(phys_offset)
    header = f.read(NODE_HEADER_SIZE)
    if len(header) < NODE_HEADER_SIZE:
        return

    level = header[NH_LEVEL]
    nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]

    if level == 0:
        # Leaf node — parse items for CHUNK_ITEM entries
        _parse_chunk_leaf(f, phys_offset, nodesize, nritems, chunk_map)
    else:
        # Internal node — follow key pointers recursively
        # Each key_ptr: btrfs_disk_key(17) + block_number(8) + generation(8) = 33
        for i in range(nritems):
            ptr_offset = phys_offset + NODE_HEADER_SIZE + (i * 33)
            f.seek(ptr_offset)
            ptr_data = f.read(33)
            if len(ptr_data) < 33:
                break

            # key = ptr_data[0:17]
            child_logical = struct.unpack_from("<Q", ptr_data, 17)[0]

            # Translate the child's logical address using what we have so far
            child_phys = translate_logical_to_physical(child_logical, chunk_map)
            if child_phys is not None:
                _walk_chunk_tree_node(f, child_phys, nodesize, chunk_map)


def _parse_chunk_leaf(f, node_offset, nodesize, nritems, chunk_map):
    """
    Parse a leaf node from the chunk tree.  Extract CHUNK_ITEM entries.

    Each leaf item:
        btrfs_disk_key (17 bytes): objectid(8) + type(1) + offset(8)
        data_offset (4 bytes): offset of data relative to end of header
        data_size (4 bytes)
    """
    for i in range(nritems):
        item_offset = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(item_offset)
        item_raw = f.read(ITEM_POINTER_SIZE)
        if len(item_raw) < ITEM_POINTER_SIZE:
            break

        key_raw, data_offset, data_size = struct.unpack("<17sII", item_raw)
        obj_id = struct.unpack_from("<Q", key_raw, 0)[0]
        item_type = key_raw[8]
        logical_start = struct.unpack_from("<Q", key_raw, 9)[0]  # key offset = logical addr

        if item_type != BTRFS_CHUNK_ITEM_KEY:
            continue

        # Read the CHUNK_ITEM data
        abs_data_offset = node_offset + NODE_HEADER_SIZE + data_offset
        f.seek(abs_data_offset)

        if data_size < 48:
            continue

        chunk_data = f.read(data_size)
        if len(chunk_data) < 48:
            continue

        chunk_length = struct.unpack_from("<Q", chunk_data, 0)[0]
        chunk_type    = struct.unpack_from("<Q", chunk_data, CHUNK_ITEM_TYPE_OFFSET)[0]
        num_stripes = struct.unpack_from("<H", chunk_data, 44)[0]

        # Read stripes
        stripe_offset = 48
        for s in range(num_stripes):
            if stripe_offset + 32 > len(chunk_data):
                break

            physical_start = struct.unpack_from("<Q", chunk_data, stripe_offset + 8)[0]
            stripe_offset += 32

            chunk_map.append({
                "logical_start":  logical_start,
                "logical_end":    logical_start + chunk_length,
                "physical_start": physical_start,
                "chunk_length":   chunk_length,
                "type":           chunk_type,
            })


def _deduplicate_chunks(chunk_map):
    """Remove duplicate chunk entries (same logical_start and physical_start)."""
    seen = set()
    deduped = []
    for c in chunk_map:
        key = (c["logical_start"], c["physical_start"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return deduped


def build_scan_regions(chunk_map, nodesize, image_size, include_data=False):
    """
    Compute the physical byte ranges that may contain B-tree nodes.

    Btrfs only ever allocates metadata nodes inside METADATA or SYSTEM block
    groups. However, chunks can be relocated or removed (balance, shrink),
    leaving old metadata blocks in *unmapped* physical space. So the candidate
    space is:

        [boot_end, image_size)  minus  DATA-chunk physical ranges

    The boot region (first 64 KiB, reserved by Btrfs) is never written and is
    skipped, matching the legacy sweep start.

    Args:
        chunk_map:      list of chunk dicts with physical_start/chunk_length/type
        nodesize:       B-tree node size
        image_size:     total image size in bytes
        include_data:   if True, DATA chunks are also scanned (paranoid mode)

    Returns:
        List of (start, end) physical ranges, node-size aligned, sorted and
        merged. Scanning only these ranges finds exactly the same nodes as a
        full-image sweep (verified by tests).
    """
    boot_end = SUPERBLOCK_OFFSET + nodesize

    # Intervals that provably cannot contain metadata nodes.
    excluded = [(0, boot_end)]
    if not include_data:
        for c in chunk_map:
            if (c.get("type", 0) & 0x7) == BTRFS_BLOCK_GROUP_DATA:
                excluded.append((c["physical_start"],
                                 c["physical_start"] + c["chunk_length"]))

    # Candidate = [boot_end, image_size) minus excluded intervals.
    excluded.sort()
    regions = []
    cursor = boot_end
    for start, end in excluded:
        if end <= cursor:
            continue
        if start > cursor and start < image_size:
            regions.append((cursor, min(start, image_size)))
        cursor = max(cursor, end)
    if cursor < image_size:
        regions.append((cursor, image_size))

    # Snap to node boundaries and drop empty intervals.
    aligned = []
    for start, end in regions:
        start = ((start + nodesize - 1) // nodesize) * nodesize
        end = (end // nodesize) * nodesize
        if start < end:
            aligned.append((start, end))
    return aligned


def translate_logical_to_physical(logical_addr, chunk_map):
    """
    Translates a logical (virtual) address to a physical byte offset
    on the block device using the chunk map.

    Returns None if the address is not covered by any mapped chunk.
    """
    for chunk in chunk_map:
        if chunk["logical_start"] <= logical_addr < chunk["logical_end"]:
            offset_inside_chunk = logical_addr - chunk["logical_start"]
            return chunk["physical_start"] + offset_inside_chunk

    return None
