# utils/btree.py
# Brute-force scanner for Btrfs B-tree nodes.
#
# Strategy (per Paper 2 — Bhat & Wani, 2018):
#   1. Scan the raw image for node-sized blocks that match the FS UUID.
#   2. For orphaned nodes (generation < superblock generation), parse all
#      valid items (items within nritems).
#   3. Also scan for Orphan-Items — items beyond nritems that are remnants
#      of B-tree redistribution/merging and may reference deleted files.
#   4. Build an inode→filename map from DIR_ITEM, DIR_INDEX, and INODE_REF items.
#   5. Extract inline file data directly; for regular extents, translate
#      logical→physical addresses via the chunk map and read the data.

import struct
import os
from .constants import (
    SUPERBLOCK_OFFSET, NODE_HEADER_SIZE, ITEM_POINTER_SIZE,
    KEY_PTR_SIZE,
    NH_FSID, NH_GENERATION, NH_OWNER, NH_NRITEMS, NH_LEVEL,
    BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
    BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY,
    BTRFS_EXTENT_DATA_KEY,
    BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_REG,
    FILE_EXTENT_HEADER_SIZE, DIR_ITEM_HEADER_SIZE,
    INODE_ITEM_SIZE,
    BTRFS_FS_TREE_OBJECTID,
    ITEM_TYPE_NAMES,
)
from .inode_parser import parse_inode_item
from .chunk_parser import translate_logical_to_physical


# ─── Output directory ────────────────────────────────────────────
OUTPUT_DIR = "recovery_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ─── Item Parsing ────────────────────────────────────────────────

def _parse_dir_entry(f, absolute_data_offset, data_size, object_id, inode_map, label):
    """
    Parse a DIR_ITEM or DIR_INDEX payload.

    DIR_ITEM / DIR_INDEX structure (30-byte header + variable-length name):
        btrfs_disk_key location  (17 bytes) — target inode's key
        __le64 transid           (8 bytes)
        __le16 data_len          (2 bytes) — should be 0 for DIR_ITEM
        __le16 name_len          (2 bytes)
        __u8   type              (1 byte)  — file type (1=file, 2=dir, ...)
        char   name[name_len]

    Returns (target_inode, filename) or (None, None) on failure.
    """
    f.seek(absolute_data_offset)
    if data_size < DIR_ITEM_HEADER_SIZE:
        return None, None

    dir_header = f.read(DIR_ITEM_HEADER_SIZE)
    if len(dir_header) < DIR_ITEM_HEADER_SIZE:
        return None, None

    target_key = dir_header[0:17]
    target_inode = struct.unpack_from("<Q", target_key, 0)[0]
    # transid = struct.unpack_from("<Q", dir_header, 17)[0]
    # data_len = struct.unpack_from("<H", dir_header, 25)[0]
    name_len = struct.unpack_from("<H", dir_header, 27)[0]
    file_type = dir_header[29]

    if name_len == 0 or name_len > 255:
        return None, None

    raw_name = f.read(name_len)
    if len(raw_name) < name_len:
        return None, None

    try:
        filename = raw_name.decode('utf-8', errors='replace')
        # Filter out clearly garbage filenames
        if not filename.isprintable() or len(filename.strip()) == 0:
            return None, None

        print(f"        [{label}] '{filename}' -> Inode {target_inode} (type={file_type})")

        # Update the inode map — prefer shorter/cleaner names
        if target_inode not in inode_map or len(filename) < len(inode_map[target_inode]):
            inode_map[target_inode] = filename

        return target_inode, filename
    except Exception:
        return None, None


def _parse_inode_ref(f, absolute_data_offset, data_size, object_id, inode_map):
    """
    Parse an INODE_REF payload.

    INODE_REF structure:
        __le64 index         (8 bytes) — index in directory
        __le16 name_len      (2 bytes)
        char   name[name_len]

    The object_id of the item key IS the inode number.
    The key offset is the parent directory's inode number.

    Returns the filename or None.
    """
    f.seek(absolute_data_offset)
    remaining = data_size
    filenames = []

    while remaining >= 10:  # minimum: 8 (index) + 2 (name_len) = 10
        ref_data = f.read(10)
        if len(ref_data) < 10:
            break

        # index = struct.unpack_from("<Q", ref_data, 0)[0]
        name_len = struct.unpack_from("<H", ref_data, 8)[0]
        remaining -= 10

        if name_len == 0 or name_len > 255 or name_len > remaining:
            break

        raw_name = f.read(name_len)
        remaining -= name_len

        if len(raw_name) < name_len:
            break

        try:
            filename = raw_name.decode('utf-8', errors='replace')
            if filename.isprintable() and len(filename.strip()) > 0:
                print(f"        [INODE_REF] Inode {object_id} -> '{filename}'")
                if object_id not in inode_map:
                    inode_map[object_id] = filename
                filenames.append(filename)
        except Exception:
            pass

    return filenames[0] if filenames else None


def _extract_inline_extent(f, absolute_data_offset, data_size, object_id,
                           node_gen, inode_map, report, source_label):
    """
    Extract inline file data from an EXTENT_DATA item.

    Inline extent: the file data immediately follows the 21-byte extent header.
    """
    f.seek(absolute_data_offset)
    extent_header = f.read(FILE_EXTENT_HEADER_SIZE)  # 21 bytes
    if len(extent_header) < FILE_EXTENT_HEADER_SIZE:
        return

    # generation = struct.unpack_from("<Q", extent_header, 0)[0]
    # ram_bytes = struct.unpack_from("<Q", extent_header, 8)[0]
    compression = extent_header[16]
    # encryption = extent_header[17]
    extent_type = extent_header[20]

    if extent_type == BTRFS_FILE_EXTENT_INLINE:
        payload_size = data_size - FILE_EXTENT_HEADER_SIZE
        if payload_size <= 0:
            return

        raw_file_bytes = f.read(payload_size)
        if len(raw_file_bytes) < payload_size:
            return

        # Handle compression (stub — log it but save raw for now)
        if compression != 0:
            comp_names = {1: "zlib", 2: "lzo", 3: "zstd"}
            comp_name = comp_names.get(compression, f"unknown({compression})")
            print(f"        [!] Inline data is {comp_name}-compressed ({payload_size} bytes)")

        real_filename = inode_map.get(object_id, f"inode_{object_id}")
        # Sanitize filename for filesystem safety
        safe_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in real_filename)
        out_path = os.path.join(OUTPUT_DIR, f"{safe_name}_gen{node_gen}_{source_label}_inline.bin")

        # Avoid overwriting files we've already recovered
        if os.path.exists(out_path):
            return

        with open(out_path, "wb") as out_file:
            out_file.write(raw_file_bytes)

        print(f"        [***] Extracted Inline Data -> {out_path} ({payload_size} bytes)")

        report.inline_files_recovered += 1
        report.add_recovered_file({
            "filename":     real_filename,
            "inode":        object_id,
            "generation":   node_gen,
            "extent_type":  "inline",
            "size":         payload_size,
            "output_path":  out_path,
            "source":       source_label,
            "compressed":   compression != 0,
        })

    elif extent_type == BTRFS_FILE_EXTENT_REG:
        _handle_regular_extent(f, absolute_data_offset, object_id, node_gen,
                               inode_map, report, source_label)


def _handle_regular_extent(f, absolute_data_offset, object_id, node_gen,
                           inode_map, report, source_label):
    """
    Handle a regular (non-inline) file extent.

    Regular extent data (after the 21-byte header):
        disk_bytenr    (8 bytes) — logical address of extent on disk
        disk_num_bytes (8 bytes) — size of extent on disk
        offset         (8 bytes) — offset within the extent
        num_bytes      (8 bytes) — logical number of bytes in file

    We store these references for a second-pass extraction using the chunk map.
    """
    f.seek(absolute_data_offset + FILE_EXTENT_HEADER_SIZE)
    extent_ref = f.read(32)
    if len(extent_ref) < 32:
        return

    disk_bytenr    = struct.unpack_from("<Q", extent_ref, 0)[0]
    disk_num_bytes = struct.unpack_from("<Q", extent_ref, 8)[0]
    offset         = struct.unpack_from("<Q", extent_ref, 16)[0]
    num_bytes      = struct.unpack_from("<Q", extent_ref, 24)[0]

    real_filename = inode_map.get(object_id, f"inode_{object_id}")

    if disk_bytenr == 0:
        # Sparse extent — all zeros
        print(f"        [!] Sparse extent for '{real_filename}' ({num_bytes} bytes)")
        return

    print(f"        [EXTENT] '{real_filename}' (Inode {object_id})")
    print(f"            -> Logical Addr:  0x{disk_bytenr:X}")
    print(f"            -> Disk Size:     {disk_num_bytes} bytes")
    print(f"            -> File Offset:   {offset}")
    print(f"            -> File Bytes:    {num_bytes}")

    # Store extent reference for second-pass recovery
    report.add_recovered_file({
        "filename":        real_filename,
        "inode":           object_id,
        "generation":      node_gen,
        "extent_type":     "regular",
        "size":            num_bytes,
        "disk_bytenr":     disk_bytenr,
        "disk_num_bytes":  disk_num_bytes,
        "offset":          offset,
        "source":          source_label,
        "output_path":     None,  # filled in during second pass
    })


# ─── Node Parsing ────────────────────────────────────────────────

def parse_node_items(f, node_offset, nodesize, node_gen, inode_map, report,
                     scan_orphan_items=True):
    """
    Parses a B-tree leaf node's item pointers.

    Builds filename ↔ inode mappings from DIR_ITEM, DIR_INDEX, INODE_REF.
    Extracts inline file data from EXTENT_DATA items.
    Records regular extent references for second-pass extraction.

    If scan_orphan_items is True, also scans items beyond nritems
    (Orphan-Items per Paper 2 — remnants of B-tree balancing operations).
    """
    f.seek(node_offset)
    header = f.read(NODE_HEADER_SIZE)

    if len(header) < NODE_HEADER_SIZE:
        return

    level = header[NH_LEVEL]
    nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]

    if level != 0:
        # Internal node — skip for now in brute-force mode.
        # Future: scan internal-node slack for leaf remnants (Paper 2, Sec. 3.4)
        return

    # Sanity check: nritems should be reasonable
    max_possible_items = (nodesize - NODE_HEADER_SIZE) // ITEM_POINTER_SIZE
    if nritems > max_possible_items:
        return  # corrupted header

    # ── Parse valid items (within nritems) ──
    for i in range(nritems):
        _parse_single_item(f, node_offset, i, node_gen, inode_map, report,
                           source_label="valid")

    # ── Parse Orphan-Items (beyond nritems) ──
    if scan_orphan_items:
        # Scan additional item slots beyond nritems up to the maximum
        # We limit to a reasonable number to avoid reading garbage
        max_orphan_scan = min(max_possible_items, nritems + 200) - nritems
        orphan_count = 0

        for i in range(nritems, nritems + max_orphan_scan):
            pointer_offset = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)

            # Read the raw item pointer and check if it looks valid
            f.seek(pointer_offset)
            pointer_raw = f.read(ITEM_POINTER_SIZE)
            if len(pointer_raw) < ITEM_POINTER_SIZE:
                break

            key_raw, data_offset, data_size = struct.unpack("<17sII", pointer_raw)
            item_type = key_raw[8]

            # Validate: does this look like a real item?
            # - data_offset + data_size should fit within the node
            # - item_type should be a known type
            # - data_size should be non-zero and reasonable
            if data_size == 0 or data_size > nodesize:
                continue
            if data_offset + data_size > nodesize - NODE_HEADER_SIZE:
                continue
            if item_type not in (BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
                                 BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY,
                                 BTRFS_EXTENT_DATA_KEY):
                continue

            # This looks like a valid Orphan-Item!
            orphan_count += 1
            _parse_single_item(f, node_offset, i, node_gen, inode_map, report,
                               source_label="orphan")

        if orphan_count > 0:
            report.orphan_items_found += orphan_count
            print(f"        [ORPHAN] Found {orphan_count} Orphan-Items in this node")


def _parse_single_item(f, node_offset, item_index, node_gen, inode_map,
                        report, source_label):
    """
    Parse a single btrfs_item at the given index within a leaf node.
    """
    pointer_offset = node_offset + NODE_HEADER_SIZE + (item_index * ITEM_POINTER_SIZE)
    f.seek(pointer_offset)
    pointer_raw = f.read(ITEM_POINTER_SIZE)

    if len(pointer_raw) < ITEM_POINTER_SIZE:
        return

    # Unpack: btrfs_disk_key (17 bytes) + data_offset (4) + data_size (4)
    key_raw, data_offset, data_size = struct.unpack("<17sII", pointer_raw)

    object_id  = struct.unpack_from("<Q", key_raw, 0)[0]
    item_type  = key_raw[8]
    key_offset = struct.unpack_from("<Q", key_raw, 9)[0]

    # Absolute byte position of this item's data payload
    absolute_data_offset = node_offset + NODE_HEADER_SIZE + data_offset

    # ── INODE_ITEM (type 0x01) ──
    if item_type == BTRFS_INODE_ITEM_KEY:
        if data_size >= INODE_ITEM_SIZE:
            f.seek(absolute_data_offset)
            inode_data = f.read(INODE_ITEM_SIZE)
            parsed = parse_inode_item(inode_data)
            if parsed:
                report.add_inode_metadata(object_id, node_gen, parsed)
                size_str = f"{parsed['size']} bytes"
                mtime_str = parsed['mtime']['iso']
                print(f"        [INODE] Inode {object_id}: size={size_str}, "
                      f"nlink={parsed['nlink']}, mtime={mtime_str}")

    # ── INODE_REF (type 0x0C) ──
    elif item_type == BTRFS_INODE_REF_KEY:
        _parse_inode_ref(f, absolute_data_offset, data_size, object_id, inode_map)

    # ── DIR_ITEM (type 0x54) ──
    elif item_type == BTRFS_DIR_ITEM_KEY:
        _parse_dir_entry(f, absolute_data_offset, data_size, object_id,
                         inode_map, "DIR_ITEM")

    # ── DIR_INDEX (type 0x60) ──
    elif item_type == BTRFS_DIR_INDEX_KEY:
        _parse_dir_entry(f, absolute_data_offset, data_size, object_id,
                         inode_map, "DIR_INDEX")

    # ── EXTENT_DATA (type 0x6C) ──
    elif item_type == BTRFS_EXTENT_DATA_KEY:
        _extract_inline_extent(f, absolute_data_offset, data_size, object_id,
                               node_gen, inode_map, report, source_label)


# ─── Main Sweep ──────────────────────────────────────────────────

def sweep_for_orphans(image_path, sb_data, report, scan_current_gen=True):
    """
    Brute-force sweep of the raw disk image for B-tree nodes.

    Phase 1: Scan for orphaned nodes (gen < sb_gen) — these are old CoW
             copies that may contain deleted file data.
    Phase 2: Optionally also scan current-generation nodes for Orphan-Items
             (items beyond nritems) — remnants from B-tree balancing.

    After scanning, performs a second pass to extract regular extent data
    using the chunk map for logical → physical translation.
    """
    print("[*] Starting raw disk sweep for B-tree nodes...")
    fsid     = sb_data["fsid"]
    sb_gen   = sb_data["generation"]
    nodesize = sb_data["nodesize"]
    chunk_map= sb_data["chunk_map"]

    # Initialize the inode → filename map
    inode_map = {}

    file_size = os.path.getsize(image_path)

    with open(image_path, "rb") as f:
        # Start scanning from after the superblock region
        current_offset = SUPERBLOCK_OFFSET + nodesize

        while current_offset + NODE_HEADER_SIZE <= file_size:
            f.seek(current_offset)
            header = f.read(NODE_HEADER_SIZE)

            if not header or len(header) < NODE_HEADER_SIZE:
                break

            report.nodes_scanned += 1

            # Check if this block belongs to our filesystem
            node_fsid = header[NH_FSID:NH_FSID + 16]

            if node_fsid == fsid:
                node_gen = struct.unpack_from("<Q", header, NH_GENERATION)[0]
                node_owner = struct.unpack_from("<Q", header, NH_OWNER)[0]
                level = header[NH_LEVEL]

                # ── Orphaned node (old CoW copy) ──
                if node_gen < sb_gen:
                    report.orphan_nodes_found += 1
                    print(f"\n    [!] Orphaned Node @ offset 0x{current_offset:X} "
                          f"(Gen {node_gen}, Owner {node_owner}, Level {level})")

                    parse_node_items(f, current_offset, nodesize, node_gen,
                                     inode_map, report, scan_orphan_items=True)

                # ── Current-gen node: scan only for Orphan-Items ──
                elif scan_current_gen and level == 0:
                    report.current_nodes_scanned += 1
                    # Only scan for Orphan-Items in current-gen leaf nodes
                    # (valid items in current nodes are the active filesystem)
                    parse_node_items(f, current_offset, nodesize, node_gen,
                                     inode_map, report, scan_orphan_items=True)

            current_offset += nodesize

    print(f"\n[*] Scan complete. Found {report.orphan_nodes_found} orphaned nodes.")
    print(f"    Inode map contains {len(inode_map)} filename mappings.")

    # ── Second Pass: Extract regular extent data ──
    _extract_regular_extents(image_path, chunk_map, report)

    return inode_map


def _extract_regular_extents(image_path, chunk_map, report):
    """
    Second pass: for each regular extent reference collected during the scan,
    translate the logical address to physical using the chunk map and read
    the actual file data from disk.
    """
    regular_extents = [
        f for f in report.recovered_files
        if f.get("extent_type") == "regular" and f.get("output_path") is None
    ]

    if not regular_extents:
        return

    print(f"\n[*] Second pass: extracting {len(regular_extents)} regular extent(s)...")

    with open(image_path, "rb") as f:
        for entry in regular_extents:
            disk_bytenr    = entry["disk_bytenr"]
            disk_num_bytes = entry["disk_num_bytes"]
            offset         = entry["offset"]
            num_bytes      = entry["size"]
            filename       = entry["filename"]
            gen            = entry["generation"]
            source         = entry["source"]

            # Translate logical → physical
            phys_addr = translate_logical_to_physical(disk_bytenr, chunk_map)
            if phys_addr is None:
                print(f"    [!] Could not translate logical addr 0x{disk_bytenr:X} "
                      f"for '{filename}' — not in chunk map")
                report.regular_extents_failed += 1
                continue

            # Read the data from the physical location
            read_offset = phys_addr + offset
            f.seek(read_offset)
            raw_data = f.read(num_bytes)

            if len(raw_data) < num_bytes:
                print(f"    [!] Short read for '{filename}': got {len(raw_data)}/{num_bytes}")

            safe_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in filename)
            out_path = os.path.join(OUTPUT_DIR, f"{safe_name}_gen{gen}_{source}_extent.bin")

            # Avoid overwriting
            if os.path.exists(out_path):
                base, ext = os.path.splitext(out_path)
                counter = 1
                while os.path.exists(out_path):
                    out_path = f"{base}_{counter}{ext}"
                    counter += 1

            with open(out_path, "wb") as out_file:
                out_file.write(raw_data)

            entry["output_path"] = out_path
            report.regular_extents_recovered += 1
            print(f"    [+] Extracted '{filename}' -> {out_path} "
                  f"({len(raw_data)} bytes, phys=0x{read_offset:X})")
