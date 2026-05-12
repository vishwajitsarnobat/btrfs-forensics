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
    BTRFS_EXTENT_TREE_OBJECTID,
    BTRFS_DEV_TREE_OBJECTID,
    BTRFS_EXTENT_ITEM_KEY,
    BTRFS_EXTENT_DATA_REF_KEY,
    BTRFS_ROOT_ITEM_KEY,
    BTRFS_DEV_ITEM_KEY,
    ITEM_TYPE_NAMES,
)
from .inode_parser import parse_inode_item
from .chunk_parser import translate_logical_to_physical
from .crc32c import crc32c


# ─── Inode Map Helpers ───────────────────────────────────────────
# The inode map is keyed by (inode_number, generation) to avoid
# filename collisions when the same inode number is reused across
# generations (e.g., after delete + recreate).

def _inode_map_set(inode_map, inode_id, generation, filename):
    """Store a filename mapping for (inode, generation). Prefer shorter names."""
    key = (inode_id, generation)
    if key not in inode_map or len(filename) < len(inode_map[key]):
        inode_map[key] = filename


def _inode_map_get(inode_map, inode_id, generation):
    """Look up filename by (inode, generation), falling back to any generation."""
    key = (inode_id, generation)
    if key in inode_map:
        return inode_map[key]
    # Fallback: find any generation for this inode
    for (ino, gen), name in inode_map.items():
        if ino == inode_id:
            return name
    return f"inode_{inode_id}"


# ─── Item Parsing ────────────────────────────────────────────────

def _parse_dir_entry(f, absolute_data_offset, data_size, object_id,
                     node_gen, inode_map, label, report):
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

        # ── Move/rename detection (C1) ──
        # If this inode already has a *different* name in the map,
        # the orphaned entry is the pre-move/pre-rename path.
        for (ino, gen), existing_name in inode_map.items():
            if ino == target_inode and existing_name != filename:
                print(f"        [MOVE] Inode {target_inode}: "
                      f"'{filename}' → '{existing_name}' (file was moved/renamed)")
                report.add_move_artifact({
                    "inode":         target_inode,
                    "original_path": filename,
                    "current_path":  existing_name,
                })
                break

        # Update the inode map (generation-aware)
        _inode_map_set(inode_map, target_inode, node_gen, filename)

        return target_inode, filename
    except Exception:
        return None, None


def _parse_inode_ref(f, absolute_data_offset, data_size, object_id,
                     node_gen, inode_map):
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
                # Update inode map (generation-aware) — only if no name yet
                key = (object_id, node_gen)
                if key not in inode_map:
                    _inode_map_set(inode_map, object_id, node_gen, filename)
                filenames.append(filename)
        except Exception:
            pass

    return filenames[0] if filenames else None


def _extract_inline_extent(f, absolute_data_offset, data_size, object_id,
                           node_gen, inode_map, report, source_label,
                           output_dir):
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

        real_filename = _inode_map_get(inode_map, object_id, node_gen)
        # Sanitize filename for filesystem safety
        safe_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in real_filename)
        out_path = os.path.join(output_dir, f"{safe_name}_gen{node_gen}_{source_label}_inline.bin")

        # Avoid overwriting files we've already recovered — log the skip
        if os.path.exists(out_path):
            print(f"        [*] Duplicate inline extent for '{real_filename}' "
                  f"(gen {node_gen}) — already extracted, skipping")
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

    real_filename = _inode_map_get(inode_map, object_id, node_gen)

    if disk_bytenr == 0:
        # Sparse extent — all zeros
        print(f"        [!] Sparse extent for '{real_filename}' ({num_bytes} bytes)")
        return

    # ── File slack reporting (C2) ──
    file_slack = disk_num_bytes - (offset + num_bytes)
    if file_slack > 0:
        print(f"            → File Slack:    {file_slack} bytes (unextracted)")

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
        "file_slack":      file_slack if file_slack > 0 else 0,
        "source":          source_label,
        "output_path":     None,  # filled in during second pass
    })


# ─── Node Parsing ────────────────────────────────────────────────

def parse_node_items(f, node_offset, nodesize, node_gen, inode_map, report,
                     output_dir, scan_orphan_items=True, parse_valid_items=True):
    """
    Parses a B-tree leaf node's item pointers.

    Builds filename ↔ inode mappings from DIR_ITEM, DIR_INDEX, INODE_REF.
    Extracts inline file data from EXTENT_DATA items.
    Records regular extent references for second-pass extraction.

    If parse_valid_items is True, parses items within nritems (indices 0..nritems-1).
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
        # Internal node — scan key-pointer slots beyond nritems
        # for orphaned children (B4) and mine slack space (D1)
        if scan_orphan_items:
            _scan_internal_node_orphan_ptrs(f, node_offset, nodesize, nritems,
                                            node_gen, report)
        return

    # Sanity check: nritems should be reasonable
    max_possible_items = (nodesize - NODE_HEADER_SIZE) // ITEM_POINTER_SIZE
    if nritems > max_possible_items:
        return  # corrupted header

    # ── Parse valid items (within nritems) ──
    if parse_valid_items:
        for i in range(nritems):
            _parse_single_item(f, node_offset, i, node_gen, inode_map, report,
                               output_dir, source_label="valid")

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
                               output_dir, source_label="orphan")

        if orphan_count > 0:
            report.orphan_items_found += orphan_count
            print(f"        [ORPHAN] Found {orphan_count} Orphan-Items in this node")

    # ── Leaf slack extraction (B1) ──
    _extract_leaf_slack(f, node_offset, nodesize, nritems, node_gen, report,
                        output_dir)


def _parse_single_item(f, node_offset, item_index, node_gen, inode_map,
                        report, output_dir, source_label):
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
        _parse_inode_ref(f, absolute_data_offset, data_size, object_id,
                         node_gen, inode_map)

    # ── DIR_ITEM (type 0x54) ──
    elif item_type == BTRFS_DIR_ITEM_KEY:
        _parse_dir_entry(f, absolute_data_offset, data_size, object_id,
                         node_gen, inode_map, "DIR_ITEM", report)

    # ── DIR_INDEX (type 0x60) ──
    elif item_type == BTRFS_DIR_INDEX_KEY:
        _parse_dir_entry(f, absolute_data_offset, data_size, object_id,
                         node_gen, inode_map, "DIR_INDEX", report)

    # ── EXTENT_DATA (type 0x6C) ──
    elif item_type == BTRFS_EXTENT_DATA_KEY:
        _extract_inline_extent(f, absolute_data_offset, data_size, object_id,
                               node_gen, inode_map, report, source_label,
                               output_dir)

    # ── ROOT_ITEM reserved field inspection (D3) ──
    elif item_type == BTRFS_ROOT_ITEM_KEY:
        if data_size >= 439:
            f.seek(absolute_data_offset)
            root_item_data = f.read(data_size)
            # Check reserved/padding regions for non-zero values
            # ROOT_ITEM is 439 bytes; bytes 235..438 are reserved in older formats
            if len(root_item_data) >= 439:
                reserved_region = root_item_data[235:439]
                non_zero_count = sum(1 for b in reserved_region if b != 0)
                if non_zero_count > 0:
                    print(f"        [ROOT_ITEM] Inode {object_id}: "
                          f"{non_zero_count} non-zero bytes in reserved region")
                    report.root_item_anomalies += 1


# ─── Main Sweep ──────────────────────────────────────────────────

def sweep_for_orphans(image_path, sb_data, report, output_dir,
                      scan_current_gen=True):
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
    # Keyed by (inode_number, generation) to avoid collisions when the same
    # inode number is reused across generations (delete + recreate).
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
                # ── CRC32c checksum validation ──
                # Read the full node and verify Castagnoli CRC32c.
                # The checksum is stored in the first 4 bytes of the header;
                # it covers bytes 32 onward (everything after the csum field).
                f.seek(current_offset)
                node_bytes = f.read(nodesize)
                if len(node_bytes) < nodesize:
                    current_offset += nodesize
                    continue
                stored_csum = struct.unpack_from("<I", node_bytes, 0)[0]
                computed_csum = crc32c(node_bytes[32:])
                if stored_csum != computed_csum:
                    report.checksum_failures += 1
                    current_offset += nodesize
                    continue

                node_gen = struct.unpack_from("<Q", header, NH_GENERATION)[0]
                node_owner = struct.unpack_from("<Q", header, NH_OWNER)[0]
                level = header[NH_LEVEL]

                # ── Snapshot presence indicator (C4) ──
                if node_owner >= 256:
                    report.subvolume_nodes_seen += 1

                # ── Orphaned node (old CoW copy) ──
                if node_gen < sb_gen:
                    report.orphan_nodes_found += 1
                    print(f"\n    [!] Orphaned Node @ offset 0x{current_offset:X} "
                          f"(Gen {node_gen}, Owner {node_owner}, Level {level})")

                    # Branch: extent-tree nodes get a specialized parser (B3)
                    if node_owner == BTRFS_EXTENT_TREE_OBJECTID and level == 0:
                        _parse_extent_tree_leaf(f, current_offset, nodesize,
                                                node_gen, report)
                    # Branch: device-tree nodes (D4)
                    elif node_owner == BTRFS_DEV_TREE_OBJECTID and level == 0:
                        _parse_dev_tree_leaf(f, current_offset, nodesize,
                                             node_gen, report)
                    else:
                        parse_node_items(f, current_offset, nodesize, node_gen,
                                         inode_map, report, output_dir,
                                         scan_orphan_items=True,
                                         parse_valid_items=True)

                # ── Current-gen node: scan ONLY for Orphan-Items ──
                elif scan_current_gen and level == 0:
                    report.current_nodes_scanned += 1
                    # Valid items in current nodes are the active filesystem —
                    # only scan for Orphan-Items (beyond nritems)
                    parse_node_items(f, current_offset, nodesize, node_gen,
                                     inode_map, report, output_dir,
                                     scan_orphan_items=True,
                                     parse_valid_items=False)

            current_offset += nodesize

    print(f"\n[*] Scan complete. Found {report.orphan_nodes_found} orphaned nodes.")
    print(f"    Inode map contains {len(inode_map)} filename mappings.")

    # ── Defragmentation hazard detection (C3) ──
    if report.nodes_scanned > 0:
        orphan_ratio = report.orphan_nodes_found / report.nodes_scanned
        bytes_used_pct = sb_data["bytes_used"] / sb_data["total_bytes"] if sb_data["total_bytes"] > 0 else 0
        if orphan_ratio < 0.01 and bytes_used_pct > 0.5:
            print(f"\n[!] DEFRAG WARNING: Very low orphaned-node ratio "
                  f"({orphan_ratio:.1%}) with {bytes_used_pct:.0%} disk usage.")
            print("    Online defragmentation may have run, reducing recoverable data.")
            report.defrag_warning = True

    # ── Snapshot presence indicator (C4) ──
    if report.subvolume_nodes_seen > 0:
        print(f"[*] Subvolume/snapshot nodes detected ({report.subvolume_nodes_seen} nodes). "
              "Recovery probability is elevated on snapshot-heavy filesystems.")
        report.has_snapshots = True

    # ── Second Pass: Extract regular extent data ──
    _extract_regular_extents(image_path, chunk_map, report, output_dir)

    return inode_map


def _extract_regular_extents(image_path, chunk_map, report, output_dir):
    """
    Second pass: for each regular extent reference collected during the scan,
    translate the logical address to physical using the chunk map and read
    the actual file data from disk.

    Deduplicates by (disk_bytenr, offset, num_bytes) to avoid writing
    identical extent data multiple times.
    """
    regular_extents = [
        f for f in report.recovered_files
        if f.get("extent_type") == "regular" and f.get("output_path") is None
    ]

    if not regular_extents:
        return

    print(f"\n[*] Second pass: extracting {len(regular_extents)} regular extent(s)...")

    # Track already-extracted extents to avoid duplicates
    extracted_extents = set()  # (disk_bytenr, offset, num_bytes)

    with open(image_path, "rb") as f:
        for entry in regular_extents:
            disk_bytenr    = entry["disk_bytenr"]
            disk_num_bytes = entry["disk_num_bytes"]
            offset         = entry["offset"]
            num_bytes      = entry["size"]
            filename       = entry["filename"]
            gen            = entry["generation"]
            source         = entry["source"]

            # ── Deduplicate ──
            extent_key = (disk_bytenr, offset, num_bytes)
            if extent_key in extracted_extents:
                print(f"    [*] Duplicate extent for '{filename}' "
                      f"(0x{disk_bytenr:X}+{offset}, {num_bytes} bytes) "
                      f"— already extracted, skipping")
                entry["output_path"] = "(duplicate)"
                continue
            extracted_extents.add(extent_key)

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
            out_path = os.path.join(output_dir, f"{safe_name}_gen{gen}_{source}_extent.bin")

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


# ─── Leaf Slack Extraction (B1) ──────────────────────────────────

def _extract_leaf_slack(f, node_offset, nodesize, nritems, node_gen, report,
                        output_dir):
    """
    Extract and save the slack space between the item-pointer array and
    the first item-data byte in a leaf node.

    Source: Wani et al. (2020)
    """
    if nritems == 0:
        return

    item_ptr_end = node_offset + NODE_HEADER_SIZE + (nritems * ITEM_POINTER_SIZE)

    # Find the earliest (smallest) data_offset among all valid items
    # — this is the start of the item-data region
    min_data_offset = nodesize  # worst case: no data
    for i in range(nritems):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(ITEM_POINTER_SIZE)
        if len(ptr_raw) < ITEM_POINTER_SIZE:
            break
        _, data_offset, data_size = struct.unpack("<17sII", ptr_raw)
        if data_size > 0:
            min_data_offset = min(min_data_offset, data_offset)

    # Absolute position of the first item-data byte
    first_data_byte = node_offset + NODE_HEADER_SIZE + min_data_offset

    slack_size = first_data_byte - item_ptr_end
    if slack_size <= 0:
        return

    f.seek(item_ptr_end)
    slack_bytes = f.read(slack_size)

    # Only save if non-zero (all-zero slack has no forensic value)
    if all(b == 0 for b in slack_bytes):
        return

    out_path = os.path.join(output_dir,
                            f"leaf_slack_0x{node_offset:X}_gen{node_gen}.bin")
    if not os.path.exists(out_path):
        with open(out_path, "wb") as out:
            out.write(slack_bytes)
        report.leaf_slacks_found += 1
        print(f"        [SLACK] Leaf slack {slack_size} bytes → {out_path}")


# ─── Internal Node Orphan Pointer Scanning (B4) ─────────────────

def _scan_internal_node_orphan_ptrs(f, node_offset, nodesize, nritems,
                                     node_gen, report):
    """
    In an orphaned internal node, read key-pointer pairs beyond nritems.
    Each such pair may point to an orphaned child leaf.
    Record the child logical addresses in the report.

    Also calls _mine_internal_node_slack for D1 (slack mining).

    Source: Bhat & Wani (2018)
    """
    max_possible_ptrs = (nodesize - NODE_HEADER_SIZE) // KEY_PTR_SIZE
    orphan_ptr_count = 0

    for i in range(nritems, max_possible_ptrs):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * KEY_PTR_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(KEY_PTR_SIZE)
        if len(ptr_raw) < KEY_PTR_SIZE:
            break

        # btrfs_key_ptr: disk_key(17) + block_number(8) + generation(8)
        child_logical = struct.unpack_from("<Q", ptr_raw, 17)[0]
        child_gen     = struct.unpack_from("<Q", ptr_raw, 25)[0]

        # Sanity: child_logical should look like a plausible address (non-zero, aligned)
        if child_logical == 0 or child_logical % 4096 != 0:
            break  # hit padding/garbage, stop

        orphan_ptr_count += 1
        report.add_orphan_child_ptr({
            "parent_offset": node_offset,
            "parent_gen":    node_gen,
            "child_logical": child_logical,
            "child_gen":     child_gen,
            "slot":          i,
        })

    if orphan_ptr_count > 0:
        report.internal_orphan_ptrs_found += orphan_ptr_count
        print(f"        [INT-ORPHAN] {orphan_ptr_count} orphaned child pointers "
              f"in internal node @ 0x{node_offset:X}")

    # ── Internal node slack mining (D1) ──
    _mine_internal_node_slack(f, node_offset, nodesize, nritems, node_gen, report)


# ─── Internal Node Slack Mining (D1) ─────────────────────────────

def _mine_internal_node_slack(f, node_offset, nodesize, nritems, node_gen, report):
    """
    For orphaned internal nodes, the region from
    NODE_HEADER_SIZE + (nritems × KEY_PTR_SIZE) to end of node may contain
    residual leaf item data from before the block was promoted to an internal node.

    Scan this raw region for valid btrfs_item-sized chunks.

    Source: Bhat & Wani (2018), Wani et al. (2020)
    """
    slack_start = node_offset + NODE_HEADER_SIZE + (nritems * KEY_PTR_SIZE)
    slack_end = node_offset + nodesize
    slack_size = slack_end - slack_start

    if slack_size < ITEM_POINTER_SIZE:
        return

    f.seek(slack_start)
    slack_data = f.read(slack_size)

    # All-zero slack has no value
    if all(b == 0 for b in slack_data):
        return

    known_types = {
        BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
        BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY,
        BTRFS_EXTENT_DATA_KEY, BTRFS_ROOT_ITEM_KEY,
    }

    residual_count = 0
    # Slide a 25-byte window through the slack
    for pos in range(0, len(slack_data) - ITEM_POINTER_SIZE + 1, ITEM_POINTER_SIZE):
        window = slack_data[pos:pos + ITEM_POINTER_SIZE]
        key_raw, data_offset, data_size = struct.unpack("<17sII", window)
        item_type = key_raw[8]

        if item_type in known_types and data_size > 0 and data_size < nodesize:
            if data_offset + data_size <= nodesize - NODE_HEADER_SIZE:
                residual_count += 1

    if residual_count > 0:
        report.internal_slack_residuals += residual_count
        print(f"        [INT-SLACK] {residual_count} residual item structures "
              f"in internal node slack @ 0x{node_offset:X}")


# ─── Extent Tree Leaf Parsing (B3) ───────────────────────────────

def _parse_extent_tree_leaf(f, node_offset, nodesize, node_gen, report):
    """
    Parse an orphaned extent-tree leaf node for EXTENT_DATA_REF items.
    These record (root, inode, file_offset) for extents that were
    referenced by deleted files.

    Source: Rodeh, Bacik & Mason (2013)
    """
    f.seek(node_offset)
    header = f.read(NODE_HEADER_SIZE)
    nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]
    max_possible = (nodesize - NODE_HEADER_SIZE) // ITEM_POINTER_SIZE
    if nritems > max_possible:
        return

    current_extent_laddr = None  # logical address from the preceding EXTENT_ITEM key

    for i in range(nritems):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(ITEM_POINTER_SIZE)
        if len(ptr_raw) < ITEM_POINTER_SIZE:
            break
        key_raw, data_offset, data_size = struct.unpack("<17sII", ptr_raw)
        item_type  = key_raw[8]
        key_objid  = struct.unpack_from("<Q", key_raw, 0)[0]
        key_offset = struct.unpack_from("<Q", key_raw, 9)[0]

        abs_data = node_offset + NODE_HEADER_SIZE + data_offset

        if item_type == BTRFS_EXTENT_ITEM_KEY:
            # The key offset IS the logical address of this extent
            current_extent_laddr = key_offset

        elif item_type == BTRFS_EXTENT_DATA_REF_KEY and data_size >= 28:
            f.seek(abs_data)
            ref_data = f.read(28)
            if len(ref_data) < 28:
                continue
            ref_root     = struct.unpack_from("<Q", ref_data, 0)[0]
            ref_inode    = struct.unpack_from("<Q", ref_data, 8)[0]
            ref_offset   = struct.unpack_from("<Q", ref_data, 16)[0]
            ref_count    = struct.unpack_from("<I", ref_data, 24)[0]

            print(f"        [BACKREF] Extent 0x{current_extent_laddr or 0:X} "
                  f"→ root={ref_root} inode={ref_inode} offset={ref_offset} "
                  f"count={ref_count}")

            report.add_extent_backref({
                "extent_laddr":  current_extent_laddr,
                "root":          ref_root,
                "inode":         ref_inode,
                "file_offset":   ref_offset,
                "ref_count":     ref_count,
                "node_gen":      node_gen,
            })


# ─── Device Tree Leaf Parsing (D4) ───────────────────────────────

def _parse_dev_tree_leaf(f, node_offset, nodesize, node_gen, report):
    """
    Parse an orphaned device-tree leaf node for DEV_ITEM entries.
    Extracts device UUID, total device size, and physical layout.

    Source: Hilgert et al. (2018)
    """
    f.seek(node_offset)
    header = f.read(NODE_HEADER_SIZE)
    nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]
    max_possible = (nodesize - NODE_HEADER_SIZE) // ITEM_POINTER_SIZE
    if nritems > max_possible:
        return

    for i in range(nritems):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(ITEM_POINTER_SIZE)
        if len(ptr_raw) < ITEM_POINTER_SIZE:
            break
        key_raw, data_offset, data_size = struct.unpack("<17sII", ptr_raw)
        item_type = key_raw[8]

        if item_type != BTRFS_DEV_ITEM_KEY or data_size < 98:
            continue

        abs_data = node_offset + NODE_HEADER_SIZE + data_offset
        f.seek(abs_data)
        dev_data = f.read(min(data_size, 98))
        if len(dev_data) < 98:
            continue

        # DEV_ITEM layout (first 98 bytes):
        #   devid(8) + total_bytes(8) + bytes_used(8) + ...
        #   + type(8) + generation(8) + start_offset(8) + dev_group(4)
        #   + seek_speed(1) + bandwidth(1) + uuid(16) + fsid(16)
        import uuid
        devid       = struct.unpack_from("<Q", dev_data, 0)[0]
        total_bytes = struct.unpack_from("<Q", dev_data, 8)[0]
        bytes_used  = struct.unpack_from("<Q", dev_data, 16)[0]
        dev_uuid    = uuid.UUID(bytes=dev_data[82:98])

        print(f"        [DEV] Device {devid}: UUID={dev_uuid}, "
              f"size={total_bytes/(1024*1024):.1f} MiB, "
              f"used={bytes_used/(1024*1024):.2f} MiB")

        report.add_device_info({
            "devid":       devid,
            "uuid":        str(dev_uuid),
            "total_bytes": total_bytes,
            "bytes_used":  bytes_used,
            "node_gen":    node_gen,
        })
