# utils/anchored_walk.py
# M1 — anchored historical walking.
#
# Each validated superblock backup root references a complete filesystem tree
# as of an older generation. Walking those trees reconstructs the filesystem
# *state* at that point in time with structural proof (a checksum-valid
# root-to-leaf path) — no blind scanning involved. This module:
#
#   1. walks a backup's fs tree and collects the file inventory as of its gen
#   2. walks the current fs tree (via the live root tree) for comparison
#   3. tags sweep-recovered artifacts with "anchored" provenance where the
#      (inode, generation) pair appears in a historical state
#   4. reports files that existed in a historical state but are gone now
#      (deleted since that generation)

import struct
from .constants import (
    NODE_HEADER_SIZE, ITEM_POINTER_SIZE,
    BTRFS_INODE_ITEM_KEY, BTRFS_INODE_REF_KEY,
    BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY,
    BTRFS_EXTENT_DATA_KEY, BTRFS_FS_TREE_OBJECTID,
    BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_REG,
    FILE_EXTENT_HEADER_SIZE, DIR_ITEM_HEADER_SIZE,
)
from .inode_parser import parse_inode_item
from .tree_walker import walk_tree
from .orphan_scan import _find_tree_root_by_objectid


def get_current_fs_tree_root(image_path, sb_data):
    """Logical address of the current fs tree root via the live root tree."""
    return _find_tree_root_by_objectid(
        image_path, sb_data["root_tree_addr"], sb_data["chunk_map"],
        sb_data["nodesize"], BTRFS_FS_TREE_OBJECTID)


def collect_fs_tree_state(image_path, sb_data, fs_root, gen):
    """
    Walk the fs tree anchored at `fs_root` and return its file inventory.

    Returns a dict:
        {inode: {"filename": str, "size": int, "has_data": bool,
                 "nlink": int}}
    Keyed by inode number; later duplicates (CoW copies) keep the first.
    """
    inventory = {}

    def on_leaf(laddr, phys, nritems, header):
        with open(image_path, "rb") as f:
            for i in range(nritems):
                ptr_off = phys + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
                f.seek(ptr_off)
                raw = f.read(ITEM_POINTER_SIZE)
                if len(raw) < ITEM_POINTER_SIZE:
                    break
                key_raw, data_offset, data_size = struct.unpack("<17sII", raw)
                object_id = struct.unpack_from("<Q", key_raw, 0)[0]
                item_type = key_raw[8]
                abs_data = phys + NODE_HEADER_SIZE + data_offset

                if item_type == BTRFS_INODE_ITEM_KEY and data_size >= 160:
                    f.seek(abs_data)
                    parsed = parse_inode_item(f.read(160))
                    if parsed:
                        inv = inventory.setdefault(object_id, {
                            "filename": None, "size": 0, "has_data": False,
                            "nlink": parsed["nlink"],
                        })
                        inv["size"] = parsed["size"]

                elif item_type == BTRFS_INODE_REF_KEY and object_id > 0:
                    # INODE_REF: objectid = inode, data = index(8)+name_len(2)+name
                    if data_size >= 10:
                        f.seek(abs_data)
                        name_len = struct.unpack_from("<H", f.read(10), 8)[0]
                        if 0 < name_len <= 255 and 10 + name_len <= data_size:
                            raw_name = f.read(name_len)
                            try:
                                name = raw_name.decode("utf-8", errors="replace")
                                if name.isprintable() and name.strip():
                                    inventory.setdefault(object_id, {
                                        "filename": None, "size": 0,
                                        "has_data": False, "nlink": 0,
                                    })["filename"] = name
                            except Exception:
                                pass

                elif item_type in (BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY) \
                        and data_size >= DIR_ITEM_HEADER_SIZE:
                    # DIR_ITEM: target inode key(17) + transid(8) + ... + name
                    f.seek(abs_data)
                    dir_header = f.read(DIR_ITEM_HEADER_SIZE)
                    target_inode = struct.unpack_from("<Q", dir_header, 0)[0]
                    name_len = struct.unpack_from("<H", dir_header, 27)[0]
                    if 0 < name_len <= 255 and target_inode > 0:
                        raw_name = f.read(name_len)
                        try:
                            name = raw_name.decode("utf-8", errors="replace")
                            if name.isprintable() and name.strip():
                                inventory.setdefault(target_inode, {
                                    "filename": None, "size": 0,
                                    "has_data": False, "nlink": 0,
                                })["filename"] = name
                        except Exception:
                            pass

                elif item_type == BTRFS_EXTENT_DATA_KEY and object_id > 0:
                    inv = inventory.setdefault(object_id, {
                        "filename": None, "size": 0, "has_data": False,
                        "nlink": 0,
                    })
                    inv["has_data"] = True
                    if data_size >= FILE_EXTENT_HEADER_SIZE:
                        f.seek(abs_data)
                        ext_hdr = f.read(FILE_EXTENT_HEADER_SIZE)
                        ext_type = ext_hdr[20]
                        if ext_type in (BTRFS_FILE_EXTENT_INLINE,
                                        BTRFS_FILE_EXTENT_REG):
                            inv["size"] = max(
                                inv["size"], data_size - FILE_EXTENT_HEADER_SIZE)

    walk_tree(image_path, fs_root, sb_data["chunk_map"], sb_data["nodesize"],
              on_leaf=on_leaf)
    return inventory


def analyze_historical_states(image_path, sb_data, backups, report,
                              current_inventory=None):
    """
    Walk every validated backup fs tree, compare with the current state, and
    tag sweep-recovered files with anchored provenance.

    Populates on `report`:
        - backup_roots_parsed / backup_roots_valid / historical_states_walked
        - historical_states: [{gen, fs_root, node_count, files: [...]}]
        - deleted_since_backup: count of files present in a historical state
          but missing from the current fs tree
    """
    if current_inventory is None:
        current_root = get_current_fs_tree_root(image_path, sb_data)
        current_inventory = (
            collect_fs_tree_state(image_path, sb_data, current_root,
                                  sb_data["generation"])
            if current_root else {})

    report.backup_roots_parsed = len(backups)
    report.backup_roots_valid = sum(
        1 for b in backups if b.get("valid_roots"))
    report.current_fs_inodes = len(current_inventory)

    states = []
    for backup in backups:
        if not backup.get("fs_root"):
            continue
        inventory = collect_fs_tree_state(image_path, sb_data,
                                          backup["fs_root"], backup["gen"])
        state = {
            "gen":        backup["gen"],
            "fs_root":    backup["fs_root"],
            "validated":  "fs_root" in backup.get("valid_roots", set()),
            "node_count": None,  # set below via walk count if needed
            "files": [
                {"inode": ino, "filename": inv["filename"],
                 "size": inv["size"], "has_data": inv["has_data"],
                 "nlink": inv["nlink"]}
                for ino, inv in sorted(inventory.items())
            ],
            "file_count": len(inventory),
        }
        deleted = [{"inode": ino, "filename": inv["filename"]}
                   for ino, inv in inventory.items()
                   if ino not in current_inventory]
        state["deleted_since"] = deleted
        report.deleted_since_backup += len(deleted)
        states.append(state)
        print(f"    [ANCHORED] gen {backup['gen']} fs_tree 0x{backup['fs_root']:X}: "
              f"{len(inventory)} inode(s), {len(deleted)} deleted since")

    report.historical_states = states
    report.historical_states_walked = len(states)

    # Tag sweep-recovered artifacts that appear in a historical state.
    anchored_pairs = set()
    for state in states:
        for f in state["files"]:
            anchored_pairs.add((f["inode"], state["gen"]))
    confirmed = 0
    for entry in report.recovered_files:
        if (entry.get("inode"), entry.get("generation")) in anchored_pairs:
            entry["provenance"] = "anchored"
            confirmed += 1
    report.anchored_files_confirmed = confirmed
    return states
