# utils/orphan_scan.py
# Structure-aware helpers for the targeted orphan-node scan (M2).
#
# The brute-force sweep treats the whole image uniformly. The targeted scan
# instead uses Btrfs structural patterns to know *where* metadata nodes can
# live and *which* blocks are currently allocated:
#
#   1. Typed chunk map  -> candidate physical regions (METADATA/SYSTEM
#      chunks plus unmapped gaps left by relocated/removed chunks).
#   2. Extent tree      -> the set of currently-allocated metadata blocks
#      (METADATA_ITEM / EXTENT_ITEM entries), reachable via the root tree's
#      ROOT_ITEM for the extent tree.
#
# The live set is a classification aid: live blocks are current filesystem
# state, everything else in the candidate regions is orphan territory.

import struct
from .constants import (
    NODE_HEADER_SIZE, ITEM_POINTER_SIZE,
    BTRFS_ROOT_ITEM_KEY, BTRFS_EXTENT_TREE_OBJECTID,
    BTRFS_METADATA_ITEM_KEY, BTRFS_EXTENT_ITEM_KEY,
    ROOT_ITEM_BYTENR_OFFSET,
)
from .chunk_parser import translate_logical_to_physical
from .tree_walker import walk_tree


def _find_tree_root_by_objectid(image_path, root_tree_addr, chunk_map,
                                nodesize, target_objectid):
    """
    Walk the root tree and return the tree-root logical address of the tree
    whose ROOT_ITEM has the given objectid (e.g. 2 = extent tree), or None.
    """
    found = {"bytenr": None}

    def on_leaf(laddr, phys, nritems, header):
        if found["bytenr"] is not None:
            return
        with open(image_path, "rb") as f:
            for i in range(nritems):
                ptr_off = phys + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
                f.seek(ptr_off)
                raw = f.read(ITEM_POINTER_SIZE)
                if len(raw) < ITEM_POINTER_SIZE:
                    break
                key_raw, data_offset, data_size = struct.unpack("<17sII", raw)
                obj_id = struct.unpack_from("<Q", key_raw, 0)[0]
                item_type = key_raw[8]
                if (item_type == BTRFS_ROOT_ITEM_KEY
                        and obj_id == target_objectid
                        and data_size > ROOT_ITEM_BYTENR_OFFSET):
                    f.seek(phys + NODE_HEADER_SIZE + data_offset)
                    root_item = f.read(ROOT_ITEM_BYTENR_OFFSET + 8)
                    if len(root_item) >= ROOT_ITEM_BYTENR_OFFSET + 8:
                        found["bytenr"] = struct.unpack_from(
                            "<Q", root_item, ROOT_ITEM_BYTENR_OFFSET)[0]
                        return

    walk_tree(image_path, root_tree_addr, chunk_map, nodesize, on_leaf=on_leaf)
    return found["bytenr"]


def get_extent_tree_root(image_path, sb_data):
    """Logical address of the extent tree root, or None."""
    return _find_tree_root_by_objectid(
        image_path, sb_data["root_tree_addr"], sb_data["chunk_map"],
        sb_data["nodesize"], BTRFS_EXTENT_TREE_OBJECTID)


def get_live_metadata_blocks(image_path, sb_data, extent_tree_root=None):
    """
    Collect the set of *physical* offsets of currently-allocated metadata
    blocks, as recorded in the extent tree (METADATA_ITEM / EXTENT_ITEM).

    Returns (live_phys_offsets, live_logical_addrs).
    """
    if extent_tree_root is None:
        extent_tree_root = get_extent_tree_root(image_path, sb_data)
    if extent_tree_root is None:
        return set(), set()

    chunk_map = sb_data["chunk_map"]
    nodesize = sb_data["nodesize"]
    live_logical = set()

    def on_leaf(laddr, phys, nritems, header):
        with open(image_path, "rb") as f:
            for i in range(nritems):
                ptr_off = phys + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
                f.seek(ptr_off)
                raw = f.read(ITEM_POINTER_SIZE)
                if len(raw) < ITEM_POINTER_SIZE:
                    break
                key_raw, _data_offset, _data_size = struct.unpack("<17sII", raw)
                item_type = key_raw[8]
                if item_type in (BTRFS_METADATA_ITEM_KEY,
                                 BTRFS_EXTENT_ITEM_KEY):
                    bytenr = struct.unpack_from("<Q", key_raw, 0)[0]
                    if bytenr != 0:
                        live_logical.add(bytenr)

    walk_tree(image_path, extent_tree_root, chunk_map, nodesize, on_leaf=on_leaf)

    live_phys = set()
    for laddr in live_logical:
        phys = translate_logical_to_physical(laddr, chunk_map)
        if phys is not None:
            live_phys.add(phys)
    return live_phys, live_logical
