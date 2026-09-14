# utils/tree_walker.py
# Generic anchored B-tree walker.
#
# Given the logical address of a tree root plus the chunk map, walks the
# entire tree (internal nodes -> leaves) and invokes callbacks. This is the
# reusable primitive behind root-tree walking, extent-tree walking, and the
# future anchored historical reconstruction (M1). It mirrors the pattern
# already proven in chunk_parser._walk_chunk_tree_node, generalized.

import struct
from .constants import (
    NODE_HEADER_SIZE, KEY_PTR_SIZE,
    NH_LEVEL, NH_NRITEMS,
)
from .chunk_parser import translate_logical_to_physical


def walk_tree(image_path, root_logical, chunk_map, nodesize,
              on_leaf=None, on_internal=None, validate_crc=False,
              crc32c=None):
    """
    Walk a Btrfs metadata tree starting at the given logical root.

    Args:
        image_path:   path to the raw disk image
        root_logical: logical address of the tree root node
        chunk_map:    chunk map for logical -> physical translation
        nodesize:     node size in bytes
        on_leaf:      callback(laddr, phys, nritems, header_bytes) per leaf
        on_internal:  callback(laddr, phys, level, nritems, header_bytes)
                      per internal node (called before descending)
        validate_crc: if True, only descend into CRC-valid nodes
                      (requires the crc32c function)
        crc32c:       CRC32c implementation used when validate_crc is True

    Nodes are visited depth-first. Shared/duplicate nodes (snapshots) are
    visited once. Returns the set of logical addresses visited.
    """
    visited = set()
    stack = [root_logical]

    with open(image_path, "rb") as f:
        while stack:
            laddr = stack.pop()
            if laddr in visited:
                continue
            visited.add(laddr)

            phys = translate_logical_to_physical(laddr, chunk_map)
            if phys is None:
                continue

            f.seek(phys)
            header = f.read(NODE_HEADER_SIZE)
            if len(header) < NODE_HEADER_SIZE:
                continue

            if validate_crc:
                f.seek(phys)
                node_bytes = f.read(nodesize)
                if len(node_bytes) < nodesize:
                    continue
                stored_csum = struct.unpack_from("<I", node_bytes, 0)[0]
                if crc32c is None or stored_csum != crc32c(node_bytes[32:]):
                    continue

            level = header[NH_LEVEL]
            nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]

            if level == 0:
                if on_leaf is not None:
                    on_leaf(laddr, phys, nritems, header)
                continue

            if on_internal is not None:
                on_internal(laddr, phys, level, nritems, header)

            for i in range(nritems):
                ptr_off = phys + NODE_HEADER_SIZE + (i * KEY_PTR_SIZE)
                f.seek(ptr_off)
                ptr_raw = f.read(KEY_PTR_SIZE)
                if len(ptr_raw) < KEY_PTR_SIZE:
                    break
                child_logical = struct.unpack_from("<Q", ptr_raw, 17)[0]
                stack.append(child_logical)

    return visited
