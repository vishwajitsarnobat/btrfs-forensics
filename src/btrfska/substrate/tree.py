"""Anchored tree walking with per-hop validation, and fs-tree inventories.

`walk(reader, bytenr, expect)` reads the block at `bytenr` and descends depth-first in key order.
Each child is read with the expectations its parent pointer implies: level one lower, the tree's
owner, the pointer's generation and key, and the start's log context. Those checks are therefore
recorded on the child's copies (see node.py). The walker adds its own hop findings to each `Visit`:
- a pointer to a block already reached in this walk (a cycle or a shared block) is not followed;
- a child whose last key is not below the parent's next key.
An invalid node is yielded but not descended, because its pointers cannot be trusted. Depth is
bounded: levels are below 8 and must drop by one per hop.
"""

import stat
from collections.abc import Iterator
from dataclasses import dataclass

from btrfska.substrate import items, ondisk
from btrfska.substrate.node import NO_EXPECTATIONS, Expect, Item, NodeReader, ValidatedNode

K = ondisk.ITEM_KEYS


class IncompleteTree(Exception):
    """A tree could not be read completely: an invalid node, a hop problem or a malformed item."""


@dataclass(frozen=True)
class Visit:
    node: ValidatedNode
    parent: int | None  # logical address of the parent node; None for the start block
    slot: int | None  # the pointer's slot in the parent
    depth: int
    problems: tuple[str, ...] = ()  # hop findings; node findings are in node.problems
    expect: Expect = NO_EXPECTATIONS  # what the referrer said the block must be


def walk(reader: NodeReader, bytenr: int, expect: Expect = NO_EXPECTATIONS) -> Iterator[Visit]:
    """Every node reachable from `bytenr`, parents before children, children in key order."""
    claimed = {bytenr}
    stack = [(bytenr, expect, None, None, 0, None)]
    while stack:
        logical, expected, parent, slot, depth, upper = stack.pop()
        node = reader.read(logical, expected)
        problems, children = [], []
        if node.valid:
            keys = (
                [i.key for i in node.items] if node.level == 0 else [p.key for p in node.key_ptrs]
            )
            if upper is not None and keys and keys[-1] >= upper:
                problems.append(f"last key {keys[-1]} is not below the parent's next key {upper}")
            ptrs = node.key_ptrs if node.level else ()
            for index, ptr in enumerate(ptrs):
                if ptr.blockptr in claimed:
                    problems.append(
                        f"slot {index} points to {ptr.blockptr}, already reached in this walk; "
                        "not followed"
                    )
                    continue
                claimed.add(ptr.blockptr)
                child_expect = Expect(
                    level=node.level - 1,
                    owner=expected.owner,
                    generation=ptr.generation,
                    first_key=ptr.key,
                    log=expected.log,
                )
                child_upper = ptrs[index + 1].key if index + 1 < len(ptrs) else upper
                children.append(
                    (ptr.blockptr, child_expect, logical, index, depth + 1, child_upper)
                )
        yield Visit(node, parent, slot, depth, tuple(problems), expected)
        stack.extend(reversed(children))


def leaf_items(visits) -> Iterator[tuple[Visit, Item]]:
    """(visit, item) for every item of every valid leaf among `visits`."""
    for visit in visits:
        if visit.node.valid and visit.node.level == 0:
            for item in visit.node.items:
                yield visit, item


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _extent(offset: int, extent: dict) -> dict:
    kind = items.EXTENT_TYPE_NAMES.get(extent["type"], f"type {extent['type']}")
    if extent["type"] == ondisk.FILE_EXTENT_INLINE:
        return {
            "offset": offset,
            "type": kind,
            "ram_bytes": extent["ram_bytes"],
            "compression": extent["compression"],
        }
    return {
        "offset": offset,
        "type": kind,
        "disk_bytenr": extent["disk_bytenr"],
        "disk_num_bytes": extent["disk_num_bytes"],
        "num_bytes": extent["num_bytes"],
        "compression": extent["compression"],
    }


def _add(inodes: dict[int, dict], item: Item) -> None:
    key = item.key
    if key.type == K["INODE_ITEM"]:
        inode = items.inode_item(item.data)
        entry = inodes.setdefault(key.objectid, {})
        entry["kind"], entry["size"] = _kind(inode["mode"]), inode["size"]
        if entry["kind"] == "dir":
            entry.setdefault("entries", {})
    elif key.type == K["INODE_REF"] and key.offset != key.objectid:  # not a subvolume root's ".."
        entry = inodes.setdefault(key.objectid, {})
        entry.setdefault("name", items.inode_refs(item.data)[0]["name"])
        entry.setdefault("parent", key.offset)
    elif key.type == K["DIR_INDEX"]:
        entries = inodes.setdefault(key.objectid, {}).setdefault("entries", {})
        for dir_entry in items.dir_items(item.data):
            entries[dir_entry["name"]] = dir_entry["location"].objectid
    elif key.type == K["EXTENT_DATA"]:
        extent = _extent(key.offset, items.file_extent(item.data))
        inodes.setdefault(key.objectid, {}).setdefault("extents", []).append(extent)


def fs_tree_inventory(
    reader: NodeReader, bytenr: int, expect: Expect = NO_EXPECTATIONS
) -> dict[int, dict]:
    """Inodes of the fs tree at `bytenr`: kind, size, name and parent, dir entries, extents.

    A directory maps entry names to objectids (DIR_INDEX); a file or subdirectory takes its first
    INODE_REF name. Raises IncompleteTree rather than returning a partial inventory.
    """
    inodes: dict[int, dict] = {}
    for visit in walk(reader, bytenr, expect):
        node = visit.node
        if not node.valid or visit.problems:
            findings = "; ".join(visit.problems if node.valid else node.problems)
            raise IncompleteTree(f"tree at {bytenr}: node {node.logical}: {findings}")
        for item in node.items if node.level == 0 else ():
            try:
                _add(inodes, item)
            except items.ItemError as exc:
                message = f"tree at {bytenr}: item {item.key} in {node.logical}: {exc}"
                raise IncompleteTree(message) from None
    return inodes
