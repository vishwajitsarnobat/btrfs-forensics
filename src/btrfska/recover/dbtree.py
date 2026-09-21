"""Walk a tree in the evidence database, from any cataloged root (plan.md M4b, decision 1), and
find the leaves no cataloged root reaches (M4d).

The database holds every valid block the scan found, at whatever physical offset, with its items
or key pointers. A tree is therefore walked without the image and without a chunk map: root block,
`key_ptrs`, the child with that (bytenr, generation) one level down, and so on to the leaves.
That reaches blocks of removed chunks, which a walk through the image cannot address.

A pointer whose child was not scanned as a valid block is a gap: it is reported and nothing
below it is known. A child whose first key is not the pointer's key is not followed either.
"""

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass

from btrfska.catalog.schema import s64, u64
from btrfska.substrate.node import Item, Key, is_subvolume_tree
from btrfska.substrate.ondisk import FS_TREE_OBJECTID as FS_TREE


class RootNotCataloged(LookupError):
    """The database holds no such root, or not the tree asked for under it."""


@dataclass(frozen=True)
class Root:
    """One tree as one cataloged root tree names it."""

    source: str  # current, backup:GEN or state:ID; orphan_node:BYTENR for a leaf on its own
    state_id: int | None
    tree_id: int
    bytenr: int
    generation: int
    level: int
    kind: str = "anchored_root"  # or orphan_node: `bytenr` is then a leaf no state reaches


@dataclass(frozen=True)
class Leaf:
    content_id: int
    bytenr: int
    generation: int
    physical: int  # the lowest offset among the valid copies holding this content
    status: str  # live, backup_reachable or unreferenced: the best status among those copies


def _state(conn: sqlite3.Connection, spec: str) -> int:
    kind, _, number = spec.partition(":")
    states = conn.execute("SELECT state_id, known_as FROM states ORDER BY state_id").fetchall()
    if kind == "state" and number.isdigit():
        matching = [row[0] for row in states if row[0] == int(number)]
    elif spec == "current" or (kind == "backup" and number.isdigit()):
        matching = [row[0] for row in states if spec in json.loads(row[1])]
    else:
        raise RootNotCataloged(f"invalid root {spec!r}: expected current, backup:GEN or state:ID")
    if not matching:
        raise RootNotCataloged(f"the database holds no root tree for {spec!r}")
    return matching[0]


def resolve_roots(conn: sqlite3.Connection, spec: str, tree_id: int | None) -> list[Root]:
    """The root block of tree `tree_id` under `current`, `backup:GEN` or `state:ID`.

    With `tree_id` None: every file tree that root tree names, the top-level fs tree and each
    subvolume and snapshot, in tree id order. A snapshot's ROOT_ITEM is keyed by the transaction
    that took it; a tree with several ROOT_ITEMs is read from the one with the highest offset.
    """
    state_id = _state(conn, spec)
    rows = conn.execute(
        "SELECT tree_id, bytenr, generation, level FROM state_trees WHERE state_id = ?"
        " ORDER BY key_offset",
        (state_id,),
    ).fetchall()
    trees = {u64(row[0]): row for row in rows}  # the highest key offset wins
    if tree_id is None:
        wanted = sorted(tree for tree in trees if tree == FS_TREE or is_subvolume_tree(tree))
    elif tree_id in trees:
        wanted = [tree_id]
    else:
        raise RootNotCataloged(f"root {spec!r} names no tree {tree_id}")
    return [
        Root(spec, state_id, tree, u64(trees[tree][1]), u64(trees[tree][2]), trees[tree][3])
        for tree in wanted
    ]


def every_state(conn: sqlite3.Connection) -> list[str]:
    """`state:ID` for every cataloged root tree, in the catalog's order (newest first)."""
    rows = conn.execute("SELECT state_id FROM states ORDER BY state_id")
    return [f"state:{row[0]}" for row in rows]


def orphan_leaves(conn: sqlite3.Connection) -> list[tuple[Root, Leaf]]:
    """Valid file-tree leaves that no cataloged state reaches, each as a root of its own.

    Reached means: among the leaves of tree 5 or of a subvolume under any row of `states`. That
    is stricter than `nodes.status`, which knows the current and the backup roots only.
    """
    reached: set[int] = set()
    for spec in every_state(conn):
        for root in resolve_roots(conn, spec, None):
            reached.update(leaf.content_id for leaf in tree_leaves(conn, root)[0])
    rows = conn.execute(
        "SELECT content_id, bytenr, generation, owner, first_physical, live, backup_reachable"
        " FROM content_blocks WHERE level = 0 ORDER BY owner, generation DESC, bytenr"
    ).fetchall()
    found = []
    for content_id, bytenr, generation, owner, physical, live, backup in rows:
        tree = u64(owner)
        if content_id in reached or not is_subvolume_tree(tree):
            continue
        status = "live" if live else "backup_reachable" if backup else "unreferenced"
        leaf = Leaf(content_id, u64(bytenr), u64(generation), physical, status)
        root = Root(
            f"orphan_node:{leaf.bytenr}", None, tree, leaf.bytenr, leaf.generation, 0,
            kind="orphan_node",
        )  # fmt: skip
        found.append((root, leaf))
    return found


def former_names(conn: sqlite3.Connection, tree_id: int, objectid: int, created: int):
    """Names `objectid` had in tree `tree_id`, from leaves of any generation that also hold its
    INODE_ITEM with creation generation `created` (inode numbers are reused; the pair is not).
    Rows of (parent, name bytes, index, extended, leaf generation), newest leaf first."""
    rows = conn.execute(
        "SELECT DISTINCT r.parent_objectid, r.name_raw, r.dir_index, r.extended, b.generation"
        " FROM inode_refs r"
        " JOIN inodes i ON i.content_id = r.content_id AND i.objectid = r.objectid"
        " JOIN content_blocks b ON b.content_id = r.content_id"
        " WHERE r.objectid = ? AND i.generation = ? AND b.owner = ?"
        " ORDER BY b.generation DESC, r.dir_index",
        (s64(objectid), s64(created), s64(tree_id)),
    ).fetchall()
    return [(u64(row[0]), bytes(row[1]), u64(row[2]), bool(row[3]), u64(row[4])) for row in rows]


def resolve_root(conn: sqlite3.Connection, spec: str, tree_id: int) -> Root:
    return resolve_roots(conn, spec, tree_id)[0]


def _block(conn: sqlite3.Connection, bytenr: int, generation: int, level: int):
    """(content_id, physical, status, first_key) of the valid block, or None."""
    return conn.execute(
        "SELECT n.content_id, MIN(n.physical),"
        " CASE WHEN MAX(n.status = 'live') THEN 'live'"
        "      WHEN MAX(n.status = 'backup_reachable') THEN 'backup_reachable'"
        "      ELSE 'unreferenced' END, c.first_key"
        " FROM nodes n JOIN contents c USING (content_id)"
        " WHERE n.valid = 1 AND n.bytenr = ? AND n.generation = ? AND n.level = ?"
        " GROUP BY n.content_id ORDER BY MIN(n.physical) LIMIT 1",
        (s64(bytenr), s64(generation), level),
    ).fetchone()


def tree_leaves(conn: sqlite3.Connection, root: Root) -> tuple[list[Leaf], list[str]]:
    """The leaves of `root`'s tree in key order, and one line per gap."""
    leaves, gaps, seen = [], [], set()
    stack = [(root.bytenr, root.generation, root.level, None)]
    while stack:
        bytenr, generation, level, expected_key = stack.pop()
        where = f"block {bytenr} generation {generation} level {level}"
        if (bytenr, generation) in seen:
            gaps.append(f"{where}: reached twice; not followed again")
            continue
        seen.add((bytenr, generation))
        if not 0 <= level < 8:
            gaps.append(f"{where}: impossible level")
            continue
        found = _block(conn, bytenr, generation, level)
        if found is None:
            gaps.append(f"{where}: not among the valid scanned blocks")
            continue
        content_id, physical, status, first_key = found
        if expected_key is not None and first_key is not None and first_key != expected_key:
            gaps.append(f"{where}: its first key is not the key its parent points to")
            continue
        if level == 0:
            leaves.append(Leaf(content_id, bytenr, generation, physical, status))
            continue
        children = conn.execute(
            "SELECT blockptr, ptr_generation, key_sort FROM key_ptrs WHERE content_id = ?"
            " ORDER BY slot DESC",
            (content_id,),
        ).fetchall()
        stack.extend((u64(ptr), u64(gen), level - 1, key) for ptr, gen, key in children)
    return leaves, gaps


def leaf_items(conn: sqlite3.Connection, leaf: Leaf) -> Iterator[Item]:
    """The items of one leaf in slot order, as the substrate's `Item`."""
    rows = conn.execute(
        "SELECT slot, key_objectid, key_type, key_offset, data_offset, data_size, data"
        " FROM items WHERE content_id = ? ORDER BY slot",
        (leaf.content_id,),
    )
    for slot, objectid, key_type, offset, data_offset, data_size, data in rows:
        yield Item(slot, Key(u64(objectid), key_type, u64(offset)), data_offset, data_size, data)
