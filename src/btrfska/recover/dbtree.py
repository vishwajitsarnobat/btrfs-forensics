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
from btrfska.substrate.node import Item, Key, is_subvolume_tree, owner_ok
from btrfska.substrate.ondisk import FS_TREE_OBJECTID as FS_TREE
from btrfska.substrate.ondisk import ROOT_TREE_OBJECTID as ROOT_TREE
from btrfska.substrate.ondisk import TREE_LOG_OBJECTID as LOG_TREE


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
    # anchored_root; orphan_node: `bytenr` is a leaf no state reaches, read on its own;
    # orphan_graph: `bytenr` is the top of a fragment (`fragment_roots`), or such a leaf with joins;
    # log_tree: a subvolume's log tree, named by a log root tree (recover/logs.py)
    kind: str = "anchored_root"
    subvolume: int | None = None  # log_tree: the subvolume it logged
    named_by: int | None = None  # log_tree: the log root leaf whose ROOT_ITEM names it


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
    """Valid file-tree leaves that no scanned root tree leads to, and leaves of dropped log
    trees, each as a root of its own.

    Reached means: among the leaves of a file tree whose root some ROOT_ITEM names, in any valid
    root-tree leaf the scan found, of any generation. That covers every cataloged state, root
    trees beyond the number evaluated as states, and root-tree leaves whose parent node is lost;
    `nodes.status` knows the current and the backup roots only.
    """
    named = conn.execute(
        "SELECT DISTINCT r.tree_id, r.bytenr, r.generation, r.level FROM root_items r"
        " JOIN content_blocks b USING (content_id) WHERE b.owner = ? AND r.bytenr != 0",
        (ROOT_TREE,),
    ).fetchall()
    reached: set[int] = set()
    for tree, bytenr, generation, level in named:
        if is_subvolume_tree(u64(tree)):
            root = Root("root_item", None, u64(tree), u64(bytenr), u64(generation), level)
            reached.update(leaf.content_id for leaf in tree_leaves(conn, root)[0])
    rows = conn.execute(
        "SELECT content_id, bytenr, generation, owner, MIN(physical), MAX(status = 'live'),"
        " MAX(status = 'backup_reachable'), MAX(log_tree) FROM nodes"
        " WHERE valid = 1 AND level = 0 AND content_id IS NOT NULL"
        " GROUP BY content_id, bytenr, generation, owner ORDER BY owner, generation DESC, bytenr"
    ).fetchall()
    found = []
    for content_id, bytenr, generation, owner, physical, live, backup, in_live_log in rows:
        tree = u64(owner)
        if tree == LOG_TREE:
            # A leaf of a log tree: what fsync wrote between two commits. The log the superblock
            # still names is not orphaned (replaying it is reconstruction, plan.md M5); a log
            # tree dropped by a later commit is, and no root tree ever pointed to it.
            if in_live_log:
                continue
        elif content_id in reached or not is_subvolume_tree(tree):
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


def _block(conn: sqlite3.Connection, bytenr: int, generation: int, level: int):
    """(content_id, physical, status, first_key, owner) of the valid block, or None."""
    return conn.execute(
        "SELECT n.content_id, MIN(n.physical),"
        " CASE WHEN MAX(n.status = 'live') THEN 'live'"
        "      WHEN MAX(n.status = 'backup_reachable') THEN 'backup_reachable'"
        "      ELSE 'unreferenced' END, c.first_key, n.owner"
        " FROM nodes n JOIN contents c USING (content_id)"
        " WHERE n.valid = 1 AND n.bytenr = ? AND n.generation = ? AND n.level = ?"
        " GROUP BY n.content_id ORDER BY MIN(n.physical) LIMIT 1",
        (s64(bytenr), s64(generation), level),
    ).fetchone()


def _mismatched(conn: sqlite3.Connection, tree_id: int, bytenr: int, generation: int, level: int):
    """What the database holds at `bytenr` instead of the block a pointer names: a sentence for
    the gap line, or "". Such a block passes every integrity check (it is valid as scanned) and
    fails linkage checks against this pointer (node.py, plan.md M5b). It is another block,
    usually a newer one, and it is never followed: read as part of this tree it would show a
    state that did not exist."""
    rows = conn.execute(
        "SELECT DISTINCT generation, level, owner FROM nodes WHERE valid = 1 AND bytenr = ?"
        " ORDER BY generation DESC LIMIT 3",
        (s64(bytenr),),
    ).fetchall()
    found = []
    for other_generation, other_level, owner in rows:
        failed = []
        if other_level != level:
            failed.append("level")
        if owner_ok(tree_id, u64(owner)) is False:
            failed.append("owner")
        if u64(other_generation) != generation:
            failed.append("parent_generation")
        found.append(
            f"generation {u64(other_generation)} level {other_level} owner {u64(owner)} "
            f"(linkage mismatch: {', '.join(failed)})"
        )
    if not found:
        return ""
    return "; a valid block lies at that address, not followed: " + "; ".join(found)


def leaf_by_content(conn: sqlite3.Connection, content_id: int) -> Leaf | None:
    """The valid leaf holding this content, as `orphan_leaves` describes one."""
    row = conn.execute(
        "SELECT bytenr, generation, MIN(physical), MAX(status = 'live'),"
        " MAX(status = 'backup_reachable') FROM nodes"
        " WHERE valid = 1 AND level = 0 AND content_id = ? GROUP BY bytenr, generation"
        " ORDER BY generation DESC LIMIT 1",
        (content_id,),
    ).fetchone()
    if row is None:
        return None
    status = "live" if row[3] else "backup_reachable" if row[4] else "unreferenced"
    return Leaf(content_id, u64(row[0]), u64(row[1]), row[2], status)


def fragment_roots(conn: sqlite3.Connection, limit: int) -> tuple[int, list[Root]]:
    """(how many there are, the newest `limit` of them): internal nodes of file trees that no
    scanned key pointer, no ROOT_ITEM and no superblock slot names (plan.md M5c). Each is the
    top of a fragment: a tree version that was never committed, or whose root tree is lost."""
    rows = conn.execute(
        "SELECT b.bytenr, b.generation, b.level, b.owner FROM blocks b WHERE b.level > 0"
        " AND NOT EXISTS (SELECT 1 FROM key_ptrs k"
        "   WHERE k.blockptr = b.bytenr AND k.ptr_generation = b.generation)"
        " AND NOT EXISTS (SELECT 1 FROM root_items r"
        "   WHERE r.bytenr = b.bytenr AND r.generation = b.generation)"
        " AND NOT EXISTS (SELECT 1 FROM known_roots n"
        "   WHERE n.bytenr = b.bytenr AND n.generation = b.generation)"
        " ORDER BY b.generation DESC, b.bytenr"
    ).fetchall()
    found = [
        Root(f"fragment:{u64(bytenr)}@{u64(generation)}", None, u64(owner), u64(bytenr),
             u64(generation), level, kind="orphan_graph")
        for bytenr, generation, level, owner in rows
        if is_subvolume_tree(u64(owner))
    ]  # fmt: skip
    return len(found), found[:limit]


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
            other = _mismatched(conn, root.tree_id, bytenr, generation, level)
            gaps.append(f"{where}: not among the valid scanned blocks{other}")
            continue
        content_id, physical, status, first_key, owner = found
        if owner_ok(root.tree_id, u64(owner)) is False:
            gaps.append(
                f"{where}: a block of tree {u64(owner)}, not of this tree (linkage mismatch: "
                "owner); not followed"
            )
            continue
        if expected_key is not None and first_key is not None and first_key != expected_key:
            gaps.append(
                f"{where}: its first key is not the key its parent points to (linkage mismatch: "
                "first_key); not followed"
            )
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
