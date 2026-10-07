"""Which csum trees a recovery verifies a root's file data against (plan.md M6a, decision 2).

The csum trees come from the evidence database, walked like any other tree (`dbtree`), so a
state's csum tree is read even where the current chunk map no longer places its blocks. For each
root, in order:
- an anchored root: the csum tree its own state names (`state_trees`, tree 7), then the current
  state's;
- a log tree: its own EXTENT_CSUM items (tree-log.c:5023 `log_extent_csums`; never complete, a
  log holds only what changed), then the csum tree of its base state, then the current one;
- a leaf or fragment without a state: the oldest cataloged state not older than its generation,
  the first commit that could hold the checksums of what it points to, then the current one.
A tree walked without a gap is complete: its lack of a checksum is final (datacsum.Csums). A
state that names no csum tree gives an empty tree that is not complete, so the next one is
asked.
"""

import json
import sqlite3

from btrfska.catalog.schema import s64, u64
from btrfska.recover.dbtree import Leaf, Root, leaf_items, tree_leaves
from btrfska.substrate.datacsum import Csums, CsumTree
from btrfska.substrate.ondisk import CSUM_TREE_OBJECTID as CSUM_TREE


def _label(state_id: int, known_as: str) -> str:
    """The state as the superblock names it, when it does; else `state:ID`."""
    names = json.loads(known_as)
    return "current" if "current" in names else (names[0] if names else f"state:{state_id}")


class CsumTrees:
    """The csum trees of one recovery, each read once."""

    def __init__(self, conn: sqlite3.Connection, csum_type: int, sectorsize: int) -> None:
        self.conn, self.csum_type, self.sectorsize = conn, csum_type, sectorsize
        self.by_state: dict[int, CsumTree] = {}
        self.read: list[CsumTree] = []  # every tree read, in order, for the run's summary
        rows = conn.execute("SELECT state_id, known_as FROM states ORDER BY state_id").fetchall()
        self.labels = {state_id: _label(state_id, known_as) for state_id, known_as in rows}
        self.current = next(
            (state_id for state_id, known_as in rows if "current" in json.loads(known_as)), None
        )

    def _tree(self, source: str, complete: bool) -> CsumTree:
        tree = CsumTree(source, self.csum_type, self.sectorsize, complete=complete)
        self.read.append(tree)
        return tree

    def _add(self, tree: CsumTree, leaves: list[Leaf]) -> None:
        for leaf in leaves:
            for item in leaf_items(self.conn, leaf):
                tree.add(item, f"leaf {leaf.bytenr} slot {item.slot}")

    def state(self, state_id: int) -> CsumTree:
        """The csum tree state `state_id` names."""
        if state_id in self.by_state:
            return self.by_state[state_id]
        source = self.labels.get(state_id, f"state:{state_id}")
        row = self.conn.execute(
            "SELECT bytenr, generation, level FROM state_trees WHERE state_id = ? AND tree_id = ?"
            " ORDER BY key_offset DESC LIMIT 1",
            (state_id, s64(CSUM_TREE)),
        ).fetchone()
        if row is None:
            tree = self._tree(source, complete=False)
            tree.problems.append("the state names no csum tree")
        else:
            root = Root(source, state_id, CSUM_TREE, u64(row[0]), u64(row[1]), row[2])
            leaves, gaps = tree_leaves(self.conn, root)
            tree = self._tree(source, complete=not gaps)
            tree.problems += gaps[:8]
            self._add(tree, leaves)
        self.by_state[state_id] = tree
        return tree

    def _first_state_from(self, generation: int) -> int | None:
        row = self.conn.execute(
            "SELECT state_id FROM states WHERE generation >= ? ORDER BY generation, state_id"
            " LIMIT 1",
            (s64(generation),),
        ).fetchone()
        return None if row is None else row[0]

    def for_root(self, root: Root, leaves: list[Leaf] = (), base: Root | None = None) -> Csums:
        """The trees to ask for `root`'s data. `leaves` are a log tree's own leaves, `base` its
        base state's root (recover/logs.py)."""
        trees, states = [], []
        if root.kind == "log_tree":
            own = self._tree(root.source, complete=False)
            self._add(own, list(leaves))
            trees.append(own)
            states.append(None if base is None else base.state_id)
        elif root.state_id is not None:
            states.append(root.state_id)
        else:
            states.append(self._first_state_from(root.generation))
        states.append(self.current)
        for state_id in dict.fromkeys(states):
            if state_id is not None:
                trees.append(self.state(state_id))
        return Csums(trees, self.csum_type, self.sectorsize)

    def summary(self) -> dict:
        """Per tree read: whether it is complete, its items and its findings."""
        found = {}
        for tree in self.read:
            found.setdefault(
                tree.source,
                {"complete": tree.complete, "items": tree.items, "problems": tree.notes()},
            )
        return found
