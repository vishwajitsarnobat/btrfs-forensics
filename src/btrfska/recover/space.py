"""Where a recovery's extents and tree blocks lie in the current allocation, and how likely their
bytes are to be overwritten (plan.md M6b).

The allocation is the current state's, read from the evidence database like any tree (`dbtree`):
its free space tree (tree 10) when the superblock has FREE_SPACE_TREE and FREE_SPACE_TREE_VALID
(the kernel rebuilds a tree without VALID, disk-io.c:3062-3067) and the tree is walked without a
gap; otherwise free space derived from its extent tree (tree 2) and block groups (tree 11 with
BLOCK_GROUP_TREE). Both are read when both exist, and compared.

Bytes are placed by where they were read: the physical copy used, mapped back to a current logical
address (`ChunkMap.logical_of`). That places bytes read through a historical chunk map too. The
free space trees of older states, each read through its own state's chunk map, say between which
two commits the bytes became free (`freed_in`).

The discard mode is the one the examiner states, else the one the image shows (plan.md M6b,
decision 6): blocks a committed state points to that read as zeros (the scan's `zeroed` walk
failures), freed data sectors that read as zeros although a csum tree gives them a non-zero
checksum, and freed tree blocks and data that still hold their bytes.
"""

import json
import sqlite3

from btrfska.catalog.schema import s64, u64
from btrfska.recover.csums import CsumTrees
from btrfska.recover.dbtree import Leaf, Root, leaf_items, tree_leaves
from btrfska.recover.maps import stored_map
from btrfska.substrate import csum, ondisk
from btrfska.substrate.chunks import ChunkMap, MappingError
from btrfska.substrate.extents import ExtentRead
from btrfska.substrate.freespace import (
    BG,
    LEVELS,
    Discard,
    ExtentTree,
    FreeSpaceTree,
    Placement,
    SpaceView,
    observed_discard,
    overwrite_risk,
    super_stripes,
    verdict_of,
)
from btrfska.substrate.node import NodeReader

MAX_SAMPLES = 4096  # freed data extents read for discard evidence, newest first: a cost bound
EXTENT_TREE, FST, BGT = (
    ondisk.EXTENT_TREE_OBJECTID, ondisk.FREE_SPACE_TREE_OBJECTID, ondisk.BLOCK_GROUP_TREE_OBJECTID,
)  # fmt: skip
TRUSTED_FST = ondisk.COMPAT_RO["FREE_SPACE_TREE"] | ondisk.COMPAT_RO["FREE_SPACE_TREE_VALID"]


class SpaceViews:
    """The allocation views of one recovery, each read once, and the discard mode."""

    def __init__(self, conn: sqlite3.Connection, reader: NodeReader, *,
                 discard: str | None = None) -> None:  # fmt: skip
        self.conn, self.reader = conn, reader
        self.map: ChunkMap = reader.chunk_map
        self.nodesize, self.sectorsize = reader.ctx.nodesize, reader.ctx.sectorsize
        scan = conn.execute(
            "SELECT compat_ro_flags, incompat_flags, image_size FROM scan_runs"
        ).fetchone()
        compat_ro, incompat, self.device_size = scan if scan else (0, 0, reader.img.size)
        self.fst_trusted = compat_ro & TRUSTED_FST == TRUSTED_FST
        self.bgt = bool(compat_ro & ondisk.COMPAT_RO["BLOCK_GROUP_TREE"])
        self.zoned = bool(incompat & ondisk.INCOMPAT["ZONED"])
        rows = conn.execute(
            "SELECT state_id, generation, known_as, map_id FROM states"
            " ORDER BY generation, state_id"
        ).fetchall()
        self.states = [(row[0], u64(row[1]), json.loads(row[2]), row[3]) for row in rows]
        current = [s for s in self.states if "current" in s[2]]
        self.current_id = current[0][0] if current else None
        self.view = self._view(self.current_id) if self.current_id is not None else None
        self._history: list | None = None
        self._maps: dict[int, ChunkMap | None] = {}
        self._blocks: dict[int, Placement | None] = {}
        self.discard = Discard(discard, *self._observe())

    # ---- reading the trees -----------------------------------------------------------------
    def _root(self, state_id: int, tree: int) -> Root | None:
        row = self.conn.execute(
            "SELECT bytenr, generation, level FROM state_trees WHERE state_id = ? AND tree_id = ?"
            " ORDER BY key_offset DESC LIMIT 1",
            (state_id, s64(tree)),
        ).fetchone()
        if row is None:
            return None
        return Root(f"state:{state_id}", state_id, tree, u64(row[0]), u64(row[1]), row[2])

    def _read(self, state_id: int, tree: int, into) -> bool:
        """Every item of the state's tree into `into`; False when the tree is missing or was not
        walked without a gap."""
        root = self._root(state_id, tree)
        if root is None:
            into._problem(f"the state names no tree {tree}")
            return False
        leaves, gaps = tree_leaves(self.conn, root)
        for line in gaps[:4]:
            into._problem(f"tree {tree}: {line}")
        for leaf in leaves:
            for item in leaf_items(self.conn, leaf):
                into.add(item, f"leaf {leaf.bytenr} slot {item.slot}")
        return not gaps

    def _fst(self, state_id: int) -> FreeSpaceTree | None:
        if self._root(state_id, FST) is None:
            return None
        tree = FreeSpaceTree(f"free space tree of state:{state_id}", self.sectorsize)
        tree.complete = self._read(state_id, FST, tree)
        return tree

    def _view(self, state_id: int) -> SpaceView:
        extents = ExtentTree(f"extent tree of state:{state_id}", self.nodesize)
        extents.complete = self._read(state_id, EXTENT_TREE, extents)
        if self.bgt:
            extents.complete &= self._read(state_id, BGT, extents)
        fst = self._fst(state_id) if self.fst_trusted else None
        if fst is not None and not fst.complete and extents.complete:
            fst = None  # a tree with a gap gives way to the derivation from a whole extent tree
        excluded = super_stripes(self.map, extents.groups.values(), self.device_size)
        return SpaceView(extents if extents.items else None, fst, excluded)

    def _state_map(self, map_id: int | None) -> ChunkMap | None:
        if map_id is None:
            return None
        if map_id not in self._maps:
            row = self.conn.execute(
                "SELECT name, kind FROM chunk_maps WHERE map_id = ?", (map_id,)
            ).fetchone()
            if row is None:
                self._maps[map_id] = None
            elif row[1] == "current":
                self._maps[map_id] = self.map
            else:
                self._maps[map_id] = stored_map(self.conn, map_id, row[0], self.map.devices)
        return self._maps[map_id]

    def history(self) -> list[tuple[int, SpaceView, ChunkMap]]:
        """(generation, view of its free space tree, chunk map) of every state whose free space
        tree was read without a gap and whose chunk map is known, oldest first."""
        if self._history is None:
            self._history = []
            for state_id, generation, _, map_id in self.states if self.fst_trusted else ():
                chunk_map = self._state_map(map_id)
                tree = self._fst(state_id) if chunk_map is not None else None
                if tree is not None and tree.complete:
                    self._history.append((generation, SpaceView(None, tree), chunk_map))
        return self._history

    # ---- discard evidence --------------------------------------------------------------------
    def _wholly_free(self, logical: int, length: int, kinds: int) -> bool:
        free, _, _ = self.view.place(logical, logical + length)
        groups = self.view.groups_in(logical, logical + length)
        return free == length and all(g.flags is not None and g.flags & kinds for g in groups)

    def _observe(self) -> tuple[str, dict]:
        evidence = {"metadata_zeroed": 0, "metadata_intact": 0, "data_zeroed": 0,
                    "data_intact": 0, "data_zero_unverified": 0, "data_sampled": 0}  # fmt: skip
        if self.view is None or self.view.source is None:
            return "unknown", evidence
        evidence["metadata_zeroed"] = self.conn.execute(
            "SELECT COUNT(DISTINCT bytenr) FROM walk_failures WHERE failure_class = 'zeroed'"
        ).fetchone()[0]
        metadata = BG["METADATA"] | BG["SYSTEM"]
        for (physical,) in self.conn.execute(
            "SELECT DISTINCT physical FROM nodes WHERE valid = 1 AND orphan = 1"
        ):
            mapped = self.map.logical_of(None, physical)
            if mapped and mapped[1] >= self.nodesize:
                evidence["metadata_intact"] += self._wholly_free(mapped[0], self.nodesize, metadata)
        self._sample_data(evidence)
        intact = evidence["metadata_intact"] + evidence["data_intact"]
        mode = observed_discard(evidence["metadata_zeroed"], evidence["data_zeroed"], intact)
        return mode, evidence

    def _sample_data(self, evidence: dict) -> None:
        """The first sector of freed data extents named by leaves of the current chunk map's time
        (so that their logical addresses are the current map's): non-zero bytes mean no trim
        reached them; zeros whose checksum, in the csum tree of their time, is not that of zeros
        mean a trim did. Zeros without a checksum say nothing."""
        row = self.conn.execute(
            "SELECT root_generation FROM chunk_maps WHERE kind = 'current'"
        ).fetchone()
        if row is None or row[0] is None:
            return
        rows = self.conn.execute(
            "SELECT f.disk_bytenr, f.disk_num_bytes, MIN(f.generation) FROM file_extents f"
            " JOIN content_blocks b USING (content_id)"
            " WHERE f.extent_type = ? AND f.disk_bytenr != 0 AND b.generation >= ?"
            " GROUP BY f.disk_bytenr, f.disk_num_bytes ORDER BY MIN(f.generation) DESC",
            (ondisk.FILE_EXTENT_REG, row[0]),
        ).fetchall()
        sector, img = self.sectorsize, self.reader.img
        zeros = None
        trees = CsumTrees(self.conn, self.reader.ctx.csum_type, sector)
        for disk_bytenr, disk_num_bytes, generation in rows:
            if evidence["data_sampled"] >= MAX_SAMPLES:
                break
            start, length = u64(disk_bytenr), u64(disk_num_bytes)
            if not length or not self._wholly_free(start, length, BG["DATA"]):
                continue
            try:
                copy = self.map.copies(start, sector)[0]
            except MappingError:
                continue
            if copy.missing_device or copy.physical + sector > img.size:
                continue
            evidence["data_sampled"] += 1
            if any(img.mmap[copy.physical : copy.physical + sector]):
                evidence["data_intact"] += 1
                continue
            asked = Root("sample", None, ondisk.FS_TREE_OBJECTID, 0, u64(generation), 0,
                         kind="orphan_node")  # fmt: skip
            _, sums = trees.for_root(asked).lookup(start)
            zeros = zeros or csum.compute(self.reader.ctx.csum_type, bytes(sector))
            if sums and zeros not in sums:
                evidence["data_zeroed"] += 1
            else:
                evidence["data_zero_unverified"] += 1

    # ---- placing ------------------------------------------------------------------------------
    def _pieces(self, chunk_map: ChunkMap, pieces) -> list[tuple[int | None, int]]:
        return [found for devid, physical, length in pieces
                for found in chunk_map.logical_ranges(devid, physical, length)]  # fmt: skip

    def _freed_in(self, pieces, since: int) -> dict | None:
        """{"after": GEN or None, "by": GEN}: the first state not older than `since` whose free
        space tree holds every byte free, and the newest state before it that held some of them
        allocated (plan.md M6b, decision 7). None when no such state survives."""
        after = None
        for generation, view, chunk_map in self.history():
            if generation < since:
                continue
            logical = self._pieces(chunk_map, pieces)
            if any(start is None for start, _ in logical):
                continue  # that state's map does not place these bytes: it says nothing
            free = allocated = 0
            for start, n in logical:
                f, a, _ = view.place(start, start + n)
                free, allocated = free + f, allocated + a
            if free == sum(n for _, n in logical):
                return {"after": after, "by": generation}
            if allocated:
                after = generation
        return None

    def _place(self, pieces, held, since: int) -> Placement | None:
        """`pieces`: (devid or None, physical, length) of the bytes; `held`: a function of the
        view that says whether it still has the same allocation."""
        view = self.view
        if view is None or view.source is None:
            return None
        logical = self._pieces(self.map, pieces)
        free = allocated = outside = 0
        groups = {}
        for start, n in logical:
            if start is None:
                outside += n
                continue
            f, a, o = view.place(start, start + n)
            free, allocated, outside = free + f, allocated + a, outside + o
            for group in view.groups_in(start, start + n):
                groups[group.start] = group
        verdict = verdict_of(held(view), free, allocated, outside)
        risk, reasons = overwrite_risk(verdict, groups.values(), self.discard, self.zoned)
        return Placement(
            verdict, view.source, free + allocated + outside, free, allocated, outside,
            tuple(g.record() for g in groups.values()),
            None if verdict == "in_use" else self._freed_in(pieces, since), risk,
            LEVELS[risk], reasons,
        )  # fmt: skip

    def _parent_holds(self, parent: int, objectid: int, start: int) -> bool:
        """Whether the live leaf at `parent` has an EXTENT_DATA of inode `objectid` at `start`."""
        return (
            self.conn.execute(
                "SELECT 1 FROM file_extents f JOIN nodes n USING (content_id)"
                " WHERE n.bytenr = ? AND n.status = 'live' AND n.valid = 1 AND f.objectid = ?"
                " AND f.disk_bytenr = ? LIMIT 1",
                (s64(parent), s64(objectid), s64(start)),
            ).fetchone()
            is not None
        )

    def extent(self, extent: ExtentRead, since: int, objectid: int) -> Placement | None:
        """The placement of the bytes one extent read of inode `objectid` supplied from disk;
        None when it read nothing from disk (inline, holes, prealloc, failures)."""
        if extent.error_kind or not extent.ranges or extent.disk_bytenr is None:
            return None
        pieces = []
        for piece in extent.ranges:
            used = next((copy for copy in piece.copies if copy.used), None)
            if used is None:
                return None
            pieces.append((used.devid, used.physical, piece.length))
        first = self.map.logical_of(pieces[0][0], pieces[0][1])
        start = (
            None if first is None else first[0] - (extent.ranges[0].logical - extent.disk_bytenr)
        )

        def held(view: SpaceView) -> bool:
            return start is not None and view.holds_data(
                start, extent.disk_num_bytes, objectid,
                lambda parent: self._parent_holds(parent, objectid, start),
            )  # fmt: skip

        return self._place(pieces, held, since)

    def block(self, leaf: Leaf) -> Placement | None:
        """The placement of the tree block a leaf was read from (its lowest valid copy)."""
        if leaf.content_id not in self._blocks:
            first = self.map.logical_of(None, leaf.physical)

            def held(view: SpaceView) -> bool:
                return first is not None and view.holds_block(first[0], leaf.generation)

            pieces = [(None, leaf.physical, self.nodesize)]
            self._blocks[leaf.content_id] = self._place(pieces, held, leaf.generation)
        return self._blocks[leaf.content_id]

    def summary(self) -> dict:
        view = self.view
        found = {
            "source": None if view is None else view.source,
            "complete": bool(view and view.complete),
            "block_groups": 0 if view is None else len(view.groups),
            "free_bytes": 0 if view is None else view.free.total(),
            "cross_check": None if view is None else view.cross_check(),
            "discard": {"stated": self.discard.stated, "observed": self.discard.observed,
                        "mode": self.discard.mode, "evidence": self.discard.evidence},
            "zoned": self.zoned,
            "history": len(self._history or ()),
            "problems": [] if view is None else view.notes(),
        }  # fmt: skip
        return found
