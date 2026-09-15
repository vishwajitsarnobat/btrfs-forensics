"""Old-root discovery: historical tree roots among the scanned tree blocks, and how complete each
historical root-tree state still is.

The idea is btrfs-progs `btrfs-find-root`'s (it prints, per generation, the highest-level
root-tree block it finds), fed into records instead of stdout:

1. **Index.** Every valid scan candidate is one row (bytenr, generation, level, owner, physical)
   in compact numpy columns. A log block (owner TREE_LOG) whose only failed check is its
   generation, exactly superblock + 1, is indexed too: that is the log rule (node.py), so
   superseded log commits that no walk reaches stay visible. Every other log candidate that fails
   is counted as rejected. Owner 12 (RAID stripe tree) and 13 (remap tree) candidates are kept as
   raw, unparsed records. Every candidate not indexed is kept as (bytenr, generation, physical)
   only, to classify missing blocks (step 3).
2. **Groups and candidate roots.** A distinct block is (bytenr, generation, level, owner); its
   physical copies are rows. A block is *referenced* when an indexed internal block one level up,
   of an owner the kernel's owner check accepts for it and of the block's generation or a newer
   one, points to it with its bytenr and generation. The *candidate roots* are the blocks nothing
   references, at any level: a planted higher-level block cannot demote the real roots of its
   generation to fragments. A block only a newer parent points to (`referenced_by_newer`, such as
   an unchanged leaf of a multi-leaf tree whose own parent is gone) is part of that newer tree,
   not a candidate. A forged newer parent can still claim an older block; it is then a candidate
   itself and its state reaches that block. A candidate whose pointers name an indexed block of
   the pointer's bytenr and generation only at another level than its own level - 1 has an
   inconsistent level (`level_consistent`).
3. **Root-tree states.** Every owner-1 candidate root, a *candidate root-tree block*, is one
   *state*: a historical root tree as far as that block reaches. Its trees
   are resolved through the index, not through a chunk map: a pointer or ROOT_ITEM (bytenr,
   generation, level) is *found* when a valid scanned block carries exactly that bytenr, generation
   and level, an owner the kernel's owner check accepts (node.owner_ok), and the pointer's first
   key. So a state whose chunks have since moved still resolves. A referenced block that is not
   found gets a node.FAILURE_CLASSES class (`reused` is a newer tree's block at that address,
   `corrupt` a failed integrity check) from every source that has it, and the most informative
   class wins, in FAILURE_CLASSES order:
   - a read through the current chunk map;
   - when the current map does not place the address, a read through the state's own chunk
     items (step 4), so a block of a pre-balance state is read where that state had it;
   - the invalid scanned copies whose header carries the block's bytenr and generation (at most
     MAX_LISTED), checked against the same expectations: a present but invalid block is
     `corrupt` or `mismatch`, never `unmapped`.
   A valid read is `not_scanned` (a range the scan plan skipped); `changed` means the indexed bytes
   no longer match; `unmapped` means no map places the address and no invalid copy was scanned.
   - `referenced` counts the distinct blocks named by the state's found blocks: its root-tree
     blocks, every tree root its ROOT_ITEMs name, and every pointer below a found block;
   - `completeness` = found / referenced. It covers the root tree reached from the candidate
     block and every tree a ROOT_ITEM in its found leaves names, except ROOT_ITEMs naming tree 1
     (not followed). The chunk tree and the log tree are excluded: no ROOT_ITEM names them. With
     nothing missing it is 1.0 and means that every block of the root tree and of every
     ROOT_ITEM-named tree was found, nothing more (no data, no chunk or log tree). Nothing is
     known below a missing block, so it overstates how much of the state survives; `unchecked`
     pointers beyond MAX_MISSING are not de-duplicated, which can understate it.
4. **Chunk root of a state** (read-only analysis that feeds historical chunk maps, plan.md M5):
   the superblock's or a backup slot's chunk root when the state is one of theirs, else the newest
   owner-3 candidate root no newer than the state (`inferred`). When it differs from the current
   chunk root, its CHUNK_ITEMs are read through the index, independently of any sys_chunk_array,
   and each found block of the state is checked against the current chunk map and against those
   items: does either place the block's bytenr at a physical offset where it was scanned? No map
   is kept or used for reading.
5. **Rediscovery.** Every superblock and backup-slot root (`known_roots`) is looked up: indexed,
   and a candidate root of its owner and generation.

Bounds. Memory holds the index columns (about 50 bytes per valid copy, 24 per invalid one), per-node
arrays, at most
MAX_STATES evaluated states with at most MAX_PROBLEMS problems each, MAX_LISTED bytenrs per group,
MAX_RAW raw records, and caches memoised per subtree, never per tree root:
- the outcome of each reference (bytenr, generation, level, owner class, first key): found,
  `changed`, `mismatch` or no indexed block;
- the pointers of each found internal node, parsed and resolved once (vectorised against the
  index) into followed children and dangling slots;
- the (found, missing) counts of each referenced subtree, for the per-tree figures;
- the class of each missing block, read at most once per reference across all states.
A state walk visits each of its distinct found blocks once, whatever the number of trees, states or
parents that share it, and keeps at most MAX_MISSING missing blocks, read and classified. Further
missing references are counted as `unchecked` without a read (a count of pointers, not
de-duplicated), so the reads of a run are at most MAX_STATES x MAX_MISSING and a subtree shared by
many roots costs its distinct blocks, not roots x pointers. Repeated pointers to a block cost one
problem each. Levels must drop by one per hop, so walks are at most 8 deep.
"""

from array import array
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import numpy as np

from btrfska.scan.classify import reachability
from btrfska.scan.kernel_numpy import NodeRecord, iter_candidate_nodes
from btrfska.scan.regions import ScanPlan, plan_scan
from btrfska.substrate import items, ondisk
from btrfska.substrate.chunks import ChunkMap, MappingError, parse_chunk
from btrfska.substrate.fs import Filesystem
from btrfska.substrate.image import ImageHandle
from btrfska.substrate.node import (
    FAILURE_CLASSES,
    Expect,
    Key,
    NodeContext,
    NodeCopy,
    NodeReader,
    check_block,
    copy_failure,
    is_subvolume_tree,
    node_failure,
    owner_ok,
    parse_items,
)
from btrfska.substrate.roots import root_sets

K = ondisk.ITEM_KEYS
LOG = ondisk.TREE_LOG_OBJECTID
MAX_STATES = 64
MAX_LISTED = 16
MAX_PROBLEMS = 32
MAX_RAW = 256
MAX_MISSING = 256  # distinct missing blocks classified per state; the rest count as `unchecked`
# One btrfs_key_ptr: key (objectid, type, offset), blockptr, generation (ondisk.KEY_PTR).
_PTR = np.dtype([("objectid", "<u8"), ("type", "u1"), ("offset", "<u8"), ("blockptr", "<u8"),
                 ("generation", "<u8")])  # fmt: skip
RAW_OWNERS = {
    ondisk.RAID_STRIPE_TREE_OBJECTID: "raid_stripe_blocks",
    ondisk.REMAP_TREE_OBJECTID: "remap_blocks",
}


@dataclass(frozen=True)
class KnownRoot:
    """A tree root the superblock or one of its backup slots names."""

    source: str  # "current" or "backup:GEN"
    tree: str  # root, extent, chunk, dev, fs, csum or log
    tree_id: int
    bytenr: int
    generation: int | None
    level: int | None


def known_roots(fields: dict) -> list[KnownRoot]:
    """Backup-slot roots by generation, then the superblock's root, chunk root and log root."""
    roots = [
        KnownRoot(root_set.source, name, tree.tree_id, tree.bytenr, tree.generation, tree.level)
        for root_set in root_sets(fields)
        for name, tree in root_set.trees.items()
        if tree.bytenr
    ]
    if fields.get("log_root"):
        roots.append(
            KnownRoot("current", "log", LOG, fields["log_root"], fields["generation"] + 1,
                      fields["log_root_level"])
        )  # fmt: skip
    return roots


class BlockIndex:
    """Valid scanned tree blocks: one row per physical copy, sorted by (bytenr, generation, level,
    owner, physical). A node is a distinct (bytenr, generation, level, owner)."""

    def __init__(
        self,
        columns: dict[str, array],
        stats: dict[str, int],
        raw: list[dict],
        invalid: dict[str, array] | None = None,
    ):
        self.stats, self.raw = stats, raw
        invalid = invalid or {name: array("Q") for name in ("bytenr", "generation", "physical")}
        bad = {name: np.frombuffer(col, np.uint64) for name, col in invalid.items()}
        bad_order = np.lexsort((bad["physical"], bad["generation"], bad["bytenr"]))
        self.invalid_bytenr = bad["bytenr"][bad_order]
        self.invalid_generation = bad["generation"][bad_order]
        self.invalid_physical = bad["physical"][bad_order]
        view = {name: np.frombuffer(col, np.uint64 if col.typecode == "Q" else np.uint8)
                for name, col in columns.items()}  # fmt: skip
        order = np.lexsort(
            (view["physical"], view["owner"], view["level"], view["generation"], view["bytenr"])
        )
        self.bytenr = view["bytenr"][order]
        self.generation = view["generation"][order]
        self.level = view["level"][order]
        self.owner = view["owner"][order]
        self.physical = view["physical"][order]
        rows = len(order)
        starts = np.ones(rows, bool)
        if rows:
            starts[1:] = (
                (self.bytenr[1:] != self.bytenr[:-1])
                | (self.generation[1:] != self.generation[:-1])
                | (self.level[1:] != self.level[:-1])
                | (self.owner[1:] != self.owner[:-1])
            )
        self.node_start = np.flatnonzero(starts)
        self.node_end = np.append(self.node_start[1:], rows)

    @property
    def nodes(self) -> int:
        return len(self.node_start)

    def node(self, index: int) -> tuple[int, int, int, int]:
        """(bytenr, generation, level, owner) of node `index`."""
        row = self.node_start[index]
        return (int(self.bytenr[row]), int(self.generation[row]), int(self.level[row]),
                int(self.owner[row]))  # fmt: skip

    def copies(self, index: int) -> tuple[int, ...]:
        return tuple(int(p) for p in self.physical[self.node_start[index] : self.node_end[index]])

    def _rows(self, bytenr: int, generation: int) -> tuple[int, int]:
        lo = int(np.searchsorted(self.bytenr, np.uint64(bytenr), "left"))
        hi = int(np.searchsorted(self.bytenr, np.uint64(bytenr), "right"))
        gens = self.generation[lo:hi]
        return tuple(lo + int(np.searchsorted(gens, np.uint64(generation), side))
                     for side in ("left", "right"))  # fmt: skip

    def _nodes(self, lo: int, hi: int) -> list[int]:
        first = int(np.searchsorted(self.node_start, lo, "right")) - 1
        last = int(np.searchsorted(self.node_start, hi, "left"))
        return list(range(first, last)) if lo < hi else []

    def invalid_copies(self, bytenr: int, generation: int, limit: int) -> list[int]:
        """Physical offsets of up to `limit` invalid scanned copies with this header bytenr and
        generation."""
        if not (0 <= bytenr < 1 << 64 and 0 <= generation < 1 << 64):
            return []
        lo = int(np.searchsorted(self.invalid_bytenr, np.uint64(bytenr), "left"))
        hi = int(np.searchsorted(self.invalid_bytenr, np.uint64(bytenr), "right"))
        gens = self.invalid_generation[lo:hi]
        first = lo + int(np.searchsorted(gens, np.uint64(generation), "left"))
        end = lo + int(np.searchsorted(gens, np.uint64(generation), "right"))
        return [int(p) for p in self.invalid_physical[first : min(end, first + limit)]]

    def find_generation(self, bytenr: int, generation: int) -> list[int]:
        """Node indices with this bytenr and generation, at any level, in (level, owner) order."""
        if not (0 <= bytenr < 1 << 64 and 0 <= generation < 1 << 64):
            return []
        return self._nodes(*self._rows(bytenr, generation))

    def find(self, bytenr: int, generation: int, level: int) -> list[int]:
        """Node indices with this bytenr, generation and level, in owner order."""
        if not (0 <= bytenr < 1 << 64 and 0 <= generation < 1 << 64 and 0 <= level < 256):
            return []
        lo, hi = self._rows(bytenr, generation)
        levels = self.level[lo:hi]
        lo, hi = (lo + int(np.searchsorted(levels, np.uint8(level), side))
                  for side in ("left", "right"))  # fmt: skip
        return self._nodes(lo, hi)


def index_records(records: Iterable[NodeRecord], ctx: NodeContext) -> BlockIndex:
    """Index valid candidates (and log blocks one generation ahead); see the module docstring."""
    columns = {name: array("Q") for name in ("bytenr", "generation", "owner", "physical")}
    columns["level"] = array("B")
    invalid = {name: array("Q") for name in ("bytenr", "generation", "physical")}
    stats = dict.fromkeys(
        ("candidates", "indexed_copies", "log_accepted", "log_rejected", *RAW_OWNERS.values(),
         "invalid_copies"),
        0,
    )  # fmt: skip
    raw = []
    for record in records:
        stats["candidates"] += 1
        if record.owner in RAW_OWNERS:
            stats[RAW_OWNERS[record.owner]] += 1
            if len(raw) < MAX_RAW:
                raw.append({
                    "owner": record.owner, "physical": record.physical, "bytenr": record.bytenr,
                    "generation": record.generation, "level": record.level,
                    "nritems": record.nritems, "valid": record.valid,
                })  # fmt: skip
        accepted = record.valid
        if record.owner == LOG and not record.valid:
            failed = [check.name for check in record.checks if check.ok is False]
            accepted = failed == ["generation"] and record.generation == ctx.generation + 1
            stats["log_accepted" if accepted else "log_rejected"] += 1
        if accepted:
            stats["indexed_copies"] += 1
            for name in ("bytenr", "generation", "owner", "physical"):
                columns[name].append(getattr(record, name))
            columns["level"].append(record.level)
        elif record.bytenr is not None and record.generation is not None:
            stats["invalid_copies"] += 1
            for name in ("bytenr", "generation", "physical"):
                invalid[name].append(getattr(record, name))
    return BlockIndex(columns, stats, raw, invalid)


@dataclass(frozen=True)
class Group:
    owner: int
    generation: int
    level: int
    blocks: int  # distinct blocks
    copies: int
    unreferenced: int  # blocks no internal block of the same generation points to
    referenced_by_newer: int  # of those, blocks an internal block of a newer generation points to
    top: bool  # the highest level of this owner and generation
    candidates: int  # unreferenced blocks no newer parent points to, at any level
    listed: tuple[int, ...]  # bytenrs of the first MAX_LISTED candidates


@dataclass(frozen=True)
class TreeRef:
    """A tree a root-tree state names through a ROOT_ITEM."""

    tree_id: int
    key_offset: int
    bytenr: int
    generation: int
    level: int
    leaf: int
    slot: int
    status: str  # found, skipped, not_scanned, changed or a node.FAILURE_CLASSES entry
    blocks: int  # distinct blocks of the tree found
    missing: int  # distinct blocks of the tree referenced but not found


@dataclass(frozen=True)
class ChunkRoot:
    bytenr: int
    generation: int
    level: int
    source: str  # current, backup:GEN or inferred
    differs_from_current: bool


@dataclass(frozen=True)
class State:
    bytenr: int
    generation: int
    level: int
    copies: tuple[int, ...]
    known_as: tuple[str, ...]  # current and backup:GEN sources naming this root-tree block
    trees: tuple[TreeRef, ...]
    root_tree_blocks: int
    root_tree_missing: int
    found: int
    referenced: int
    missing: dict[str, int]
    completeness: float
    chunk_root: ChunkRoot | None
    maps_current: int  # found blocks the current chunk map places where they were scanned
    maps_historical: int | None  # the same under the state's chunk items (None: no other chunks)
    maps_neither: int
    level_consistent: bool  # no pointer names an indexed (bytenr, generation) at another level
    problems: tuple[str, ...]


@dataclass(frozen=True)
class LogGeneration:
    generation: int
    blocks: int
    copies: int
    levels: tuple[int, ...]
    candidates: int
    listed: tuple[int, ...]
    live: int  # blocks the walk of the superblock's log tree reached
    superseded: int  # blocks of generation superblock + 1 that walk did not reach
    committed: bool  # generation <= superblock: a log left from a committed transaction


@dataclass(frozen=True)
class Rediscovery:
    root: KnownRoot
    indexed: bool
    candidate: bool


@dataclass(frozen=True)
class Discovery:
    stats: dict[str, int]
    groups: tuple[Group, ...]
    root_tree_candidates: int
    states: tuple[State, ...]
    rediscovered: tuple[Rediscovery, ...]
    logs: tuple[LogGeneration, ...]
    raw: list[dict]
    walk_failures: tuple[tuple[str, int, int, str], ...] = ()
    _index: BlockIndex | None = field(default=None, repr=False, compare=False)
    _candidate: np.ndarray | None = field(default=None, repr=False, compare=False)

    def candidate(self, bytenr: int, generation: int, level: int, owner: int) -> bool:
        """Whether (bytenr, generation, level) is a candidate root of an owner `owner` accepts."""
        return any(
            bool(self._candidate[j]) and owner_ok(owner, self._index.node(j)[3]) is not False
            for j in self._index.find(bytenr, generation, level)
        )


@dataclass
class _Walk:
    """One state walk over its root tree and trees: distinct blocks found and missing."""

    found: dict = field(default_factory=dict)  # (bytenr, generation, level) -> node index
    missing: dict = field(default_factory=dict)  # (bytenr, generation, level) -> class
    unchecked: int = 0  # missing references beyond MAX_MISSING: not read, not de-duplicated
    seen: dict = field(default_factory=dict)  # (key, owner class) -> tree ordinal reaching it
    items: list = field(default_factory=list)  # (item, leaf bytenr) of the wanted item type
    problems: list[str] = field(default_factory=list)
    classify: bool = True  # False: missing references are only counted (chunk-item walks)
    historical: ChunkMap | None = None  # the state's own chunk items, when not the current ones
    map_id: tuple | None = None  # the chunk root `historical` was read from


@dataclass(frozen=True)
class _Links:
    followed: tuple  # (slot, child key, pointer key): pointers naming an indexed block
    dangling: np.ndarray  # slots of the other pointers, in slot order
    distinct_dangling: int


def _owner_class(owner: int | None) -> int | str | None:
    """What owner_ok depends on: any owner (None), any subvolume tree, or exactly `owner`."""
    if owner in (None, 0, ondisk.TREE_RELOC_OBJECTID):
        return None
    return "subvolume" if is_subvolume_tree(owner) else owner


def _reached(label: str, where: str, key) -> str:
    return (f"{label}{where} points to {key[0]} (generation {key[1]}, level {key[2]}), "
            "already reached; not followed")  # fmt: skip


class _Discoverer:
    def __init__(self, img, index, ctx, chunk_map, known, log_live):
        self.img, self.index, self.ctx, self.chunk_map = img, index, ctx, chunk_map
        self.known, self.log_live = tuple(known), log_live
        self.reader = NodeReader(img, chunk_map, ctx)
        self.maps: dict = {}
        # Per-subtree caches: reference outcomes, parsed pointers, subtree counts, missing classes.
        self.outcomes: dict = {}
        self.links: dict = {}
        self.counts: dict = {}
        self.classes: dict = {}
        n = index.nodes
        starts = index.node_start
        self.n_bytenr, self.n_gen = index.bytenr[starts], index.generation[starts]
        self.n_level, self.n_owner = index.level[starts], index.owner[starts]
        self.n_copies = index.node_end - starts
        self.unique_bytenr = np.unique(self.n_bytenr)
        self.referenced_same = np.zeros(n, bool)
        self.referenced_newer = np.zeros(n, bool)
        self.level_mismatches = np.zeros(n, np.int64)
        self._mark_references()
        self.order = np.lexsort((self.n_bytenr, self.n_level, self.n_gen, self.n_owner))
        self.top = np.zeros(n, bool)
        if n:
            o = self.order
            change = np.ones(n, bool)
            change[1:] = (self.n_owner[o][1:] != self.n_owner[o][:-1]) | (
                self.n_gen[o][1:] != self.n_gen[o][:-1]
            )
            starts_og = np.flatnonzero(change)
            highest = np.maximum.reduceat(self.n_level[o], starts_og)
            lengths = np.diff(np.append(starts_og, n))
            self.top[o] = self.n_level[o] == np.repeat(highest, lengths)
        self.candidate = ~(self.referenced_same | self.referenced_newer)
        current = [k for k in self.known if k.source == "current" and k.tree == "chunk"]
        self.current_chunk = (current[0].bytenr, current[0].generation) if current else None

    # -- references and groups ------------------------------------------------------------------
    def _block(self, node: int) -> bytes | None:
        physical = int(self.index.physical[self.index.node_start[node]])
        if physical + self.ctx.nodesize > self.img.size:
            return None
        return bytes(self.img.mmap[physical : physical + self.ctx.nodesize])

    def _header_matches(self, block: bytes | None, node: int) -> bool:
        if block is None:
            return False
        header = ondisk.HEADER.unpack_from(block)
        fields = (header["bytenr"], header["generation"], header["level"], header["owner"])
        return fields == self.index.node(node) and header["fsid"] == self.ctx.fsid

    def _mark_references(self) -> None:
        """Each internal block is read once. A pointer (bytenr, generation) of a block of that
        generation or newer marks the indexed blocks it names one level down with an acceptable
        owner as referenced by the same or a newer generation. A pointer that names an indexed
        block of that bytenr and generation only at another level counts as a level mismatch of
        the pointing block."""
        for node in np.flatnonzero(self.n_level > 0).tolist():
            if not self._header_matches(self._block(node), node):
                continue
            _, generation, level, owner = self.index.node(node)
            ptrs = self._pointers(node)
            named = self._present(ptrs["blockptr"]) & (ptrs["generation"] <= generation)
            for slot in np.flatnonzero(named).tolist():
                ptr_generation = int(ptrs["generation"][slot])
                matches = [
                    child
                    for child in self.index.find_generation(int(ptrs["blockptr"][slot]),
                                                            ptr_generation)
                    if owner_ok(owner, int(self.n_owner[child])) is not False
                ]  # fmt: skip
                below = [child for child in matches if int(self.n_level[child]) == level - 1]
                if matches and not below:
                    self.level_mismatches[node] += 1
                same = ptr_generation == generation
                mark = self.referenced_same if same else self.referenced_newer
                for child in below:
                    if child != node:
                        mark[child] = True

    def groups(self) -> list[Group]:
        o, result = self.order, []
        n = len(o)
        if not n:
            return result
        change = np.ones(n, bool)
        change[1:] = (
            (self.n_owner[o][1:] != self.n_owner[o][:-1])
            | (self.n_gen[o][1:] != self.n_gen[o][:-1])
            | (self.n_level[o][1:] != self.n_level[o][:-1])
        )
        starts = np.flatnonzero(change)
        ends = np.append(starts[1:], n)
        copies = np.add.reduceat(self.n_copies[o], starts)
        no_parent = ~self.referenced_same[o]
        unreferenced = np.add.reduceat(no_parent.astype(np.int64), starts)
        newer = np.add.reduceat((no_parent & self.referenced_newer[o]).astype(np.int64), starts)
        candidates = np.add.reduceat(self.candidate[o].astype(np.int64), starts)
        for i, (start, end) in enumerate(zip(starts.tolist(), ends.tolist(), strict=True)):
            members = o[start:end]
            listed = self.n_bytenr[members][self.candidate[members]][:MAX_LISTED]
            first = members[0]
            result.append(
                Group(
                    owner=int(self.n_owner[first]), generation=int(self.n_gen[first]),
                    level=int(self.n_level[first]), blocks=end - start, copies=int(copies[i]),
                    unreferenced=int(unreferenced[i]), referenced_by_newer=int(newer[i]),
                    top=bool(self.top[first]),
                    candidates=int(candidates[i]), listed=tuple(int(b) for b in listed),
                )
            )  # fmt: skip
        return result

    # -- walks through the index -----------------------------------------------------------------
    def _resolve(self, bytenr: int, generation: int, level: int, owner: int) -> int | None:
        for node in self.index.find(bytenr, generation, level):
            if owner_ok(owner, int(self.n_owner[node])) is not False:
                return node
        return None

    def _first_key(self, block: bytes) -> Key | None:
        if not ondisk.HEADER.unpack_from(block)["nritems"]:
            return None
        first = ondisk.ITEM.unpack_from(block, ondisk.HEADER.size)  # keys lead items and pointers
        return Key(first["key_objectid"], first["key_type"], first["key_offset"])

    def _outcome(self, key, owner: int, first_key: Key | None) -> tuple:
        """A reference resolved once per subtree: (node index, None) when found, (class, detail)
        when an indexed block matches but is unusable, (None, None) when none matches."""
        memo = (key, _owner_class(owner), first_key)
        result = self.outcomes.get(memo)
        if result is None:
            node = self._resolve(*key, owner)
            result = (None, None)
            if node is not None:
                block = self._block(node)
                have = self._first_key(block) if self._header_matches(block, node) else None
                if not self._header_matches(block, node):
                    result = ("changed", f"block {key[0]} no longer matches the scan record")
                elif first_key is not None and have != first_key:
                    result = (
                        "mismatch", f"block {key[0]} first key {have} != pointer key {first_key}"
                    )  # fmt: skip
                else:
                    result = (node, None)
            self.outcomes[memo] = result
        return result

    def _pointers(self, node: int) -> np.ndarray:
        block = self._block(node)
        limit = (self.ctx.nodesize - ondisk.HEADER.size) // ondisk.KEY_PTR.size
        count = min(ondisk.HEADER.unpack_from(block)["nritems"], limit)
        return np.frombuffer(block, _PTR, count, ondisk.HEADER.size)

    def _present(self, bytenrs: np.ndarray) -> np.ndarray:
        """Whether any indexed block has each bytenr (vectorised)."""
        known = self.unique_bytenr
        if not len(known):
            return np.zeros(len(bytenrs), bool)
        at = np.minimum(np.searchsorted(known, bytenrs), len(known) - 1)
        return known[at] == bytenrs

    def _links(self, node: int, owner: int) -> _Links:
        """The pointers of a found internal node, parsed and resolved once per node and owner
        class: those naming an indexed block of an acceptable owner, and the dangling rest."""
        memo = (node, _owner_class(owner))
        links = self.links.get(memo)
        if links is None:
            ptrs = self._pointers(node)
            level = int(self.n_level[node]) - 1
            present = self._present(ptrs["blockptr"])
            followed, unresolved = [], []
            for slot in np.flatnonzero(present).tolist():
                ptr = ptrs[slot]
                child = (int(ptr["blockptr"]), int(ptr["generation"]), level)
                if self._resolve(*child, owner) is None:
                    unresolved.append(slot)
                else:
                    key = Key(int(ptr["objectid"]), int(ptr["type"]), int(ptr["offset"]))
                    followed.append((slot, child, key))
            dangling = np.sort(
                np.concatenate([np.flatnonzero(~present), np.array(unresolved, np.int64)])
            )
            named = np.stack([ptrs["blockptr"][dangling], ptrs["generation"][dangling]], axis=1)
            distinct = len(np.unique(named, axis=0)) if len(dangling) else 0
            links = self.links[memo] = _Links(tuple(followed), dangling, distinct)
        return links

    def _count(self, key, owner: int, first_key: Key | None) -> tuple[int, int]:
        """(found, missing) blocks of the subtree a reference names, memoised per subtree. A tree
        is counted as a tree: a block two parents of one tree name counts twice there (forged
        input only); state totals are de-duplicated by the state walk."""
        memo = (key, _owner_class(owner), first_key)
        result = self.counts.get(memo)
        if result is None:
            node, _ = self._outcome(key, owner, first_key)
            if not isinstance(node, int):
                result = (0, 1)
            elif key[2] == 0:
                result = (1, 0)
            else:
                links = self._links(node, owner)
                found, missing = 1, links.distinct_dangling
                children: dict = {}
                for _, child, pointer_key in links.followed:  # the first pointer to a block wins
                    children.setdefault(child, pointer_key)
                for child, pointer_key in children.items():
                    below = self._count(child, owner, pointer_key)
                    found, missing = found + below[0], missing + below[1]
                result = (found, missing)
            self.counts[memo] = result
        return result

    def _missing(self, key, owner: int, first_key: Key | None, historical=None) -> str:
        """Read a referenced block that no indexed block matches; see the module docstring."""
        bytenr, generation, level = key
        expect = Expect(level=level, owner=owner, generation=generation, first_key=first_key)
        if level >= ondisk.MAX_LEVEL:
            expect = Expect(owner=owner, generation=generation, first_key=first_key)
        classes = set()
        for chunk_map in (self.chunk_map, historical):
            if chunk_map is None:
                continue
            node = NodeReader(self.img, chunk_map, self.ctx).read(bytenr, expect)
            failure = node_failure(node, expect)
            if failure is None:
                return "not_scanned" if level < ondisk.MAX_LEVEL else "mismatch"
            if failure != "unmapped":
                classes.add(failure)
                break
        for physical in self.index.invalid_copies(bytenr, generation, MAX_LISTED):
            if physical + self.ctx.nodesize > self.img.size:
                continue
            block = bytes(self.img.mmap[physical : physical + self.ctx.nodesize])
            header = ondisk.HEADER.unpack_from(block)
            copy = NodeCopy(
                0, 0, physical, check_block(block, self.ctx, bytenr, expect),
                header["generation"], header["owner"], header["level"], not any(block),
            )  # fmt: skip
            classes.add(copy_failure(copy, expect) or "mismatch")
        return next((name for name in FAILURE_CLASSES if name in classes), "unmapped")

    def _classify(self, key, owner: int, first_key: Key | None, walk: _Walk) -> str:
        """The class of a missing block, read once per reference and chunk root across states."""
        memo = (key, _owner_class(owner), first_key, walk.map_id)
        if memo not in self.classes:
            self.classes[memo] = self._missing(key, owner, first_key, walk.historical)
        return self.classes[memo]

    def _note_missing(self, walk: _Walk, key, owner: int, first_key: Key | None, failure=None):
        if key in walk.found or key in walk.missing:
            return
        if not walk.classify or len(walk.missing) >= MAX_MISSING:
            walk.unchecked += 1
            return
        walk.missing[key] = failure or self._classify(key, owner, first_key, walk)

    def _dangling(self, walk: _Walk, node: int, links: _Links, owner: int, tree: int, label: str):
        slots = links.dangling
        if not len(slots):
            return
        if not walk.classify or len(walk.missing) >= MAX_MISSING:
            walk.unchecked += len(slots)
            return
        ptrs, level = self._pointers(node), int(self.n_level[node]) - 1
        owner_class = _owner_class(owner)
        bytenr = int(self.n_bytenr[node])
        for done, slot in enumerate(slots.tolist()):
            if len(walk.missing) >= MAX_MISSING:
                walk.unchecked += len(slots) - done
                return
            ptr = ptrs[slot]
            key = (int(ptr["blockptr"]), int(ptr["generation"]), level)
            first_key = Key(int(ptr["objectid"]), int(ptr["type"]), int(ptr["offset"]))
            ref = (key, owner_class)
            if ref in walk.seen:
                if walk.seen[ref] == tree:
                    walk.problems.append(_reached(label, f"node {bytenr} slot {slot}", key))
                continue
            walk.seen[ref] = tree
            self._note_missing(walk, key, owner, first_key)

    def _walk(self, walk: _Walk, key, owner: int, tree: int, wanted=None, label="") -> str:
        """Walk one tree of a state from `key` into `walk`; returns the status of `key`.

        Each distinct block is visited once per state; outcomes, pointer lists, counts and
        classes come from the per-subtree caches, so a subtree shared by many states or trees
        is parsed, resolved and classified once."""
        owner_class = _owner_class(owner)
        stack = [(key, None, "root")]
        while stack:
            child, first_key, where = stack.pop()
            ref = (child, owner_class)
            if ref in walk.seen:
                if walk.seen[ref] == tree:
                    walk.problems.append(_reached(label, where, child))
                continue
            walk.seen[ref] = tree
            node, detail = self._outcome(child, owner, first_key)
            if node is None:
                self._note_missing(walk, child, owner, first_key)
                continue
            if not isinstance(node, int):
                where_detail = detail if node == "changed" else f"{where}: {detail}"
                walk.problems.append(label + where_detail)
                self._note_missing(walk, child, owner, first_key, node)
                continue
            if child in walk.found:
                continue
            walk.found[child] = node
            if child[2] > 0:
                links = self._links(node, owner)
                self._dangling(walk, node, links, owner, tree, label)
                for slot, grandchild, pointer_key in reversed(links.followed):
                    stack.append((grandchild, pointer_key, f"node {child[0]} slot {slot}"))
            elif wanted is not None:
                leaf_items, _ = parse_items(self._block(node), self.ctx.nodesize)
                walk.items += [(i, child[0]) for i in leaf_items if i.key.type == wanted]
        if key in walk.found:
            return "found"
        return walk.missing.get(key, "unchecked")

    # -- states ----------------------------------------------------------------------------------
    def _chunk_root(self, known_as: tuple[str, ...], generation: int) -> ChunkRoot | None:
        for root in self.known:
            if root.tree == "chunk" and root.source in known_as:
                chunk = (root.bytenr, root.generation, root.level, root.source)
                break
        else:
            pool = np.flatnonzero(self.candidate & (self.n_owner == ondisk.CHUNK_TREE_OBJECTID))
            pool = pool[self.n_gen[pool] <= generation]
            if not len(pool):
                return None
            newest = pool[self.n_gen[pool] == self.n_gen[pool].max()]
            # Ties: level-consistent first, then the highest level, then the lowest bytenr.
            best = max(
                newest.tolist(),
                key=lambda j: (self.level_mismatches[j] == 0, int(self.n_level[j]),
                               -int(self.n_bytenr[j])),
            )  # fmt: skip
            bytenr, gen, level, _ = self.index.node(best)
            chunk = (bytenr, gen, level, "inferred")
        differs = self.current_chunk is None or chunk[:2] != self.current_chunk
        return ChunkRoot(*chunk, differs_from_current=differs)

    def _historical_map(self, root: ChunkRoot) -> ChunkMap:
        memo = (root.bytenr, root.generation, root.level)
        if memo not in self.maps:
            walked = _Walk(classify=False)
            self._walk(walked, memo, ondisk.CHUNK_TREE_OBJECTID, 0, K["CHUNK_ITEM"])
            chunks = [
                parse_chunk(item.key.offset, item.data, sectorsize=self.ctx.sectorsize,
                            origin=f"historical chunk tree leaf {leaf} slot {item.slot}")
                for item, leaf in walked.items
            ]  # fmt: skip
            self.maps[memo] = ChunkMap(
                f"historical:{root.generation}", chunks, self.chunk_map.devices
            )
        return self.maps[memo]

    def _placed(self, chunk_map: ChunkMap, bytenr: int, node: int) -> bool:
        try:
            copies = chunk_map.copies(bytenr, self.ctx.nodesize)
        except MappingError:
            return False
        scanned = set(self.index.copies(node))
        return any(c.physical in scanned and not c.missing_device for c in copies)

    def state(self, node: int, known_as: tuple[str, ...]) -> State:
        bytenr, generation, level, _ = self.index.node(node)
        root_key = (bytenr, generation, level)
        chunk_root = self._chunk_root(known_as, generation)
        historical = map_id = None
        if chunk_root is not None and chunk_root.differs_from_current:
            historical = self._historical_map(chunk_root)
            map_id = (chunk_root.bytenr, chunk_root.generation, chunk_root.level)
        walk = _Walk(historical=historical, map_id=map_id)
        self._walk(walk, root_key, ondisk.ROOT_TREE_OBJECTID, 0, K["ROOT_ITEM"])
        root_blocks, root_missing = self._count(root_key, ondisk.ROOT_TREE_OBJECTID, None)
        item_problems, trees = [], []
        for ordinal, (item, leaf) in enumerate(list(walk.items), start=1):
            where = f"ROOT_ITEM {item.key} in leaf {leaf} slot {item.slot}"
            try:
                parsed = items.root_item(item.data)
            except items.ItemError as exc:
                item_problems.append(f"{where}: {exc}")
                continue
            ref = (item.key.objectid, item.key.offset, parsed["bytenr"], parsed["generation"],
                   parsed["level"], leaf, item.slot)  # fmt: skip
            if item.key.objectid == ondisk.ROOT_TREE_OBJECTID:
                item_problems.append(f"{where} names the root tree; not followed")
                trees.append(TreeRef(*ref, status="skipped", blocks=0, missing=0))
                continue
            if parsed["generation"] > generation:
                item_problems.append(
                    f"{where}: generation {parsed['generation']} is newer than the root tree "
                    f"state ({generation})"
                )
            key = (parsed["bytenr"], parsed["generation"], parsed["level"])
            tree_id = item.key.objectid
            status = self._walk(walk, key, tree_id, ordinal, label=f"tree {tree_id}: ")
            trees.append(TreeRef(*ref, status, *self._count(key, tree_id, None)))
        for key in walk.found:
            walk.missing.pop(key, None)
        counts: dict[str, int] = {}
        for failure in walk.missing.values():
            counts[failure] = counts.get(failure, 0) + 1
        if walk.unchecked:
            counts["unchecked"] = walk.unchecked
        placed_current = placed_historical = neither = 0
        for (block_bytenr, _, _), block in walk.found.items():
            here = self._placed(self.chunk_map, block_bytenr, block)
            there = historical is not None and self._placed(historical, block_bytenr, block)
            placed_current += here
            placed_historical += there
            neither += not (here or there)
        mismatches = int(self.level_mismatches[node])
        if mismatches:
            item_problems.insert(0, (
                f"level {level}: {mismatches} pointer(s) name an indexed block of that bytenr and "
                f"generation at a level other than {level - 1}; the level is inconsistent"
            ))  # fmt: skip
        problems = item_problems + walk.problems
        if len(problems) > MAX_PROBLEMS:
            problems = problems[:MAX_PROBLEMS] + [
                f"and {len(problems) - MAX_PROBLEMS} more problems"
            ]
        found = len(walk.found)
        referenced = found + len(walk.missing) + walk.unchecked
        return State(
            bytenr=bytenr, generation=generation, level=level, copies=self.index.copies(node),
            known_as=known_as, trees=tuple(trees), root_tree_blocks=root_blocks,
            root_tree_missing=root_missing, found=found, referenced=referenced,
            missing=counts, completeness=found / referenced if referenced else 0.0,
            chunk_root=chunk_root, maps_current=placed_current,
            maps_historical=None if historical is None else placed_historical,
            maps_neither=neither, level_consistent=not mismatches, problems=tuple(problems),
        )  # fmt: skip

    def states(self, max_states: int) -> tuple[int, list[State]]:
        roots = np.flatnonzero(self.candidate & (self.n_owner == ondisk.ROOT_TREE_OBJECTID))
        known_as: dict[int, list[str]] = {}
        for root in self.known:
            if root.tree != "root" or root.generation is None or root.level is None:
                continue
            node = self._resolve(root.bytenr, root.generation, root.level, root.tree_id)
            if node is not None and self.candidate[node]:
                known_as.setdefault(node, []).append(root.source)
        by_age = roots[np.lexsort((self.n_bytenr[roots], ~self.n_gen[roots]))].tolist()
        chosen = sorted(known_as, key=lambda j: (-int(self.n_gen[j]), int(self.n_bytenr[j])))
        chosen += [j for j in by_age if j not in known_as][: max(0, max_states - len(chosen))]
        return len(roots), [self.state(j, tuple(known_as.get(j, ()))) for j in chosen]

    def rediscovered(self) -> list[Rediscovery]:
        result = []
        for root in self.known:
            nodes = []
            if root.generation is not None and root.level is not None:
                nodes = [
                    j for j in self.index.find(root.bytenr, root.generation, root.level)
                    if owner_ok(root.tree_id, int(self.n_owner[j])) is not False
                ]  # fmt: skip
            result.append(Rediscovery(root, bool(nodes), any(self.candidate[j] for j in nodes)))
        return result

    def logs(self) -> list[LogGeneration]:
        nodes = np.flatnonzero(self.n_owner == LOG)
        result = []
        for generation in sorted(set(self.n_gen[nodes].tolist())):
            members = nodes[self.n_gen[nodes] == generation]
            ahead = generation == self.ctx.generation + 1
            live = sum(ahead and int(self.n_bytenr[j]) in self.log_live for j in members.tolist())
            listed = self.n_bytenr[members][self.candidate[members]][:MAX_LISTED]
            result.append(
                LogGeneration(
                    generation=generation, blocks=len(members),
                    copies=int(self.n_copies[members].sum()),
                    levels=tuple(sorted(set(self.n_level[members].tolist()))),
                    candidates=int(self.candidate[members].sum()),
                    listed=tuple(int(b) for b in listed), live=live,
                    superseded=len(members) - live if ahead else 0,
                    committed=generation <= self.ctx.generation,
                )
            )  # fmt: skip
        return result


def discover(
    img: ImageHandle,
    index: BlockIndex,
    *,
    ctx: NodeContext,
    chunk_map: ChunkMap,
    known: Sequence[KnownRoot] = (),
    log_live: frozenset[int] = frozenset(),
    walk_failures: tuple[tuple[str, int, int, str], ...] = (),
    max_states: int = MAX_STATES,
) -> Discovery:
    """Groups, candidate roots, root-tree states, rediscovery and log generations of `index`.

    `chunk_map` is the current map (for missing-block classes and the mapping check), `known` the
    superblock and backup roots, `log_live` the logical addresses the current log walk reached.
    """
    work = _Discoverer(img, index, ctx, chunk_map, known, log_live)
    total, states = work.states(max_states)
    return Discovery(
        stats=dict(index.stats),
        groups=tuple(work.groups()),
        root_tree_candidates=total,
        states=tuple(states),
        rediscovered=tuple(work.rediscovered()),
        logs=tuple(work.logs()),
        raw=index.raw,
        walk_failures=walk_failures,
        _index=index,
        _candidate=work.candidate,
    )


@dataclass(frozen=True)
class RootsScan:
    plan: ScanPlan
    index: BlockIndex
    discovery: Discovery
    walk_problems: tuple[str, ...]


def discover_image(
    img: ImageHandle, fs: Filesystem, *, full_sweep: bool = False, workers: int = 1
) -> RootsScan:
    """Scan the image (as `btrfska scan` plans it) and run old-root discovery on the result."""
    plan = plan_scan(fs, img.size, full_sweep)
    reach = reachability(fs)
    ctx = fs.reader.ctx
    records = iter_candidate_nodes(img, plan.regions, ctx, fs.chunk_map, workers=workers)
    index = index_records(records, ctx)
    discovery = discover(
        img, index, ctx=ctx, chunk_map=fs.chunk_map, known=known_roots(fs.fields),
        log_live=reach.log_logical, walk_failures=reach.walk_failures,
    )  # fmt: skip
    return RootsScan(plan, index, discovery, reach.problems)
