"""Old-root discovery: historical tree roots among the scanned tree blocks, and how complete each
historical root-tree state still is.

The idea is btrfs-progs `btrfs-find-root`'s (it prints, per generation, the highest-level
root-tree block it finds), fed into records instead of stdout:

1. **Index.** Every valid scan candidate is one row (bytenr, generation, level, owner, physical)
   in compact numpy columns. A log block (owner TREE_LOG) whose only failed check is its
   generation, exactly superblock + 1, is indexed too: that is the log rule (node.py), so
   superseded log commits that no walk reaches stay visible. Every other log candidate that fails
   is counted as rejected. Owner 12 (RAID stripe tree) and 13 (remap tree) candidates are kept as
   raw, unparsed records.
2. **Groups and candidate roots.** A distinct block is (bytenr, generation, level, owner); its
   physical copies are rows. Within one owner and generation, a block is *referenced* when an
   internal block of the same owner and generation points to it with that generation, one level
   down. The *candidate roots* of an owner and generation are its unreferenced blocks at the
   highest level it has; unreferenced blocks below that level are fragments. An older block that
   only a newer parent still points to is therefore a candidate of its own generation: its old
   parent is gone.
3. **Root-tree states.** Every owner-1 candidate is a historical state of the root tree. Its trees
   are resolved through the index, not through a chunk map: a pointer or ROOT_ITEM (bytenr,
   generation, level) is *found* when a valid scanned block carries exactly that bytenr, generation
   and level, an owner the kernel's owner check accepts (node.owner_ok), and the pointer's first
   key. So a state whose chunks have since moved still resolves. A referenced block that is not
   found is read through the current chunk map and given a node.FAILURE_CLASSES class (`reused`
   is a newer tree's block at that address, `corrupt` is damage), or `not_scanned` when that read
   is valid (a range the scan plan skipped), or `changed` when the indexed bytes no longer match.
   - `referenced` counts the distinct blocks named by the state's found blocks: its root-tree
     blocks, every tree root its ROOT_ITEMs name, and every pointer below a found block;
   - `completeness` = found / referenced. Nothing is known below a missing block, so this is an
     upper bound on how much of the state survives.
4. **Chunk root of a state** (read-only analysis that feeds historical chunk maps, plan.md M5):
   the superblock's or a backup slot's chunk root when the state is one of theirs, else the newest
   owner-3 candidate root no newer than the state (`inferred`). When it differs from the current
   chunk root, its CHUNK_ITEMs are read through the index, independently of any sys_chunk_array,
   and each found block of the state is checked against the current chunk map and against those
   items: does either place the block's bytenr at a physical offset where it was scanned? No map
   is kept or used for reading.
5. **Rediscovery.** Every superblock and backup-slot root (`known_roots`) is looked up: indexed,
   and a candidate root of its owner and generation.

Bounds. Memory holds the index columns (about 50 bytes per valid copy), per-node arrays, at most
MAX_STATES evaluated states with at most MAX_PROBLEMS problems each, MAX_LISTED bytenrs per group,
MAX_RAW raw records, and the found and missing sets of each tree walked (memoised per tree root).
Each internal node is read once to find references, and a state walk visits a distinct block at
most once per tree, so repeated or cyclic pointers cost one problem each, not a re-walk. Levels
must drop by one per hop, so walks are at most 8 deep.
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
    Expect,
    Key,
    NodeContext,
    NodeReader,
    node_failure,
    owner_ok,
    parse_items,
    parse_key_ptrs,
)
from btrfska.substrate.roots import root_sets

K = ondisk.ITEM_KEYS
LOG = ondisk.TREE_LOG_OBJECTID
MAX_STATES = 64
MAX_LISTED = 16
MAX_PROBLEMS = 32
MAX_RAW = 256
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

    def __init__(self, columns: dict[str, array], stats: dict[str, int], raw: list[dict]):
        self.stats, self.raw = stats, raw
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

    def find(self, bytenr: int, generation: int, level: int) -> list[int]:
        """Node indices with this bytenr, generation and level, in owner order."""
        if not (0 <= bytenr < 1 << 64 and 0 <= generation < 1 << 64 and 0 <= level < 256):
            return []
        lo = int(np.searchsorted(self.bytenr, np.uint64(bytenr), "left"))
        hi = int(np.searchsorted(self.bytenr, np.uint64(bytenr), "right"))
        gens = self.generation[lo:hi]
        lo, hi = (lo + int(np.searchsorted(gens, np.uint64(generation), side))
                  for side in ("left", "right"))  # fmt: skip
        levels = self.level[lo:hi]
        lo, hi = (lo + int(np.searchsorted(levels, np.uint8(level), side))
                  for side in ("left", "right"))  # fmt: skip
        first = int(np.searchsorted(self.node_start, lo, "right")) - 1
        last = int(np.searchsorted(self.node_start, hi, "left"))
        return list(range(first, last)) if lo < hi else []


def index_records(records: Iterable[NodeRecord], ctx: NodeContext) -> BlockIndex:
    """Index valid candidates (and log blocks one generation ahead); see the module docstring."""
    columns = {name: array("Q") for name in ("bytenr", "generation", "owner", "physical")}
    columns["level"] = array("B")
    stats = dict.fromkeys(
        ("candidates", "indexed_copies", "log_accepted", "log_rejected", *RAW_OWNERS.values()), 0
    )
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
    return BlockIndex(columns, stats, raw)


@dataclass(frozen=True)
class Group:
    owner: int
    generation: int
    level: int
    blocks: int  # distinct blocks
    copies: int
    unreferenced: int
    top: bool  # the highest level of this owner and generation
    candidates: int  # unreferenced blocks at the top level (0 below it)
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
    found: dict[tuple[int, int, int], int] = field(default_factory=dict)  # key -> node index
    missing: dict[tuple[int, int, int], str] = field(default_factory=dict)
    leaf_items: list = field(default_factory=list)  # (item, leaf bytenr)
    problems: list[str] = field(default_factory=list)


class _Discoverer:
    def __init__(self, img, index, ctx, chunk_map, known, log_live):
        self.img, self.index, self.ctx, self.chunk_map = img, index, ctx, chunk_map
        self.known, self.log_live = tuple(known), log_live
        self.reader = NodeReader(img, chunk_map, ctx)
        self.walks: dict = {}
        self.maps: dict = {}
        n = index.nodes
        starts = index.node_start
        self.n_bytenr, self.n_gen = index.bytenr[starts], index.generation[starts]
        self.n_level, self.n_owner = index.level[starts], index.owner[starts]
        self.n_copies = index.node_end - starts
        self.referenced = np.zeros(n, bool)
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
        self.candidate = self.top & ~self.referenced
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
        for node in np.flatnonzero(self.n_level > 0).tolist():
            block = self._block(node)
            if not self._header_matches(block, node):
                continue
            _, generation, level, owner = self.index.node(node)
            ptrs, _ = parse_key_ptrs(block, self.ctx.nodesize)
            for ptr in ptrs:
                if ptr.generation != generation:
                    continue
                for child in self.index.find(ptr.blockptr, generation, level - 1):
                    if child != node and int(self.n_owner[child]) == owner:
                        self.referenced[child] = True

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
        unreferenced = np.add.reduceat((~self.referenced[o]).astype(np.int64), starts)
        candidates = np.add.reduceat(self.candidate[o].astype(np.int64), starts)
        for i, (start, end) in enumerate(zip(starts.tolist(), ends.tolist(), strict=True)):
            members = o[start:end]
            listed = self.n_bytenr[members][self.candidate[members]][:MAX_LISTED]
            first = members[0]
            result.append(
                Group(
                    owner=int(self.n_owner[first]), generation=int(self.n_gen[first]),
                    level=int(self.n_level[first]), blocks=end - start, copies=int(copies[i]),
                    unreferenced=int(unreferenced[i]), top=bool(self.top[first]),
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

    def _missing(self, key, owner: int, first_key: Key | None) -> str:
        bytenr, generation, level = key
        expect = Expect(level=level, owner=owner, generation=generation, first_key=first_key)
        if level >= ondisk.MAX_LEVEL:
            expect = Expect(owner=owner, generation=generation, first_key=first_key)
        node = self.reader.read(bytenr, expect)
        failure = node_failure(node, expect)
        if failure is None:
            return "not_scanned" if level < ondisk.MAX_LEVEL else "mismatch"
        return failure

    def walk(self, bytenr: int, generation: int, level: int, owner: int, kind: str) -> _Walk:
        """The blocks of one tree found through the index; memoised per root and kind."""
        memo = (bytenr, generation, level, owner, kind)
        if memo in self.walks:
            return self.walks[memo]
        result = _Walk()
        stack = [((bytenr, generation, level), None, "root")]
        seen = set()
        while stack:
            key, first_key, where = stack.pop()
            if key in seen:
                result.problems.append(
                    f"{where} points to {key[0]} (generation {key[1]}, level {key[2]}), "
                    "already reached; not followed"
                )
                continue
            seen.add(key)
            node = self._resolve(*key, owner)
            if node is None:
                result.missing[key] = self._missing(key, owner, first_key)
                continue
            block = self._block(node)
            if not self._header_matches(block, node):
                result.missing[key] = "changed"
                result.problems.append(f"block {key[0]} no longer matches the scan record")
                continue
            count = ondisk.HEADER.unpack_from(block)["nritems"]
            if first_key is not None:
                first = ondisk.ITEM.unpack_from(block, ondisk.HEADER.size) if count else None
                have = (
                    None
                    if first is None
                    else Key(first["key_objectid"], first["key_type"], first["key_offset"])
                )
                if have != first_key:
                    result.missing[key] = "mismatch"
                    result.problems.append(
                        f"{where}: block {key[0]} first key {have} != pointer key {first_key}"
                    )
                    continue
            result.found[key] = node
            if key[2] > 0:
                ptrs, _ = parse_key_ptrs(block, self.ctx.nodesize)
                for ptr in reversed(ptrs):
                    child = (ptr.blockptr, ptr.generation, key[2] - 1)
                    stack.append((child, ptr.key, f"node {key[0]} slot {ptr.slot}"))
            elif kind in ("root", "chunk"):
                wanted = K["ROOT_ITEM"] if kind == "root" else K["CHUNK_ITEM"]
                leaf_items, _ = parse_items(block, self.ctx.nodesize)
                result.leaf_items += [(i, key[0]) for i in leaf_items if i.key.type == wanted]
        self.walks[memo] = result
        return result

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
            # Ties: the highest level, then the lowest bytenr.
            best = max(
                newest.tolist(), key=lambda j: (int(self.n_level[j]), -int(self.n_bytenr[j]))
            )
            bytenr, gen, level, _ = self.index.node(best)
            chunk = (bytenr, gen, level, "inferred")
        differs = self.current_chunk is None or chunk[:2] != self.current_chunk
        return ChunkRoot(*chunk, differs_from_current=differs)

    def _historical_map(self, root: ChunkRoot) -> ChunkMap:
        memo = (root.bytenr, root.generation, root.level)
        if memo not in self.maps:
            walked = self.walk(*memo, ondisk.CHUNK_TREE_OBJECTID, "chunk")
            chunks = [
                parse_chunk(item.key.offset, item.data, sectorsize=self.ctx.sectorsize,
                            origin=f"historical chunk tree leaf {leaf} slot {item.slot}")
                for item, leaf in walked.leaf_items
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
        root_walk = self.walk(bytenr, generation, level, ondisk.ROOT_TREE_OBJECTID, "root")
        found, missing = dict(root_walk.found), dict(root_walk.missing)
        item_problems, walk_problems = [], list(root_walk.problems)
        trees = []
        for item, leaf in root_walk.leaf_items:
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
            walked = self.walk(*key, item.key.objectid, "tree")
            status = "found" if key in walked.found else walked.missing[key]
            trees.append(TreeRef(*ref, status, len(walked.found), len(walked.missing)))
            found.update(walked.found)
            missing.update(walked.missing)
            walk_problems += [f"tree {item.key.objectid}: {p}" for p in walked.problems]
        for key in found:
            missing.pop(key, None)
        counts: dict[str, int] = {}
        for failure in missing.values():
            counts[failure] = counts.get(failure, 0) + 1
        chunk_root = self._chunk_root(known_as, generation)
        historical = None
        if chunk_root is not None and chunk_root.differs_from_current:
            historical = self._historical_map(chunk_root)
        placed_current = placed_historical = neither = 0
        for (block_bytenr, _, _), block in found.items():
            here = self._placed(self.chunk_map, block_bytenr, block)
            there = historical is not None and self._placed(historical, block_bytenr, block)
            placed_current += here
            placed_historical += there
            neither += not (here or there)
        problems = item_problems + walk_problems
        if len(problems) > MAX_PROBLEMS:
            problems = problems[:MAX_PROBLEMS] + [
                f"and {len(problems) - MAX_PROBLEMS} more problems"
            ]
        referenced = len(found) + len(missing)
        return State(
            bytenr=bytenr, generation=generation, level=level, copies=self.index.copies(node),
            known_as=known_as, trees=tuple(trees), root_tree_blocks=len(root_walk.found),
            root_tree_missing=len(root_walk.missing), found=len(found), referenced=referenced,
            missing=counts, completeness=len(found) / referenced if referenced else 0.0,
            chunk_root=chunk_root, maps_current=placed_current,
            maps_historical=None if historical is None else placed_historical,
            maps_neither=neither, problems=tuple(problems),
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
