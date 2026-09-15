"""Orphan classification of scanned nodes.

Reachability is computed with the anchored walker (substrate/tree.py), per root set:
- a root set's trees are its superblock or backup-slot trees and every tree named by a ROOT_ITEM
  in its root tree (all subvolumes and snapshots included);
- for the current state, the log tree when the superblock names one (`log_root`), walked in a log
  context (node.py: owner BTRFS_TREE_LOG_OBJECTID, generation exactly superblock + 1). The log
  root tree comes from the superblock only; the subvolume logs are the trees its ROOT_ITEMs keyed
  (TREE_LOG_OBJECTID, ROOT_ITEM, subvolume id) name (tree-log.c:7720-7744). A subvolume log's own
  leaves are never searched for roots, and nothing named by the ordinary root tree is a log;
- a (logical, physical) pair is reached when the walk read a copy at that physical offset and the
  copy passed every check.

A valid scanned node is then:
- `live`: reached from the current state. `log_tree` marks a copy the log walk reached;
- `backup_reachable`: not live, but reached from a backup root. Backup roots are not live: the
  kernel may reuse their blocks at any time;
- `unreferenced`: reached from neither.
The last two are the orphans. An invalid candidate is `invalid` and never an orphan.

A scanned copy of a log block fails the context-free generation check (its generation is the
superblock's + 1). It is re-checked in the log context only when the log walk reached that exact
(logical, physical) copy, whose bytes then passed every check with the log expectations. No other
candidate is accepted above the superblock generation.

Flags on every candidate:
- `outside_map`: its physical offset lies in no stripe of the current chunk map (relocated or
  removed chunks);
- `legacy_orphan`: the prototype's definition, kept for parity (legacy/utils/btree.py:472-517): a
  nodesize-aligned block whose checksum validates and whose generation is below the superblock's.

The prototype's live set came from the extent tree (legacy/utils/orphan_scan.py). It is kept as a
content cross-check: the tree blocks the current extent tree lists (METADATA_ITEM, and EXTENT_ITEM
with the TREE_BLOCK flag) are compared with the logical addresses the current walks reach. The
extent tree is found through the same current root tree as the walks, so the check is not
independent of that root: a forged or damaged root tree misleads both. Log blocks never get an
extent-tree reference (extent-tree.c:5392) and are counted apart.

Memory. `classify` is a generator and `Tally` keeps running counters, so a scan holds one
candidate at a time however many the image yields. What stays in memory is bounded by the size of
the reachable trees, not by the number of candidates: the reached (logical, physical) sets of the
current state, its log and the backup roots, and the extent tree's block list.
"""

import bisect
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace

from btrfska.scan.kernel_numpy import NodeRecord, iter_candidate_nodes
from btrfska.scan.regions import Region, ScanPlan, plan_scan, stripe_extents, this_device
from btrfska.substrate import items, ondisk
from btrfska.substrate.fs import Filesystem
from btrfska.substrate.image import ImageHandle
from btrfska.substrate.node import Check, NodeContext, NodeReader, node_failure
from btrfska.substrate.roots import RootNotFound, RootSet, TreeRoot, resolve_tree, root_sets
from btrfska.substrate.tree import walk

K = ondisk.ITEM_KEYS
LOG = ondisk.TREE_LOG_OBJECTID
STATUSES = ("invalid", "live", "backup_reachable", "unreferenced")


@dataclass(frozen=True)
class Reachability:
    live: frozenset[tuple[int, int]]  # (logical, physical) of valid copies reached, current state
    backup: frozenset[tuple[int, int]]  # the same, from every backup root set
    live_logical: frozenset[int]  # logical addresses the current walks reached, valid or not
    extent_tree: frozenset[int]  # tree blocks the current extent tree lists
    problems: tuple[str, ...]
    log: frozenset[tuple[int, int]] = frozenset()  # the subset of `live` the log walk reached
    log_logical: frozenset[int] = frozenset()  # logical addresses the log walk reached
    # (root set source, tree id, logical, node.FAILURE_CLASSES entry) per invalid node walked
    walk_failures: tuple[tuple[str, int, int, str], ...] = ()

    @classmethod
    def empty(cls) -> Reachability:
        return cls(frozenset(), frozenset(), frozenset(), frozenset(), ())


@dataclass(frozen=True)
class Classified:
    record: NodeRecord
    status: str  # one of STATUSES
    outside_map: bool
    legacy_orphan: bool
    log_tree: bool = False  # this copy was reached by the walk of the superblock's log tree

    @property
    def orphan(self) -> bool:
        return self.status in ("backup_reachable", "unreferenced")


@dataclass
class Walked:
    """What the walks of one root set reached."""

    pairs: set[tuple[int, int]] = field(default_factory=set)
    logicals: set[int] = field(default_factory=set)
    log_pairs: set[tuple[int, int]] = field(default_factory=set)
    log_logicals: set[int] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    # (tree id, logical, failure class) per invalid node: reuse is told apart from damage
    failures: list[tuple[int, int, str]] = field(default_factory=list)


def _log_root(fields: dict | None) -> TreeRoot | None:
    if fields is None or not fields["log_root"]:
        return None
    return TreeRoot(
        LOG, fields["log_root"], fields["log_root_level"], fields["generation"] + 1,
        "superblock log_root", log=True,
    )  # fmt: skip


def walk_root_set(reader: NodeReader, root_set: RootSet, fields: dict | None = None) -> Walked:
    """Walk every tree of `root_set`; with `fields` (the superblock of that state), its log too."""
    # (tree, whether its leaves name further trees)
    queue = deque(
        (tree, tree.tree_id == ondisk.ROOT_TREE_OBJECTID) for tree in root_set.trees.values()
    )
    if (log_root := _log_root(fields)) is not None:
        queue.append((log_root, True))
    walked, seen = Walked(), set()
    while queue:
        tree, names_trees = queue.popleft()
        if (tree.bytenr, tree.log) in seen:
            continue
        seen.add((tree.bytenr, tree.log))
        for visit in walk(reader, tree.bytenr, tree.expect()):
            node = visit.node
            where = f"{root_set.source}: tree {tree.tree_id} node {node.logical}"
            pairs = {(node.logical, copy.physical) for copy in node.copies if copy.ok}
            walked.logicals.add(node.logical)
            walked.pairs |= pairs
            if tree.log:
                walked.log_logicals.add(node.logical)
                walked.log_pairs |= pairs
            if not node.valid:
                walked.problems.append(f"{where} is invalid: {'; '.join(node.problems)}")
                failure = node_failure(node, visit.expect)
                walked.failures.append((tree.tree_id, node.logical, failure))
                continue
            walked.problems += [f"{where}: {p}" for p in visit.problems]
            if node.level or not names_trees:
                continue
            for item in node.items:
                if item.key.type != K["ROOT_ITEM"] or (tree.log and item.key.objectid != LOG):
                    continue
                try:
                    parsed = items.root_item(item.data)
                except items.ItemError as exc:
                    walked.problems.append(f"{where}: ROOT_ITEM {item.key}: {exc}")
                    continue
                via = f"ROOT_ITEM {item.key} in leaf {node.logical} slot {item.slot}"
                child = TreeRoot(
                    item.key.objectid, parsed["bytenr"], parsed["level"], parsed["generation"],
                    via, log=tree.log,
                )  # fmt: skip
                queue.append((child, False))
    return walked


def extent_tree_blocks(reader: NodeReader, root_set: RootSet) -> tuple[frozenset[int], list[str]]:
    """Logical addresses of the tree blocks that `root_set`'s extent tree lists."""
    try:
        root = resolve_tree(reader, root_set, "extent")
    except RootNotFound as exc:
        return frozenset(), [f"extent tree: {exc}"]
    blocks, problems = set(), []
    for visit in walk(reader, root.bytenr, root.expect()):
        node = visit.node
        if not node.valid:
            problems.append(
                f"extent tree node {node.logical} is invalid: {'; '.join(node.problems)}"
            )
            continue
        for item in node.items if node.level == 0 else ():
            if item.key.type == K["METADATA_ITEM"]:
                blocks.add(item.key.objectid)
            elif item.key.type == K["EXTENT_ITEM"] and item.size >= ondisk.EXTENT_ITEM.size:
                if (
                    ondisk.EXTENT_ITEM.unpack_from(item.data)["flags"]
                    & ondisk.EXTENT_FLAG_TREE_BLOCK
                ):
                    blocks.add(item.key.objectid)
    return frozenset(blocks), problems


def reachability(fs: Filesystem) -> Reachability:
    sets = root_sets(fs.fields)
    current = walk_root_set(fs.reader, sets[-1], fs.fields)
    backup, problems = set(), list(current.problems)
    failures = [("current", *failure) for failure in current.failures]
    for root_set in sets[:-1]:
        walked = walk_root_set(fs.reader, root_set)
        backup |= walked.pairs
        problems += walked.problems
        failures += [(root_set.source, *failure) for failure in walked.failures]
    extent, found = extent_tree_blocks(fs.reader, sets[-1])
    return Reachability(
        live=frozenset(current.pairs),
        backup=frozenset(backup),
        live_logical=frozenset(current.logicals),
        extent_tree=extent,
        problems=tuple(problems + found),
        log=frozenset(current.log_pairs),
        log_logical=frozenset(current.log_logicals),
        walk_failures=tuple(failures),
    )


def failure_counts(failures: Iterable[tuple[str, int, int, str]]) -> dict[str, dict[str, int]]:
    """Walk failures per class, for the current state and for all backup roots together."""
    counts = {"current": {}, "backup": {}}
    for source, _, _, failure in failures:
        side = counts["current" if source == "current" else "backup"]
        side[failure] = side.get(failure, 0) + 1
    return counts


def _merge(ranges: Iterable[tuple[int, int]]) -> list[list[int]]:
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _in_log_context(record: NodeRecord, ctx: NodeContext) -> NodeRecord:
    """`record` with its generation check redone as the log walk did it (node.py)."""
    limit = ctx.generation + 1
    checks = tuple(
        Check("generation", True) if check.name == "generation" else check
        for check in record.checks
    )
    if record.generation != limit or not checks:
        return record
    return replace(record, checks=checks, valid=all(check.ok is not False for check in checks))


def classify(
    records: Iterable[NodeRecord],
    reach: Reachability,
    mapped: Sequence[Region],
    ctx: NodeContext,
) -> Iterator[Classified]:
    """Classify `records` one at a time; `mapped` holds the stripe ranges of the current map."""
    ranges = _merge((r.start, r.end) for r in mapped)
    starts = [start for start, _ in ranges]
    for record in records:
        pair = (record.bytenr, record.physical)
        log_tree = pair in reach.log
        if log_tree:
            record = _in_log_context(record, ctx)
        if not record.valid:
            status = "invalid"
        elif pair in reach.live:
            status = "live"
        elif pair in reach.backup:
            status = "backup_reachable"
        else:
            status = "unreferenced"
        index = bisect.bisect_right(starts, record.physical) - 1
        outside = index < 0 or record.physical >= ranges[index][1]
        csum_ok = any(check.name == "csum" and check.ok for check in record.checks)
        legacy = (
            csum_ok
            and record.generation is not None
            and record.generation < ctx.generation
            and record.physical % ctx.nodesize == 0
        )
        yield Classified(record, status, outside, legacy, log_tree)


def _region_row(region: Region) -> dict:
    return {"region": region, "candidates": 0, "valid": 0, "live": 0, "orphans": 0}


class Tally:
    """Running summary counters: memory grows with the regions, not with the candidates."""

    COUNTERS = (
        "candidates", "valid", "invalid", "live", "backup_reachable", "unreferenced",
        "outside_map", "outside_map_orphans", "bytenr_elsewhere", "legacy_orphans",
        "legacy_orphans_outside_map", "log_tree",
    )  # fmt: skip

    def __init__(
        self, regions: Sequence[Region], reach: Reachability, skipped: Sequence[Region] = ()
    ):
        self.reach = reach
        self.counts = dict.fromkeys(self.COUNTERS, 0)
        self.regions = {region: _region_row(region) for region in regions}
        # Skipped ranges that belong to a chunk are the DATA chunks the plan left out.
        self.skipped_data_bytes = sum(r.end - r.start for r in skipped if r.chunk is not None)
        self.finished = False

    def add(self, c: Classified) -> None:
        n, valid = self.counts, c.record.valid
        n["candidates"] += 1
        n[c.status] += 1
        n["valid"] += valid
        n["outside_map"] += valid and c.outside_map
        n["outside_map_orphans"] += c.orphan and c.outside_map
        n["bytenr_elsewhere"] += valid and not c.record.maps_here
        n["legacy_orphans"] += c.legacy_orphan
        n["legacy_orphans_outside_map"] += c.legacy_orphan and c.outside_map
        n["log_tree"] += c.log_tree and c.status == "live"
        row = self.regions.setdefault(c.record.region, _region_row(c.record.region))
        row["candidates"] += 1
        row["valid"] += valid
        row["live"] += c.status == "live"
        row["orphans"] += c.orphan

    def summary(self) -> dict:
        n, reach = self.counts, self.reach
        return {
            **n,
            "orphans": n["backup_reachable"] + n["unreferenced"],
            "extent_tree": len(reach.extent_tree),
            "walk_only": len(reach.live_logical - reach.extent_tree - reach.log_logical),
            "extent_tree_only": len(reach.extent_tree - reach.live_logical),
            "log_tree_blocks": len(reach.log_logical),
            "skipped_data_bytes": self.skipped_data_bytes,
            "walk_failures": failure_counts(reach.walk_failures),
            "regions": list(self.regions.values()),
        }


def summarize(
    classified: Iterable[Classified],
    regions: Sequence[Region],
    reach: Reachability,
    skipped: Sequence[Region] = (),
) -> dict:
    tally = Tally(regions, reach, skipped)
    for c in classified:
        tally.add(c)
    return tally.summary()


@dataclass(frozen=True)
class ScanResult:
    """A scan in progress. `classified` is a one-shot stream; iterate it while the image is open.
    `summary` is available once the stream is exhausted."""

    plan: ScanPlan
    reach: Reachability
    classified: Iterator[Classified]
    tally: Tally

    @property
    def summary(self) -> dict:
        if not self.tally.finished:
            raise RuntimeError("the scan summary needs the classified stream to be exhausted")
        return self.tally.summary()


def _counted(classified: Iterator[Classified], tally: Tally) -> Iterator[Classified]:
    for item in classified:
        tally.add(item)
        yield item
    tally.finished = True


def scan_image(
    img: ImageHandle, fs: Filesystem, full_sweep: bool = False, workers: int = 1
) -> ScanResult:
    """Plan the regions and walk the roots now; scan and classify as `classified` is iterated."""
    plan = plan_scan(fs, img.size, full_sweep)
    reach = reachability(fs)
    records = iter_candidate_nodes(img, plan.regions, fs.reader.ctx, fs.chunk_map, workers=workers)
    mapped = stripe_extents(fs.chunk_map, this_device(fs))
    tally = Tally(plan.regions, reach, plan.skipped)
    stream = _counted(classify(records, reach, mapped, fs.reader.ctx), tally)
    return ScanResult(plan, reach, stream, tally)
