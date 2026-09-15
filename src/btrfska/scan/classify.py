"""Orphan classification of scanned nodes.

Reachability is computed with the anchored walker (substrate/tree.py), per root set:
- a root set's trees are its superblock or backup-slot trees, every tree named by a ROOT_ITEM in
  its root tree (all subvolumes and snapshots included) and, for the current state, the log tree
  when the superblock names one;
- a (logical, physical) pair is reached when the walk read a copy at that physical offset and the
  copy passed every check.

A valid scanned node is then:
- `live`: reached from the current state;
- `backup_reachable`: not live, but reached from a backup root. Backup roots are not live: the
  kernel may reuse their blocks at any time;
- `unreferenced`: reached from neither.
The last two are the orphans. An invalid candidate is `invalid` and never an orphan.

Flags on every candidate:
- `outside_map`: its physical offset lies in no stripe of the current chunk map (relocated or
  removed chunks);
- `legacy_orphan`: the prototype's definition, kept for parity (legacy/utils/btree.py:472-517): a
  nodesize-aligned block whose checksum validates and whose generation is below the superblock's.

The prototype's live set came from the extent tree (legacy/utils/orphan_scan.py). It is kept as a
cross-check: the tree blocks the current extent tree lists (METADATA_ITEM, and EXTENT_ITEM with the
TREE_BLOCK flag) are compared with the logical addresses the current walks reach.
"""

import bisect
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from btrfska.scan.kernel_numpy import NodeRecord, iter_candidate_nodes
from btrfska.scan.regions import Region, ScanPlan, plan_scan, stripe_extents, this_device
from btrfska.substrate import items, ondisk
from btrfska.substrate.fs import Filesystem
from btrfska.substrate.image import ImageHandle
from btrfska.substrate.node import NodeContext, NodeReader
from btrfska.substrate.roots import RootNotFound, RootSet, TreeRoot, resolve_tree, root_sets
from btrfska.substrate.tree import walk

K = ondisk.ITEM_KEYS
STATUSES = ("invalid", "live", "backup_reachable", "unreferenced")
_ROOT_TREES = (ondisk.ROOT_TREE_OBJECTID, ondisk.TREE_LOG_OBJECTID)


@dataclass(frozen=True)
class Reachability:
    live: frozenset[tuple[int, int]]  # (logical, physical) of valid copies reached, current state
    backup: frozenset[tuple[int, int]]  # the same, from every backup root set
    live_logical: frozenset[int]  # logical addresses the current walks reached, valid or not
    extent_tree: frozenset[int]  # tree blocks the current extent tree lists
    problems: tuple[str, ...]

    @classmethod
    def empty(cls) -> Reachability:
        return cls(frozenset(), frozenset(), frozenset(), frozenset(), ())


@dataclass(frozen=True)
class Classified:
    record: NodeRecord
    status: str  # one of STATUSES
    outside_map: bool
    legacy_orphan: bool

    @property
    def orphan(self) -> bool:
        return self.status in ("backup_reachable", "unreferenced")


def _trees(root_set: RootSet, fields: dict | None) -> list[TreeRoot]:
    trees = list(root_set.trees.values())
    if fields is not None and fields["log_root"]:
        log = TreeRoot(
            ondisk.TREE_LOG_OBJECTID, fields["log_root"], fields["log_root_level"], None,
            "superblock log_root",
        )  # fmt: skip
        trees.append(log)
    return trees


def _reach(reader: NodeReader, root_set: RootSet, fields: dict | None = None):
    """(valid pairs, logical addresses reached, problems) for every tree of `root_set`."""
    queue, seen = _trees(root_set, fields), set()
    pairs, logicals, problems = set(), set(), []
    while queue:
        tree = queue.pop(0)
        if tree.bytenr in seen:
            continue
        seen.add(tree.bytenr)
        for visit in walk(reader, tree.bytenr, tree.expect()):
            node = visit.node
            where = f"{root_set.source}: tree {tree.tree_id} node {node.logical}"
            logicals.add(node.logical)
            pairs.update((node.logical, copy.physical) for copy in node.copies if copy.ok)
            if not node.valid:
                problems.append(f"{where} is invalid: {'; '.join(node.problems)}")
                continue
            problems += [f"{where}: {p}" for p in visit.problems]
            if node.level or tree.tree_id not in _ROOT_TREES:
                continue
            for item in node.items:
                if item.key.type != K["ROOT_ITEM"]:
                    continue
                try:
                    parsed = items.root_item(item.data)
                except items.ItemError as exc:
                    problems.append(f"{where}: ROOT_ITEM {item.key}: {exc}")
                    continue
                via = f"ROOT_ITEM {item.key} in leaf {node.logical} slot {item.slot}"
                queue.append(
                    TreeRoot(
                        item.key.objectid, parsed["bytenr"], parsed["level"],
                        parsed["generation"], via,
                    )
                )  # fmt: skip
    return pairs, logicals, problems


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
    live, live_logical, problems = _reach(fs.reader, sets[-1], fs.fields)
    backup = set()
    for root_set in sets[:-1]:
        pairs, _, found = _reach(fs.reader, root_set)
        backup |= pairs
        problems += found
    extent, found = extent_tree_blocks(fs.reader, sets[-1])
    return Reachability(
        live=frozenset(live),
        backup=frozenset(backup),
        live_logical=frozenset(live_logical),
        extent_tree=extent,
        problems=tuple(problems + found),
    )


def _merge(ranges: Iterable[tuple[int, int]]) -> list[list[int]]:
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def classify(
    records: Iterable[NodeRecord],
    reach: Reachability,
    mapped: Sequence[Region],
    ctx: NodeContext,
) -> list[Classified]:
    """Classify `records`; `mapped` holds the stripe ranges of the current chunk map."""
    ranges = _merge((r.start, r.end) for r in mapped)
    starts = [start for start, _ in ranges]
    result = []
    for record in records:
        pair = (record.bytenr, record.physical)
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
        result.append(Classified(record, status, outside, legacy))
    return result


def summarize(
    classified: Sequence[Classified], regions: Sequence[Region], reach: Reachability
) -> dict:
    valid = [c for c in classified if c.record.valid]
    count = {status: sum(c.status == status for c in classified) for status in STATUSES}
    per_region = {
        region: {"region": region, "candidates": 0, "valid": 0, "live": 0, "orphans": 0}
        for region in regions
    }
    for c in classified:
        row = per_region.setdefault(
            c.record.region,
            {"region": c.record.region, "candidates": 0, "valid": 0, "live": 0, "orphans": 0},
        )
        row["candidates"] += 1
        row["valid"] += c.record.valid
        row["live"] += c.status == "live"
        row["orphans"] += c.orphan
    return {
        "candidates": len(classified),
        "valid": len(valid),
        "invalid": count["invalid"],
        "live": count["live"],
        "orphans": count["backup_reachable"] + count["unreferenced"],
        "backup_reachable": count["backup_reachable"],
        "unreferenced": count["unreferenced"],
        "outside_map": sum(c.outside_map for c in valid),
        "outside_map_orphans": sum(c.outside_map and c.orphan for c in classified),
        "bytenr_elsewhere": sum(not c.record.maps_here for c in valid),
        "legacy_orphans": sum(c.legacy_orphan for c in classified),
        "legacy_orphans_outside_map": sum(c.legacy_orphan and c.outside_map for c in classified),
        "extent_tree": len(reach.extent_tree),
        "walk_only": len(reach.live_logical - reach.extent_tree),
        "extent_tree_only": len(reach.extent_tree - reach.live_logical),
        "regions": list(per_region.values()),
    }


@dataclass(frozen=True)
class ScanResult:
    plan: ScanPlan
    reach: Reachability
    classified: list[Classified]
    summary: dict


def scan_image(
    img: ImageHandle, fs: Filesystem, full_sweep: bool = False, workers: int = 1
) -> ScanResult:
    """Plan the regions, scan them, and classify every candidate against the walks."""
    plan = plan_scan(fs, img.size, full_sweep)
    reach = reachability(fs)
    records = iter_candidate_nodes(img, plan.regions, fs.reader.ctx, fs.chunk_map, workers=workers)
    mapped = stripe_extents(fs.chunk_map, this_device(fs))
    classified = classify(records, reach, mapped, fs.reader.ctx)
    return ScanResult(plan, reach, classified, summarize(classified, plan.regions, reach))
