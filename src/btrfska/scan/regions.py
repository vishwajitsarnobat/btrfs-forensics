"""Scan regions: the physical ranges of this device where tree blocks can lie, with provenance.

Ported from the legacy `build_scan_regions` (legacy/utils/chunk_parser.py:211-266): the candidate
space is the whole device except the boot area and the DATA chunks, so the ranges that removed or
relocated chunks left behind (unmapped gaps) are scanned too. Each region names where it comes
from: a chunk stripe (`kind` is the chunk type as dump-tree prints it, with the chunk's logical
address and stripe index) or `unmapped_gap`. Kernel v7.0 references:
- a stripe covers chunk length / data stripes on its device, where data stripes =
  (num_stripes - nparity) / ncopies (volumes.c:4023-4030 calc_data_stripes, l.7271-7276
  btrfs_calc_stripe_length);
- tree blocks never overlap a superblock copy or the first 64 KiB: both are excluded from every
  block group's free space (block-group.c:2277-2330 exclude_super_stripes). The ranges up to the
  end of the primary superblock are skipped as `reserved`, the other copies as `superblock`;
- with MIXED_GROUPS, block groups hold data and metadata alike (block-group.c:2429), so DATA
  chunks are scanned (the prototype's MIXED_GROUPS defect, research.md §8);
- block-group items live in the block-group tree (tree 11) when compat_ro BLOCK_GROUP_TREE is set,
  else in the extent tree (block-group.c:1053-1058 btrfs_block_group_root).

A DATA chunk is skipped only when its block-group item agrees (same length, type and profile), so
one altered or damaged item cannot hide a range from the scan. Rejected chunk items never exclude
a range. `--full-sweep` scans every range except the reserved area and superblock copies.
"""

from dataclasses import dataclass, replace

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import BG, PROFILE_MASK, PROFILES, TYPE_MASK, ChunkMap, type_name
from btrfska.substrate.fs import Filesystem
from btrfska.substrate.roots import RootNotFound, find_root_set, resolve_tree
from btrfska.substrate.tree import walk

RESERVED_END = ondisk.SUPER_INFO_OFFSET + ondisk.SUPER_INFO_SIZE
GAP = "unmapped_gap"
_TYPE_AND_PROFILE = TYPE_MASK | PROFILE_MASK


@dataclass(frozen=True)
class Region:
    """A physical byte range [start, end) of the image and where it comes from."""

    start: int
    end: int
    kind: str  # a chunk type such as METADATA|DUP, unmapped_gap, reserved or superblock
    chunk: int | None = None  # logical address of the chunk whose stripe this is
    stripe: int | None = None  # the stripe's index in that chunk


@dataclass(frozen=True)
class ScanPlan:
    regions: tuple[Region, ...]  # scanned, sorted and disjoint
    skipped: tuple[Region, ...]  # not scanned; regions and skipped ranges partition the image
    problems: tuple[str, ...] = ()
    full_sweep: bool = False


def this_device(fs: Filesystem) -> int:
    """The devid of the device this image holds (the superblock's dev_item)."""
    return ondisk.DEV_ITEM.unpack_from(fs.fields["dev_item"])["devid"]


def stripe_extents(chunk_map: ChunkMap, devid: int) -> list[Region]:
    """The physical range of every stripe of every valid chunk that lies on device `devid`."""
    extents = []
    device_uuid = chunk_map.devices.get(devid)
    for chunk in chunk_map.chunks:
        _, ncopies, nparity = PROFILES.get(chunk.type & PROFILE_MASK, ("", 1, 0))
        length = chunk.length // max(1, (chunk.num_stripes - nparity) // ncopies)
        kind = type_name(chunk.type)
        for index, stripe in enumerate(chunk.stripes):
            if stripe.devid == devid and stripe.dev_uuid == device_uuid:
                end = stripe.offset + length
                extents.append(Region(stripe.offset, end, kind, chunk.logical, index))
    return sorted(extents, key=lambda r: (r.start, r.chunk, r.stripe))


def _skippable(chunk_map: ChunkMap, incompat: int, block_groups) -> tuple[set[int], list[str]]:
    """Logical addresses of DATA-only chunks that may be skipped, and why others were not."""
    skippable, problems = set(), []
    if incompat & ondisk.INCOMPAT["MIXED_GROUPS"]:
        return skippable, problems
    for chunk in chunk_map.chunks:
        if chunk.type & TYPE_MASK != BG["DATA"]:
            continue
        group = None if block_groups is None else block_groups.get(chunk.logical)
        if block_groups is None:
            skippable.add(chunk.logical)
        elif group is None:
            problems.append(f"DATA chunk {chunk.logical}: no block group item; scanned")
        elif (group[0], group[1] & _TYPE_AND_PROFILE) != (
            chunk.length,
            chunk.type & _TYPE_AND_PROFILE,
        ):
            problems.append(
                f"DATA chunk {chunk.logical}: block group item (length {group[0]}, "
                f"{type_name(group[1])}) differs from the chunk (length {chunk.length}, "
                f"{type_name(chunk.type)}); scanned"
            )
        else:
            skippable.add(chunk.logical)
    return skippable, problems


def build_regions(
    chunk_map: ChunkMap,
    image_size: int,
    *,
    devid: int,
    incompat: int,
    block_groups: dict[int, tuple[int, int]] | None = None,
    full_sweep: bool = False,
) -> ScanPlan:
    """Split [0, image_size) into scanned regions and skipped ranges.

    `block_groups` maps a block group's logical address to (length, flags); None trusts chunk
    types alone. Never raises on content.
    """
    extents = [replace(e, end=min(e.end, image_size)) for e in stripe_extents(chunk_map, devid)]
    extents = [e for e in extents if e.start < e.end]
    skippable, problems = (
        (set(), []) if full_sweep else _skippable(chunk_map, incompat, block_groups)
    )
    cuts = [Region(0, min(RESERVED_END, image_size), "reserved")]
    for mirror in range(1, ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset < image_size:
            end = min(offset + ondisk.SUPER_INFO_SIZE, image_size)
            cuts.append(Region(offset, end, "superblock"))

    bounds = {0, image_size}
    for item in (*cuts, *extents):
        bounds.update((item.start, item.end))
    bounds = sorted(b for b in bounds if 0 <= b <= image_size)

    pieces, overlaps = [], {}  # (scanned, region); overlapping chunk pair -> [start, end]
    for start, end in zip(bounds, bounds[1:], strict=False):
        cut = next((c for c in cuts if c.start <= start and end <= c.end), None)
        if cut is not None:
            pieces.append((False, Region(start, end, cut.kind)))
            continue
        covering = [e for e in extents if e.start <= start and end <= e.end]
        chunks = sorted({e.chunk for e in covering})
        for a, b in zip(chunks, chunks[1:], strict=False):
            span = overlaps.setdefault((a, b), [start, end])
            span[0], span[1] = min(span[0], start), max(span[1], end)
        if not covering:
            pieces.append((True, Region(start, end, GAP)))
            continue
        covering.sort(key=lambda e: (e.chunk in skippable, e.chunk, e.stripe))
        first = covering[0]
        scanned = full_sweep or first.chunk not in skippable
        pieces.append((scanned, Region(start, end, first.kind, first.chunk, first.stripe)))

    for (a, b), (start, end) in overlaps.items():
        problems.append(f"chunks {a} and {b} overlap at physical {start}-{end}; scanned")

    merged = []
    for scanned, region in pieces:
        if merged:
            previous_scanned, previous = merged[-1]
            if previous_scanned == scanned and replace(previous, start=0, end=0) == replace(
                region, start=0, end=0
            ):
                merged[-1] = (scanned, replace(previous, end=region.end))
                continue
        merged.append((scanned, region))
    return ScanPlan(
        regions=tuple(r for scanned, r in merged if scanned),
        skipped=tuple(r for scanned, r in merged if not scanned),
        problems=tuple(problems),
        full_sweep=full_sweep,
    )


def read_block_groups(fs: Filesystem) -> tuple[dict[int, tuple[int, int]], tuple[str, ...]]:
    """BLOCK_GROUP_ITEMs of the current state: logical address -> (length, flags).

    Read from tree 11 when compat_ro BLOCK_GROUP_TREE is set, else from the extent tree.
    """
    tree = (
        ondisk.BLOCK_GROUP_TREE_OBJECTID
        if fs.verdict.block_group_tree
        else ondisk.EXTENT_TREE_OBJECTID
    )
    try:
        root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), tree)
    except RootNotFound as exc:
        return {}, (f"block groups: {exc}",)
    groups, problems = {}, []
    item_size = ondisk.BLOCK_GROUP_ITEM.size
    for visit in walk(fs.reader, root.bytenr, root.expect()):
        node = visit.node
        where = f"block groups: tree {tree} node {node.logical}"
        if not node.valid:
            problems.append(f"{where} is invalid: {'; '.join(node.problems)}")
            continue
        problems += [f"{where}: {p}" for p in visit.problems]
        for item in node.items if node.level == 0 else ():
            if item.key.type != ondisk.ITEM_KEYS["BLOCK_GROUP_ITEM"]:
                continue
            if item.size < item_size:
                problems.append(f"{where}: block group item {item.key} is {item.size} bytes")
                continue
            flags = ondisk.BLOCK_GROUP_ITEM.unpack_from(item.data)["flags"]
            groups[item.key.objectid] = (item.key.offset, flags)
    return groups, tuple(problems)


def plan_scan(fs: Filesystem, image_size: int, full_sweep: bool = False) -> ScanPlan:
    """The scan plan for this filesystem's current chunk map; see the module docstring."""
    groups, problems = ({}, ()) if full_sweep else read_block_groups(fs)
    plan = build_regions(
        fs.chunk_map,
        image_size,
        devid=this_device(fs),
        incompat=fs.fields["incompat_flags"],
        block_groups=None if full_sweep else groups,
        full_sweep=full_sweep,
    )
    return replace(plan, problems=(*problems, *plan.problems))
