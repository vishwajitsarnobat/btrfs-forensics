"""Scan kernel, numpy implementation: every tree-block candidate in the given physical regions.

`iter_candidate_nodes(img, regions, ctx, chunk_map)` is the interface a later Rust kernel keeps
(plan.md §2). It probes every sector-aligned offset of every region, so nodes are found wherever
their header starts, not only on nodesize boundaries:
1. prefilter: the 16 bytes at header +0x20 must equal the tree fsid (`ctx.fsid`, which is the
   superblock's metadata_uuid when METADATA_UUID is set). numpy compares them as two u64 words
   through a strided view of the read-only map, one window of offsets at a time;
2. every hit becomes a `NodeRecord`: `node.check_block` runs without expectations and every check
   is kept, so a failed candidate is reported, never dropped. A block cut by the image end is a
   record with no checks and a `truncated` problem;
3. the header bytenr is looked up in the chunk map: does it map to this physical offset?

Regions are clipped to the image, sorted, and each offset is probed once, for the first region
that holds it. A node may extend past its region's end; it belongs to the region holding its
header. With `workers` > 1 (at most 4), regions are split into pieces that worker processes scan
through their own read-only handle; records come back in the same order.
"""

from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

import numpy as np

from btrfska.scan.regions import Region
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import ChunkMap, MappingError
from btrfska.substrate.image import ImageHandle, open_image
from btrfska.substrate.node import NO_EXPECTATIONS, Check, NodeContext, check_block

FSID_OFFSET = ondisk.HEADER.offset("fsid")
MAX_WORKERS = 4
WINDOW = 1 << 16  # offsets compared per numpy window
PIECE = 256 << 20  # bytes per worker job


@dataclass(frozen=True)
class NodeRecord:
    """One prefilter hit and its validation record. Flat and JSON-ready (dataclasses.asdict)."""

    physical: int
    bytenr: int | None  # the logical address the header claims (None: header cut by image end)
    generation: int | None
    owner: int | None
    level: int | None
    nritems: int | None
    checks: tuple[Check, ...]  # one per node.CHECK_NAMES; empty when the block is truncated
    valid: bool  # every check passed (ok is never False)
    bytenr_mapped: bool  # the current chunk map covers bytenr
    maps_here: bool  # one copy of bytenr lies at `physical` on this device
    region: Region
    problems: tuple[str, ...] = ()


def _spans(regions: Iterable[Region], size: int, step: int) -> Iterator[tuple[int, int, Region]]:
    """(first offset, end, region): disjoint, sorted, clipped, first offsets aligned to `step`."""
    cursor = 0
    for region in sorted(regions, key=lambda r: (r.start, r.end)):
        first = -(-max(region.start, cursor, 0) // step) * step
        end = min(region.end, size)
        if first < end:
            yield first, end, region
        cursor = max(cursor, end)


def _window_hits(buffer, base: int, count: int, step: int, words: tuple[int, int]) -> list[int]:
    """Offsets base + i * step (i < count) whose 16 bytes at +0x20 are the two fsid words.

    The numpy views of `buffer` die with this call, so the map can be closed between windows.
    """
    first = np.ndarray((count,), "<u8", buffer, base + FSID_OFFSET, (step,))
    candidates = np.flatnonzero(first == words[0])
    if not candidates.size:
        return []
    second = np.ndarray((count,), "<u8", buffer, base + FSID_OFFSET + 8, (step,))
    return (candidates[second[candidates] == words[1]] * step + base).tolist()


def _span_hits(img: ImageHandle, first: int, end: int, fsid: bytes, step: int) -> Iterator[int]:
    words = (int.from_bytes(fsid[:8], "little"), int.from_bytes(fsid[8:16], "little"))
    last = img.size - FSID_OFFSET - len(fsid)  # the fsid must lie inside the image
    count = min(-(-(end - first) // step), (last - first) // step + 1)
    for index in range(0, max(count, 0), WINDOW):
        base = first + index * step
        yield from _window_hits(img.mmap, base, min(WINDOW, count - index), step, words)


def iter_prefilter_hits(
    img: ImageHandle, regions: Iterable[Region], fsid: bytes, sectorsize: int
) -> Iterator[tuple[int, Region]]:
    """(physical offset, region) of every prefilter hit, without validation."""
    for first, end, region in _spans(regions, img.size, sectorsize):
        for physical in _span_hits(img, first, end, fsid, sectorsize):
            yield physical, region


def _record(
    img: ImageHandle, physical: int, region: Region, ctx: NodeContext, chunk_map: ChunkMap
) -> NodeRecord:
    available = min(ctx.nodesize, img.size - physical)
    header = None
    if available >= ondisk.HEADER.size:
        header = ondisk.HEADER.unpack_from(img.mmap, physical)
    mapped = here = False
    if header is not None:
        try:
            copies = chunk_map.copies(header["bytenr"], ctx.nodesize)
        except MappingError:
            pass
        else:
            mapped = True
            here = any(c.physical == physical and not c.missing_device for c in copies)
    if available < ctx.nodesize:
        checks, valid = (), False
        problems = (f"truncated: {available} of {ctx.nodesize} bytes before the image end",)
    else:
        block = img.mmap[physical : physical + ctx.nodesize]
        checks = check_block(block, ctx, None, NO_EXPECTATIONS)
        valid, problems = all(c.ok is not False for c in checks), ()
    fields = header or dict.fromkeys(("bytenr", "generation", "owner", "level", "nritems"))
    return NodeRecord(
        physical=physical,
        bytenr=fields["bytenr"],
        generation=fields["generation"],
        owner=fields["owner"],
        level=fields["level"],
        nritems=fields["nritems"],
        checks=checks,
        valid=valid,
        bytenr_mapped=mapped,
        maps_here=here,
        region=region,
        problems=problems,
    )


def _scan_piece(job) -> list[NodeRecord]:
    path, first, end, region, ctx, chunk_map = job
    with open_image(path) as img:
        return [
            _record(img, physical, region, ctx, chunk_map)
            for physical in _span_hits(img, first, end, ctx.fsid, ctx.sectorsize)
        ]


def iter_candidate_nodes(
    img: ImageHandle,
    regions: Iterable[Region],
    ctx: NodeContext,
    chunk_map: ChunkMap,
    *,
    workers: int = 1,
    piece: int = PIECE,
) -> Iterator[NodeRecord]:
    """Every candidate node in `regions`, in physical order; see the module docstring."""
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}, not {workers}")
    step = ctx.sectorsize
    spans = list(_spans(regions, img.size, step))
    if workers == 1:
        for first, end, region in spans:
            for physical in _span_hits(img, first, end, ctx.fsid, step):
                yield _record(img, physical, region, ctx, chunk_map)
        return
    piece = max(step, piece // step * step)
    jobs = [
        (img.path, start, min(start + piece, end), region, ctx, chunk_map)
        for first, end, region in spans
        for start in range(first, end, piece)
    ]
    pool = ProcessPoolExecutor(max_workers=workers)
    try:
        for records in pool.map(_scan_piece, jobs):
            yield from records
    finally:
        pool.shutdown(cancel_futures=True)
