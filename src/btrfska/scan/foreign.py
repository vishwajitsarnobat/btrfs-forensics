"""Foreign-FSID discovery: tree blocks of another filesystem on the same device (plan.md M6f).

The scan prefilter (kernel_numpy.py) keeps only offsets whose header carries the tree fsid, so the
tree blocks of a filesystem that was on the device before a reformat, and those this filesystem
wrote before its fsid was changed, are never candidates. `foreign_scan` finds them:
1. census: every 4096-byte aligned offset of the scanned regions whose bytes look like a tree
   block header is counted under its header fsid. A header looks like one when its flags have
   BTRFS_HEADER_FLAG_WRITTEN set and no other bit than WRITTEN and RELOC below the backref
   revision (btrfs_tree.h:765-766), the backref revision is BTRFS_OLD_BACKREF_REV or
   BTRFS_MIXED_BACKREF_REV (l.812-817), the level is below BTRFS_MAX_LEVEL, and bytenr and
   generation are non-zero, bytenr a multiple of 4096. The alignment is the smallest sectorsize,
   not the current one, so a filesystem of a smaller sectorsize is not missed;
2. selection: an fsid that is neither the tree fsid nor the superblock fsid and has at least
   MIN_BLOCKS header-shaped offsets, at most MAX_FOREIGN of them, the most frequent first; and
   the tree fsid of every valid foreign superblock copy (M1, `superblock.Selection.foreign`);
3. context: the geometry of that fsid's foreign superblock copy when one survives, else the
   (nodesize, csum type) under which most of its first SAMPLE blocks pass their checksum, the
   current filesystem's pair tried first. Without a superblock the generation is unknown and its
   check is recorded as not made (ok None);
4. validation: every offset whose header carries that fsid (the M2 prefilter with that fsid) is
   checked with `node.check_block` in that context, without expectations, as `scan` does;
5. identity: the device uuids that the fsid's valid chunk-tree leaves name (DEV_ITEMs and
   CHUNK_ITEM stripes) and its foreign superblock's dev_item. The current device uuid among them
   is the same device under a new fsid, `fsid_change`: `btrfstune -u` rewrites the fsid of every
   DEV_ITEM but keeps its uuid (btrfs-progs v6.6.3 tune/change-uuid.c:145-197), and leaves the
   blocks that the extent tree no longer lists under the old fsid (l.84-143). Only other device
   uuids are a new mkfs, `reformat`. None is `undetermined`.
An fsid change made through metadata_uuid (`btrfstune -m`) rewrites no header, so it leaves no
foreign block; it is read from the current superblock instead (METADATA_UUID set and fsid !=
metadata_uuid).

Memory and time are bounded whatever the image holds. The census is a mergeable Misra-Gries
summary (Agarwal et al., "Mergeable summaries", 2012) of at most CENSUS_SLOTS fsids: when a window
adds more, the (CENSUS_SLOTS + 1)-th largest count is taken from every count and the fsids left
at zero are dropped. Any fsid with more than 1 / (CENSUS_SLOTS + 1) of the header-shaped offsets
survives, and `undercount` is the most any count may lack. Validation records stream through
`emit`; only counters are kept, and the per-fsid tables (owners, device uuids) are capped. Each
offset carries one fsid, so the validation passes together check at most one block per offset
probed, as `scan` does.
"""

import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

import numpy as np

from btrfska.scan.kernel_numpy import WINDOW, _spans, iter_prefilter_hits
from btrfska.scan.regions import Region
from btrfska.substrate import csum, ondisk, superblock
from btrfska.substrate.chunks import parse_chunk
from btrfska.substrate.fs import Filesystem
from btrfska.substrate.image import ImageHandle
from btrfska.substrate.node import NO_EXPECTATIONS, Check, NodeContext, check_block, parse_items

STEP = ondisk.MIN_BLOCKSIZE  # census and validation alignment
CENSUS_SLOTS = 1024  # fsids the census holds at most
MIN_BLOCKS = 2  # header-shaped offsets that make an fsid recurring
MAX_FOREIGN = 8  # census fsids examined at most
SAMPLE = 32  # blocks per fsid tried when the geometry is inferred
OWNER_SLOTS = 32  # distinct owners counted per fsid; the rest are counted together
UUID_SLOTS = 16  # distinct device uuids kept per fsid
NODESIZES = tuple(1 << shift for shift in range(12, 17))  # 4 KiB to 64 KiB
UNKNOWN_GENERATION = (1 << 64) - 1  # no superblock: every generation passes, and is unchecked

_H = ondisk.HEADER
_FSID, _BYTENR, _FLAGS = _H.offset("fsid"), _H.offset("bytenr"), _H.offset("flags")
_GENERATION, _LEVEL = _H.offset("generation"), _H.offset("level")
_REV_SHIFT = 56  # BTRFS_BACKREF_REV_SHIFT, btrfs_tree.h:812
_LOW_FLAGS = (1 << _REV_SHIFT) - 1
_ALLOWED = ondisk.HEADER_FLAG_WRITTEN | ondisk.HEADER_FLAG_RELOC
KINDS = ("reformat", "fsid_change", "undetermined")
SOURCES = ("superblock", "inferred", "none")


def _text(raw: bytes) -> str:
    return str(uuid.UUID(bytes=raw))


@dataclass(frozen=True)
class Census:
    header_shaped: int  # offsets whose bytes look like a tree-block header
    counts: dict[bytes, int]  # fsid -> header-shaped offsets, a lower bound (see `undercount`)
    undercount: int  # the most any count may lack


def _view(buffer, base: int, count: int, offset: int, dtype: str) -> np.ndarray:
    return np.ndarray((count,), dtype, buffer, base + offset, (STEP,))


def _window_census(buffer, base: int, count: int) -> tuple[np.ndarray, np.ndarray]:
    """The fsid words of every header-shaped offset base + i * STEP (i < count)."""
    flags = _view(buffer, base, count, _FLAGS, "<u8")
    bytenr = _view(buffer, base, count, _BYTENR, "<u8")
    first = _view(buffer, base, count, _FSID, "<u8")
    second = _view(buffer, base, count, _FSID + 8, "<u8")
    shaped = (
        (flags & ondisk.HEADER_FLAG_WRITTEN).astype(bool)
        & (flags & _LOW_FLAGS & ~np.uint64(_ALLOWED) == 0)
        & (flags >> np.uint64(_REV_SHIFT) <= 1)
        & (_view(buffer, base, count, _LEVEL, "u1") < ondisk.MAX_LEVEL)
        & (bytenr != 0)
        & (bytenr % np.uint64(STEP) == 0)
        & (_view(buffer, base, count, _GENERATION, "<u8") != 0)
        & ((first | second) != 0)
    )
    hits = np.flatnonzero(shaped)
    return first[hits], second[hits]


def _reduce(counts: dict[bytes, int]) -> int:
    """Shrink `counts` to at most CENSUS_SLOTS fsids (Misra-Gries); returns what was taken."""
    if len(counts) <= CENSUS_SLOTS:
        return 0
    cut = sorted(counts.values(), reverse=True)[CENSUS_SLOTS]
    for fsid in list(counts):
        counts[fsid] -= cut
        if counts[fsid] <= 0:
            del counts[fsid]
    return cut


def census(img: ImageHandle, regions: Iterable[Region]) -> Census:
    """Header-shaped offsets per fsid across `regions`, in bounded memory."""
    counts, shaped, undercount = {}, 0, 0
    last = img.size - _H.size  # the whole header must lie inside the image
    for first, end, _ in _spans(regions, img.size, STEP):
        total = min(-(-(end - first) // STEP), (last - first) // STEP + 1)
        for index in range(0, max(total, 0), WINDOW):
            base = first + index * STEP
            words = np.stack(_window_census(img.mmap, base, min(WINDOW, total - index)), axis=1)
            if not len(words):
                continue
            shaped += len(words)
            unique, found = np.unique(words, axis=0, return_counts=True)
            for (a, b), n in zip(unique.tolist(), found.tolist(), strict=True):
                key = a.to_bytes(8, "little") + b.to_bytes(8, "little")
                counts[key] = counts.get(key, 0) + n
            undercount += _reduce(counts)
    return Census(shaped, counts, undercount)


@dataclass(frozen=True)
class ForeignRecord:
    """One block whose header carries a foreign fsid, validated in that fsid's context."""

    fsid: bytes
    physical: int
    bytenr: int | None  # None: the header is cut by the image end
    generation: int | None
    owner: int | None
    level: int | None
    nritems: int | None
    checks: tuple[Check, ...]  # empty when the block is truncated
    valid: bool
    region: Region
    problems: tuple[str, ...] = ()


@dataclass(frozen=True)
class Context:
    ctx: NodeContext
    source: str  # one of SOURCES
    mirror: int | None = None  # the foreign superblock copy it comes from
    sampled: int = 0  # blocks tried when inferred
    verified: int = 0  # of those, how many passed their checksum under the pair chosen


def infer_context(img: ImageHandle, fsid: bytes, regions, current: NodeContext) -> Context:
    """The (nodesize, csum type) under which most of the first SAMPLE blocks of `fsid` verify."""
    sample = []
    for physical, _ in iter_prefilter_hits(img, regions, fsid, STEP):
        sample.append(physical)
        if len(sample) == SAMPLE:
            break
    pairs = [(current.nodesize, current.csum_type)] + [
        (n, c) for n in NODESIZES for c in sorted(ondisk.CSUM_TYPES)
    ]
    best, verified = None, 0
    for nodesize, csum_type in dict.fromkeys(pairs):
        ok = sum(
            csum.block_csum_ok(csum_type, img.mmap[p : p + nodesize])
            for p in sample
            if p + nodesize <= img.size
        )
        if ok > verified:
            best, verified = (nodesize, csum_type), ok
    base = replace(current, fsid=fsid, generation=UNKNOWN_GENERATION, chunk_tree_uuid=None)
    if best is None:
        return Context(base, "none", sampled=len(sample))
    nodesize, csum_type = best
    sectorsize = min(current.sectorsize, nodesize)
    ctx = replace(base, nodesize=nodesize, csum_type=csum_type, sectorsize=sectorsize)
    return Context(ctx, "inferred", sampled=len(sample), verified=verified)


def _superblock_context(copies: list[superblock.SuperblockCopy]) -> Context:
    copy = max(copies, key=lambda c: (c.fields["generation"], -c.mirror))
    return Context(NodeContext.from_superblock(copy.fields), "superblock", copy.mirror)


def _record(img: ImageHandle, physical: int, region: Region, context: Context) -> ForeignRecord:
    ctx = context.ctx
    available = min(ctx.nodesize, img.size - physical)
    header = _H.unpack_from(img.mmap, physical) if available >= _H.size else None
    fields = header or dict.fromkeys(("bytenr", "generation", "owner", "level", "nritems"))
    if available < ctx.nodesize:
        checks, valid = (), False
        problems = (f"truncated: {available} of {ctx.nodesize} bytes before the image end",)
    else:
        checks = check_block(img.mmap[physical : physical + ctx.nodesize], ctx, None,
                             NO_EXPECTATIONS)  # fmt: skip
        if context.source != "superblock":
            checks = tuple(
                Check("generation", None) if c.name == "generation" else c for c in checks
            )
        valid, problems = all(c.ok is not False for c in checks), ()
    return ForeignRecord(
        fsid=ctx.fsid,
        physical=physical,
        bytenr=fields["bytenr"],
        generation=fields["generation"],
        owner=fields["owner"],
        level=fields["level"],
        nritems=fields["nritems"],
        checks=checks,
        valid=valid,
        region=region,
        problems=problems,
    )


def device_uuids(block, ctx: NodeContext) -> list[bytes]:
    """Device uuids named by a chunk-tree leaf: DEV_ITEM uuids and CHUNK_ITEM stripe dev_uuids.

    Never raises on content (items that do not fit or do not parse are skipped).
    """
    found = []
    items, _ = parse_items(block, ctx.nodesize)
    for item in items:
        if item.key.type == ondisk.ITEM_KEYS["DEV_ITEM"] and item.size >= ondisk.DEV_ITEM.size:
            found.append(ondisk.DEV_ITEM.unpack_from(item.data)["uuid"])
        elif item.key.type == ondisk.ITEM_KEYS["CHUNK_ITEM"]:
            chunk = parse_chunk(item.key.offset, item.data, sectorsize=ctx.sectorsize)
            found += [stripe.dev_uuid for stripe in chunk.stripes]
    return found


class _Tally:
    """Running counters for one foreign fsid: memory does not grow with its blocks."""

    def __init__(self) -> None:
        self.candidates = self.valid = self.truncated = self.owners_more = 0
        self.uuids_more = self.in_current_map = 0
        self.generations: list[int] = []  # [min, max] of the valid blocks
        self.levels: dict[int, int] = {}
        self.owners: dict[int, int] = {}
        self.uuids: dict[bytes, int] = {}
        self.regions: dict[str, int] = {}

    def add(self, record: ForeignRecord, uuids: Iterable[bytes] = ()) -> None:
        self.candidates += 1
        self.truncated += not record.checks
        if not record.valid:
            return
        self.valid += 1
        gen = record.generation
        self.generations = [min(self.generations[0], gen), max(self.generations[1], gen)] if (
            self.generations
        ) else [gen, gen]  # fmt: skip
        self.levels[record.level] = self.levels.get(record.level, 0) + 1
        if record.owner in self.owners or len(self.owners) < OWNER_SLOTS:
            self.owners[record.owner] = self.owners.get(record.owner, 0) + 1
        else:
            self.owners_more += 1
        kind = record.region.kind
        self.regions[kind] = self.regions.get(kind, 0) + 1
        self.in_current_map += record.region.chunk is not None
        for found in uuids:
            if found in self.uuids or len(self.uuids) < UUID_SLOTS:
                self.uuids[found] = self.uuids.get(found, 0) + 1
            else:
                self.uuids_more += 1


def _identity(
    uuids: dict[bytes, int],
    sb_copies: list[superblock.SuperblockCopy],
    current: bytes,
    newest: int | None,
    generation: int,
) -> tuple[str, list[str]]:
    """`kind` and its evidence: the device uuids the foreign metadata names, and its newest
    generation (`newest`) against the current superblock's (`generation`)."""
    evidence, seen = [], set(uuids)
    for copy in sb_copies:
        dev = ondisk.DEV_ITEM.unpack_from(copy.fields["dev_item"])["uuid"]
        seen.add(dev)
        evidence.append(f"superblock mirror {copy.mirror} names device uuid {_text(dev)}")
    for dev, count in sorted(uuids.items(), key=lambda kv: (-kv[1], kv[0])):
        evidence.append(f"{count} chunk-tree items name device uuid {_text(dev)}")
    if seen:
        among = "is" if current in seen else "is not"
        evidence.append(f"the current device uuid {_text(current)} {among} among them")
    # btrfstune -u leaves the generation alone, so blocks written before an fsid change are never
    # newer than the filesystem that carries on under the new fsid.
    newer = newest is not None and newest > generation
    if newer:
        evidence.append(
            f"the newest foreign generation {newest} is above the current superblock generation "
            f"{generation}: not this filesystem before an fsid change"
        )
    if current in seen:
        return ("undetermined" if newer else "fsid_change"), evidence
    if seen or newer:
        return "reformat", evidence
    evidence.append(
        "no foreign chunk-tree leaf or superblock names a device uuid, and no foreign generation "
        f"is above the current {generation}"
    )
    return "undetermined", evidence


def _context_dict(context: Context) -> dict:
    ctx = context.ctx
    return {
        "source": context.source,
        "mirror": context.mirror,
        "nodesize": ctx.nodesize,
        "sectorsize": ctx.sectorsize,
        "csum_type": ctx.csum_type,
        "csum_name": csum.csum_name(ctx.csum_type),
        "generation": None if context.source != "superblock" else ctx.generation,
        "sampled": context.sampled,
        "verified": context.verified,
    }


def _superblock_dict(copy: superblock.SuperblockCopy) -> dict:
    fields = copy.fields
    return {
        "mirror": copy.mirror,
        "offset": copy.offset,
        "generation": fields["generation"],
        "fsid": _text(fields["fsid"]),
        "tree_fsid": _text(superblock.tree_fsid(fields)),
    }


def _examine(
    img: ImageHandle,
    fs: Filesystem,
    regions,
    fsid: bytes,
    blocks: int,
    sb_copies: list[superblock.SuperblockCopy],
    emit: Callable[[ForeignRecord], None] | None,
) -> dict:
    current = fs.reader.ctx
    context = (
        _superblock_context(sb_copies) if sb_copies else infer_context(img, fsid, regions, current)
    )
    ctx, tally = context.ctx, _Tally()
    for physical, region in iter_prefilter_hits(img, regions, fsid, STEP):
        record = _record(img, physical, region, context)
        uuids = ()
        if record.valid and record.owner == ondisk.CHUNK_TREE_OBJECTID and record.level == 0:
            uuids = device_uuids(img.mmap[physical : physical + ctx.nodesize], ctx)
        tally.add(record, uuids)
        if emit is not None:
            emit(record)
    current_dev = ondisk.DEV_ITEM.unpack_from(fs.fields["dev_item"])["uuid"]
    newest = max(
        [*tally.generations[1:], *(c.fields["generation"] for c in sb_copies)], default=None
    )
    kind, evidence = _identity(tally.uuids, sb_copies, current_dev, newest, fs.fields["generation"])
    return {
        "fsid": _text(fsid),
        "census_blocks": blocks,
        "kind": kind,
        "evidence": evidence,
        "context": _context_dict(context),
        "superblocks": [_superblock_dict(c) for c in sb_copies],
        "candidates": tally.candidates,
        "valid": tally.valid,
        "invalid": tally.candidates - tally.valid,
        "truncated": tally.truncated,
        "generations": tally.generations or None,
        "levels": {str(k): v for k, v in sorted(tally.levels.items())},
        "owners": {str(k): v for k, v in sorted(tally.owners.items())},
        "owners_more": tally.owners_more,
        "device_uuids": {_text(k): v for k, v in sorted(tally.uuids.items())},
        "device_uuids_more": tally.uuids_more,
        "in_current_map": tally.in_current_map,
        "region_kinds": dict(sorted(tally.regions.items())),
    }


def metadata_uuid_change(fields: dict) -> dict | None:
    """An fsid change through metadata_uuid: METADATA_UUID set and fsid != metadata_uuid."""
    if not fields["incompat_flags"] & ondisk.INCOMPAT["METADATA_UUID"]:
        return None
    if fields["fsid"] == fields["metadata_uuid"]:
        return None
    return {"fsid": _text(fields["fsid"]), "metadata_uuid": _text(fields["metadata_uuid"])}


def foreign_scan(
    img: ImageHandle,
    fs: Filesystem,
    regions: Iterable[Region],
    emit: Callable[[ForeignRecord], None] | None = None,
) -> dict:
    """Find, validate and identify the foreign fsids in `regions`; see the module docstring.

    Every validated block goes to `emit` (in physical order per fsid, fsids in report order); the
    return value is the JSON-ready summary. Never raises on content.
    """
    regions = tuple(regions)
    current = fs.reader.ctx
    excluded = {current.fsid, fs.fields["fsid"]}
    found = census(img, regions)
    ranked = sorted(
        ((n, fsid) for fsid, n in found.counts.items() if fsid not in excluded and n >= MIN_BLOCKS),
        key=lambda pair: (-pair[0], pair[1]),
    )
    chosen = {fsid: n for n, fsid in ranked[:MAX_FOREIGN]}
    by_fsid: dict[bytes, list[superblock.SuperblockCopy]] = {}
    for copy in fs.selection.foreign:
        tree = superblock.tree_fsid(copy.fields)
        if tree not in excluded:
            by_fsid.setdefault(tree, []).append(copy)
    for tree in by_fsid:
        chosen.setdefault(tree, found.counts.get(tree, 0))
    filesystems = [
        _examine(img, fs, regions, fsid, n, by_fsid.get(fsid, []), emit)
        for fsid, n in chosen.items()
    ]
    return {
        "alignment": STEP,
        "header_shaped": found.header_shaped,
        "fsids_held": len(found.counts),
        "undercount": found.undercount,
        "current_blocks": found.counts.get(current.fsid, 0),
        "recurring": len(ranked),
        "left_out": max(0, len(ranked) - MAX_FOREIGN),
        "filesystems": filesystems,
        "metadata_uuid_change": metadata_uuid_change(fs.fields),
    }


def report_lines(summary: dict) -> list[str]:
    """The text lines `scan --foreign` prints and `catalog build --foreign` stores as problems."""
    lines = [
        f"foreign: census of {summary['header_shaped']} header-shaped offsets at "
        f"{summary['alignment']}-byte alignment, {summary['fsids_held']} fsids held "
        f"(undercount at most {summary['undercount']}); {summary['recurring']} recurring foreign "
        f"fsids, {summary['left_out']} left out"
    ]
    for f in summary["filesystems"]:
        c = f["context"]
        origin = f"superblock mirror {c['mirror']}" if c["source"] == "superblock" else (
            f"{c['source']}, {c['verified']} of {c['sampled']} sampled blocks verify"
        )  # fmt: skip
        gens = f["generations"]
        lines.append(
            f"foreign filesystem {f['fsid']}: {f['kind']}; nodesize {c['nodesize']}, "
            f"{c['csum_name']} ({origin}); candidates {f['candidates']} (valid {f['valid']}, "
            f"invalid {f['invalid']}); generations " + (f"{gens[0]}-{gens[1]}" if gens else "none")
        )
        lines += [f"  evidence: {line}" for line in f["evidence"]]
    if (change := summary["metadata_uuid_change"]) is not None:
        lines.append(
            f"foreign: fsid changed through metadata_uuid: superblock fsid {change['fsid']}, "
            f"tree blocks carry {change['metadata_uuid']}"
        )
    if not summary["filesystems"] and change is None:
        lines.append("foreign: no foreign filesystem found")
    return lines
