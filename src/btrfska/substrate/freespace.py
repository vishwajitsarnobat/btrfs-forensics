"""Free space: the free space tree's items, the allocation of one state, and the overwrite risk of
the bytes a recovery read (plan.md M6b). Kernel citations are to v7.0.

The free space tree (tree 10) has three item types (btrfs_tree.h:261-280, :1243-1248):
- FREE_SPACE_INFO (198), key (block group start, 198, length): `extent_count`, `flags`; flag
  USING_BITMAPS (1 << 0) says that the block group's free space is held in bitmaps;
- FREE_SPACE_EXTENT (199), key (start, 199, length), no payload: one free extent;
- FREE_SPACE_BITMAP (200), key (start, 200, length): one bit per sector of the range, least
  significant bit first (free-space-tree.c:152-156 sizes it, :176-195 sets bits, :510-530 tests
  one); a set bit is a free sector.
A block group's entries follow its INFO item in key order. The kernel loads them by the INFO flag
(free-space-tree.c:1673-1710): extents one by one (:1616-1671), bitmaps as runs of set bits that
carry over from one bitmap item to the next (:1536-1614), and fails the load with -EIO when the
number of free extents it counted differs from `extent_count` (:1603-1611, :1660-1668).

`FreeSpaceTree` reads those items. There is no tree-checker rule for them; the kernel only
ASSERTs that an entry lies in its block group (free-space-tree.c:1568, :1646). Hostile items are
skipped and reported: an INFO item that is not 8 bytes, is empty, passes 2^64 or overlaps the one
before it; an entry before any INFO item or outside its block group; an entry whose start or
length is zero or not a multiple of the sector size; a bitmap whose size is not
ceil(length / sectorsize / 8) bytes (so that nothing is ever allocated from what a key claims); an
entry of the kind the INFO flag does not name. Free ranges that overlap are merged and reported. A
block group whose count of free extents differs from `extent_count` is marked inconsistent.

`ExtentTree` reads the items free space can be derived from when there is no free space tree:
EXTENT_ITEM (168, key (start, 168, length)), METADATA_ITEM (169, key (start, 169, level), one
node long) and BLOCK_GROUP_ITEM (192, key (start, 192, length): used, chunk, flags). A block group
minus its extents minus the superblock stripes the kernel excludes (block-group.c:2277-2330) is
free. The kernel changes both in the same commit (extent-tree.c:3187 adds a freed extent to the
free space tree, :4973 removes an allocated one), so `SpaceView.cross_check` compares them where
both exist.

`SpaceView` is one state's allocation, `place` puts a range into it, `Placement` is the verdict on
one extent or tree block, and `overwrite_risk` scores it (plan.md M6b, decision 5).
"""

import bisect
from collections.abc import Iterable
from dataclasses import dataclass, field

from btrfska.substrate import items, ondisk
from btrfska.substrate.chunks import STRIPE_LEN, ChunkMap, type_name
from btrfska.substrate.node import Item

K = ondisk.ITEM_KEYS
BG = ondisk.BLOCK_GROUP_FLAGS
USING_BITMAPS = 1 << 0  # btrfs_free_space_info.flags (btrfs_tree.h:1248)
INFO_SIZE = ondisk.FREE_SPACE_INFO.size  # sizeof(struct btrfs_free_space_info), 8
MAX_PROBLEMS = 16  # findings kept per tree; the rest are counted
# The kernel's default reclaim threshold, in percent of a block group, set for zoned filesystems
# only (zoned.h:29, applied in space-info.c:254-255); on any other filesystem it is 0, reclaim is
# off, and only sysfs, which is not on disk, turns it on (space-info.c:2077-2084).
ZONED_RECLAIM_PERCENT = 75

VERDICTS = ("in_use", "free", "allocated", "partial", "no_block_group")
LEVELS = ("none", "low", "medium", "high", "reallocated")  # the score is the index
# The observed discard modes, and which block groups each says are trimmed: every kind (only
# discard=sync or a FITRIM discards metadata block groups; async tracks data-only block groups,
# discard.c:116, :696) or data-only block groups.
DISCARD_SCOPE = {
    "sync": "all", "async": "data", "none": None,
    "trimmed_metadata": "all", "trimmed_data": "data", "not_trimmed": None, "unknown": None,
}  # fmt: skip


class Ranges:
    """Disjoint [start, end) ranges, merged from what was added; `overlap` counts the bytes added
    more than once."""

    def __init__(self, pairs: Iterable[tuple[int, int]] = ()) -> None:
        merged: list[list[int]] = []
        self.overlap = 0
        for start, end in sorted((s, e) for s, e in pairs if s < e):
            if merged and start <= merged[-1][1]:
                self.overlap += max(0, min(end, merged[-1][1]) - start)
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self.pairs = [(s, e) for s, e in merged]
        self._starts = [s for s, _ in self.pairs]

    def __len__(self) -> int:
        return len(self.pairs)

    def total(self) -> int:
        return sum(e - s for s, e in self.pairs)

    def covered(self, start: int, end: int) -> int:
        """Bytes of [start, end) the ranges hold."""
        found = 0
        at = max(bisect.bisect_right(self._starts, start) - 1, 0)
        for s, e in self.pairs[at:]:
            if s >= end:
                break
            found += max(0, min(e, end) - max(s, start))
        return found

    def within(self, start: int, end: int) -> list[tuple[int, int]]:
        """The ranges clipped to [start, end)."""
        at = max(bisect.bisect_right(self._starts, start) - 1, 0)
        found = []
        for s, e in self.pairs[at:]:
            if s >= end:
                break
            if e > start:
                found.append((max(s, start), min(e, end)))
        return found


def subtract(start: int, end: int, taken: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """[start, end) without the sorted, disjoint `taken` ranges."""
    found, at = [], start
    for s, e in taken:
        if s > at:
            found.append((at, min(s, end)))
        at = max(at, e)
        if at >= end:
            break
    if at < end:
        found.append((at, end))
    return [(s, e) for s, e in found if s < e]


@dataclass
class BlockGroup:
    """One block group: from a BLOCK_GROUP_ITEM (flags and used known) or a FREE_SPACE_INFO."""

    start: int
    length: int
    flags: int | None = None
    used: int | None = None

    @property
    def end(self) -> int:
        return self.start + self.length

    @property
    def data_only(self) -> bool | None:
        """btrfs_is_block_group_data_only (block-group.h:301-309); None when flags are unknown."""
        if self.flags is None:
            return None
        return bool(self.flags & BG["DATA"]) and not self.flags & BG["METADATA"]

    def record(self) -> dict:
        return {
            "start": self.start, "length": self.length,
            "type": None if self.flags is None else type_name(self.flags), "used": self.used,
        }  # fmt: skip


class _Findings:
    def __init__(self, source: str) -> None:
        self.source = source
        self.problems: list[str] = []
        self.skipped = 0

    def _problem(self, text: str) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(text)
        else:
            self.skipped += 1

    def notes(self) -> list[str]:
        found = list(self.problems)
        if self.skipped:
            found.append(f"and {self.skipped} more findings")
        return found


@dataclass
class _Info:
    start: int
    length: int
    flags: int
    extent_count: int
    counted: int = 0  # free extents counted as the kernel counts them
    last_bit_end: int | None = None  # where the last bitmap item ended
    open_run: bool = False  # the last bitmap item ended on a set bit: the run carries over

    @property
    def end(self) -> int:
        return self.start + self.length


class FreeSpaceTree(_Findings):
    """The free space one free space tree records. Call `add` for every item in key order, then
    read `free` (a `Ranges`), `block_groups` and `inconsistent`. `complete` is False when the tree
    was not read without a gap."""

    def __init__(self, source: str, sectorsize: int, *, complete: bool = True) -> None:
        super().__init__(source)
        self.sectorsize, self.complete = sectorsize, complete
        self.infos: list[_Info] = []
        self._pairs: list[tuple[int, int]] = []
        self._free: Ranges | None = None
        self._inconsistent: list[int] = []  # block group starts whose extent count is wrong
        self.items = 0

    def add(self, item: Item, where: str = "") -> None:
        key = item.key
        if key.type not in (K["FREE_SPACE_INFO"], K["FREE_SPACE_EXTENT"], K["FREE_SPACE_BITMAP"]):
            return
        self._free = None
        at = f"key ({key.objectid}, {key.type}, {key.offset})" + (f" ({where})" if where else "")
        start, length = key.objectid, key.offset
        if key.type == K["FREE_SPACE_INFO"]:
            if len(item.data) != INFO_SIZE:
                self._problem(f"FREE_SPACE_INFO {at}: size {len(item.data)}, not {INFO_SIZE}")
                return
            if length == 0 or start + length > 1 << 64:
                self._problem(f"FREE_SPACE_INFO {at}: an empty range or one past 2^64")
                return
            if self.infos and start < self.infos[-1].end:
                self._problem(f"FREE_SPACE_INFO {at}: overlaps the block group before it")
                return
            self._close()
            fields = ondisk.FREE_SPACE_INFO.unpack_from(bytes(item.data))
            self.infos.append(_Info(start, length, fields["flags"], fields["extent_count"]))
            self.items += 1
            return
        bitmap = key.type == K["FREE_SPACE_BITMAP"]
        name = "FREE_SPACE_BITMAP" if bitmap else "FREE_SPACE_EXTENT"
        info = self.infos[-1] if self.infos else None
        if length == 0 or start % self.sectorsize or length % self.sectorsize:
            self._problem(f"{name} {at}: zero, or not aligned to the sector size")
            return
        if info is None or not info.start <= start or start + length > info.end:
            self._problem(f"{name} {at}: not inside the block group of the INFO item before it")
            return
        if bool(info.flags & USING_BITMAPS) != bitmap:
            self._problem(
                f"{name} {at}: the block group's INFO item says "
                f"{'bitmaps' if info.flags & USING_BITMAPS else 'extents'}"
            )
            return
        if not bitmap:
            self._pairs.append((start, start + length))
            info.counted += 1
            self.items += 1
            return
        bits = length // self.sectorsize
        want = (bits + 7) // 8  # free_space_bitmap_size (free-space-tree.c:152-156)
        data = bytes(item.data)
        if len(data) != want:
            self._problem(f"{name} {at}: {len(data)} bytes, not {want} for {bits} sectors")
            return
        self.items += 1
        if info.last_bit_end is not None and info.last_bit_end != start:
            self._problem(f"{name} {at}: does not continue the bitmap before it")
        # Runs of set bits are free extents; the kernel counts a run that is open at the end of
        # one bitmap item and continues in the next once (free-space-tree.c:1576-1597).
        run, carried, step = None, info.open_run, self.sectorsize
        for index in range(bits):
            byte = data[index >> 3]
            if byte >> (index & 7) & 1:
                if run is None:
                    run = start + index * step
                if not carried:
                    info.counted += 1
                    carried = True
            else:
                if run is not None:
                    self._pairs.append((run, start + index * step))
                    run = None
                carried = False
        if run is not None:
            self._pairs.append((run, start + length))
        info.open_run = carried
        info.last_bit_end = start + length

    def _close(self) -> None:
        if self.infos:
            info = self.infos[-1]
            if info.counted != info.extent_count and info.start not in self._inconsistent:
                self._inconsistent.append(info.start)
                self._problem(
                    f"block group {info.start}: {info.counted} free extents, but its "
                    f"FREE_SPACE_INFO says {info.extent_count} (the kernel fails the load)"
                )

    @property
    def free(self) -> Ranges:
        if self._free is None:
            self._close()
            self._free = Ranges(self._pairs)
            if self._free.overlap:
                self._problem(f"free ranges overlap by {self._free.overlap} bytes; merged")
        return self._free

    @property
    def inconsistent(self) -> list[int]:
        """The block groups whose count of free extents is not their INFO item's."""
        self.free  # noqa: B018 - checks the last block group
        return self._inconsistent

    def block_groups(self) -> list[BlockGroup]:
        return [BlockGroup(info.start, info.length) for info in self.infos]


class ExtentTree(_Findings):
    """The extents and block groups of one extent tree (with tree 11 for the block groups when
    the filesystem has BLOCK_GROUP_TREE). Call `add` for every item."""

    def __init__(self, source: str, nodesize: int, *, complete: bool = True) -> None:
        super().__init__(source)
        self.nodesize, self.complete = nodesize, complete
        self.extents: dict[int, tuple[int, int | None, bool]] = {}  # start -> length, gen, tree
        self.groups: dict[int, BlockGroup] = {}
        self.data_refs: dict[int, set[int]] = {}  # start -> inode numbers of EXTENT_DATA_REFs
        self.shared_refs: dict[int, set[int]] = {}  # start -> parent leaves of SHARED_DATA_REFs
        self._pairs: list[tuple[int, int]] = []
        self._allocated: Ranges | None = None
        self.items = 0

    def _ref(self, start: int, ref: dict) -> None:
        if ref["type"] == K["EXTENT_DATA_REF"]:
            self.data_refs.setdefault(start, set()).add(ref["objectid"])
        elif ref["type"] == K["SHARED_DATA_REF"]:
            self.shared_refs.setdefault(start, set()).add(ref["parent"])

    def add(self, item: Item, where: str = "") -> None:
        key, data = item.key, bytes(item.data)
        at = f"key ({key.objectid}, {key.type}, {key.offset})" + (f" ({where})" if where else "")
        if key.type == K["BLOCK_GROUP_ITEM"]:
            if len(data) < ondisk.BLOCK_GROUP_ITEM.size or not key.offset:
                self._problem(f"BLOCK_GROUP_ITEM {at}: {len(data)} bytes or an empty range")
                return
            if key.objectid + key.offset > 1 << 64:
                self._problem(f"BLOCK_GROUP_ITEM {at}: the range passes 2^64")
                return
            fields = ondisk.BLOCK_GROUP_ITEM.unpack_from(data)
            if key.objectid in self.groups:
                self._problem(f"BLOCK_GROUP_ITEM {at}: a second item for this block group")
                return
            self.groups[key.objectid] = BlockGroup(
                key.objectid, key.offset, fields["flags"], fields["used"]
            )
            self.items += 1
            return
        if key.type in (K["EXTENT_DATA_REF"], K["SHARED_DATA_REF"]):
            try:
                self._ref(key.objectid, items.extent_ref(key, data))
            except items.ItemError as exc:
                self._problem(f"back-reference {at}: {exc}")
            return
        if key.type == K["EXTENT_ITEM"]:
            length, tree_block = key.offset, None
        elif key.type == K["METADATA_ITEM"]:
            length, tree_block = self.nodesize, True
        else:
            return
        if key.type == K["EXTENT_ITEM"] and len(data) >= ondisk.EXTENT_ITEM.size:
            try:
                for ref in items.extent_item(key, data)["backrefs"]:
                    self._ref(key.objectid, ref)
            except items.ItemError as exc:
                self._problem(f"extent {at}: inline back-references: {exc}")
        if not length or key.objectid + length > 1 << 64:
            self._problem(f"extent {at}: an empty range or one past 2^64")
            return
        generation = None
        if len(data) >= ondisk.EXTENT_ITEM.size:
            fields = ondisk.EXTENT_ITEM.unpack_from(data)
            generation = fields["generation"]
            if tree_block is None:
                tree_block = bool(fields["flags"] & ondisk.EXTENT_FLAG_TREE_BLOCK)
        else:
            self._problem(f"extent {at}: {len(data)} bytes, no generation; kept as allocated")
        if key.objectid in self.extents:
            self._problem(f"extent {at}: a second extent item at this address")
        else:
            self.extents[key.objectid] = (length, generation, bool(tree_block))
        self._allocated = None
        self._pairs.append((key.objectid, key.objectid + length))
        self.items += 1

    @property
    def allocated(self) -> Ranges:
        if self._allocated is None:
            self._allocated = Ranges(self._pairs)
            if self._allocated.overlap:
                self._problem(f"extents overlap by {self._allocated.overlap} bytes")
        return self._allocated


def super_stripes(chunk_map: ChunkMap, groups: Iterable[BlockGroup], device_size: int):
    """The logical ranges the kernel keeps out of free space for the superblock copies
    (exclude_super_stripes, block-group.c:2277-2330): below BTRFS_SUPER_INFO_OFFSET, and one
    io stripe (64 KiB, block-group.c:2215) from the logical address of every superblock copy
    that lies on the device, clipped to its block group."""
    found = []
    ordered = sorted(groups, key=lambda g: g.start)
    starts = [g.start for g in ordered]
    for group in ordered:
        if group.start < ondisk.SUPER_INFO_OFFSET:
            found.append((group.start, ondisk.SUPER_INFO_OFFSET))
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        physical = ondisk.sb_offset(mirror)
        if physical >= device_size:
            continue
        mapped = chunk_map.logical_of(None, physical)
        if mapped is None:
            continue
        logical = mapped[0]
        at = bisect.bisect_right(starts, logical) - 1
        if at >= 0 and logical < ordered[at].end:
            found.append((logical, min(logical + STRIPE_LEN, ordered[at].end)))
    return found


@dataclass(frozen=True)
class Placement:
    """Where one extent or tree block lies in the current state's allocation, and how likely its
    bytes are to be overwritten. JSON-ready via asdict.

    `verdict` (VERDICTS): `in_use` (the same allocation is still in the current extent tree),
    `free`, `allocated` (every byte belongs to another extent now), `partial` (some bytes do),
    `no_block_group` (no current block group holds the bytes). `free_bytes`, `allocated_bytes`
    and `outside_bytes` add up to `length`. `block_groups` are the current ones it lies in.
    `freed_in`: {"after": GEN or None, "by": GEN}, from the free space trees of older states: the
    bytes were allocated in the state of generation `after` and wholly free in the state of
    generation `by`. `risk` is the index of `level` in LEVELS; `reasons` the rules that set it.
    """

    verdict: str
    source: str | None
    length: int
    free_bytes: int = 0
    allocated_bytes: int = 0
    outside_bytes: int = 0
    block_groups: tuple[dict, ...] = ()
    freed_in: dict | None = None
    risk: int = 0
    level: str = "none"
    reasons: tuple[str, ...] = ()


class SpaceView:
    """One state's allocation: its block groups, its free ranges and its extents.

    `source` is `free_space_tree` when `fst` is given (and trusted by the caller), else
    `extent_tree`, else None (nothing to place against). Block group flags and usage always come
    from the BLOCK_GROUP_ITEMs of `extents`.
    """

    def __init__(self, extents: ExtentTree | None, fst: FreeSpaceTree | None,
                 excluded: Iterable[tuple[int, int]] = ()) -> None:  # fmt: skip
        self.extents, self.fst = extents, fst
        self.excluded = Ranges(excluded)
        self.problems: list[str] = []
        groups = dict(extents.groups) if extents else {}
        if fst is not None:
            for info in fst.block_groups():
                if info.start not in groups:
                    groups[info.start] = info
                elif groups[info.start].length != info.length:
                    self.problems.append(
                        f"block group {info.start}: length {groups[info.start].length} in its "
                        f"BLOCK_GROUP_ITEM, {info.length} in its FREE_SPACE_INFO"
                    )
        self.groups = sorted(groups.values(), key=lambda g: g.start)
        self._starts = [g.start for g in self.groups]
        self.derived = self._derive() if extents is not None else None
        if fst is not None:
            # A new block group enters the tree free from end to end, superblock stripes included
            # (free-space-tree.c:1433-1434); the kernel leaves them out when it loads free space
            # (btrfs_add_new_free_space, block-group.c:530-570), and so does the view.
            self.source, self.complete = "free_space_tree", fst.complete
            self.free = Ranges(
                r for s, e in fst.free.pairs for r in subtract(s, e, self.excluded.within(s, e))
            )
        elif self.derived is not None:
            self.source, self.free = "extent_tree", self.derived
            self.complete = extents.complete
        else:
            self.source, self.free, self.complete = None, Ranges(), False

    def _derive(self) -> Ranges:
        """Free space from the extent tree: block groups minus extents minus superblock stripes."""
        free = []
        for group in self.groups:
            if group.flags is None:  # only the free space tree names it: nothing to derive from
                continue
            taken = Ranges(
                [*self.extents.allocated.within(group.start, group.end),
                 *self.excluded.within(group.start, group.end)]
            ).pairs  # fmt: skip
            free += subtract(group.start, group.end, taken)
        return Ranges(free)

    def groups_in(self, start: int, end: int) -> list[BlockGroup]:
        at = max(bisect.bisect_right(self._starts, start) - 1, 0)
        found = []
        for group in self.groups[at:]:
            if group.start >= end:
                break
            if group.end > start:
                found.append(group)
        return found

    def place(self, start: int, end: int) -> tuple[int, int, int]:
        """(free, allocated, outside any block group) bytes of [start, end)."""
        inside = sum(min(g.end, end) - max(g.start, start) for g in self.groups_in(start, end))
        free = self.free.covered(start, end)
        return free, inside - free, (end - start) - inside

    def holds_block(self, start: int, generation: int) -> bool:
        """Whether the current extent tree has the same tree block: a tree-block extent at
        `start`, one node long, allocated in `generation` (the block's header generation)."""
        found = None if self.extents is None else self.extents.extents.get(start)
        return bool(found and found[2] and found[0] == self.extents.nodesize
                    and found[1] == generation)  # fmt: skip

    def holds_data(self, start: int, length: int, objectid: int, parent_holds) -> bool:
        """Whether the current extent tree has the same data extent: an extent at `start` of
        `length` that a back-reference gives to inode `objectid` (an EXTENT_DATA_REF of any
        tree: a snapshot's copy of the file holds the same bytes), or a SHARED_DATA_REF whose
        parent leaf `parent_holds(parent)` says names it for that inode. The generations are
        not compared: relocation gives an extent a newer one and leaves the file extent's."""
        found = None if self.extents is None else self.extents.extents.get(start)
        if not found or found[2] or found[0] != length:
            return False
        if objectid in self.extents.data_refs.get(start, ()):
            return True
        return any(parent_holds(parent) for parent in self.extents.shared_refs.get(start, ()))

    def cross_check(self) -> dict | None:
        """Where the free space tree and the free space derived from the extent tree disagree:
        bytes free only in one of them, and the first few ranges of each. Superblock stripes are
        left out of both. A block group without a BLOCK_GROUP_ITEM is not compared."""
        if self.fst is None or self.derived is None:
            return None
        only_fst, only_derived = [], []
        for group in self.groups:
            if group.flags is None:
                continue
            a = self.free.within(group.start, group.end)
            b = self.derived.within(group.start, group.end)
            only_fst += [r for s, e in a for r in subtract(s, e, b)]
            only_derived += [r for s, e in b for r in subtract(s, e, a)]
        return {
            "free_space_tree_only": sum(e - s for s, e in only_fst),
            "extent_tree_only": sum(e - s for s, e in only_derived),
            "ranges": [list(r) for r in (only_fst + only_derived)[:8]],
        }

    def notes(self) -> list[str]:
        found = list(self.problems)
        for part in (self.extents, self.fst):
            if part is not None:
                found += [f"{part.source}: {note}" for note in part.notes()]
        return found


@dataclass(frozen=True)
class Discard:
    """The discard mode a score uses: `stated` by the examiner, else `observed` on the image."""

    stated: str | None
    observed: str
    evidence: dict = field(default_factory=dict)

    @property
    def mode(self) -> str:
        return self.stated or self.observed

    @property
    def scope(self) -> str | None:
        return DISCARD_SCOPE.get(self.mode)


def observed_discard(metadata_zeroed: int, data_zeroed: int, intact: int) -> str:
    """plan.md M6b, decision 6: a zeroed block of a committed state means metadata was trimmed;
    else a zeroed freed data sector whose checksum is not that of zeros means data was; else
    freed bytes that are still there mean no trim reached them."""
    if metadata_zeroed:
        return "trimmed_metadata"
    if data_zeroed:
        return "trimmed_data"
    return "not_trimmed" if intact else "unknown"


def overwrite_risk(verdict: str, groups: Iterable[BlockGroup], discard: Discard | None,
                   zoned: bool) -> tuple[int, tuple[str, ...]]:  # fmt: skip
    """The score (index into LEVELS) and the rules that set it (plan.md M6b, decision 5)."""
    if verdict == "in_use":
        return 0, ("in_use",)
    if verdict in ("allocated", "partial"):
        return 4, ("reallocated" if verdict == "allocated" else "partly_reallocated",)
    if verdict == "no_block_group":
        return 1, ("no_block_group",)
    reasons = ["free_in_block_group"]
    groups = list(groups)
    scope = discard.scope if discard else None
    if scope == "all" or (scope == "data" and any(g.data_only for g in groups)):
        reasons.append(f"discard_{discard.mode}")
    if any(g.used == 0 for g in groups):
        reasons.append("unused_block_group")
    if zoned and any(
        g.used is not None and g.used * 100 < g.length * ZONED_RECLAIM_PERCENT for g in groups
    ):
        reasons.append("reclaim_eligible")
    return (3 if len(reasons) > 1 else 2), tuple(reasons)


def verdict_of(held: bool, free: int, allocated: int, outside: int) -> str:
    if held:
        return "in_use"
    if allocated:
        return "allocated" if not free and not outside else "partial"
    return "free" if free else "no_block_group"


def fold(placements: Iterable[Placement | None]) -> tuple[str | None, int | None, list[str]]:
    """(verdict, risk, reasons) of a file from its extents' placements: one verdict when they all
    agree, else `partial`; the highest risk, with the reasons of every placement that has it."""
    found = [p for p in placements if p is not None]
    if not found:
        return None, None, []
    verdicts = {p.verdict for p in found}
    verdict = verdicts.pop() if len(verdicts) == 1 else "partial"
    risk = max(p.risk for p in found)
    reasons = list(dict.fromkeys(r for p in found if p.risk == risk for r in p.reasons))
    return verdict, risk, reasons
