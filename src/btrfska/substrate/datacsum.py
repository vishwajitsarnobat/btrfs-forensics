"""Data checksums: the EXTENT_CSUM items of a csum tree, and the verdict on a data extent.

A csum tree (tree 7) holds EXTENT_CSUM items, key (EXTENT_CSUM_OBJECTID -10, 128, logical
address), each an array of one checksum per sector of the data starting at that address
(btrfs_tree.h:104, :192, :1130), of the type the superblock names (csum.py). A data read looks up
one checksum per sector of the logical range it reads (file-item.c:277-339 `search_csum_tree`,
:346-485 `btrfs_lookup_bio_sums`) and compares each sector (inode.c:3538-3578
`btrfs_data_csum_ok`). A log tree holds EXTENT_CSUM items of the same form for what it logged
(tree-log.c:5023 `log_extent_csums`).

`CsumTree` indexes the items of one tree, `Csums` asks several trees in order (plan.md M6a,
decision 2): a tree walked without a gap is *complete*, and its lack of a checksum for a sector
is final; any other tree passes the sector on to the next. `DataCsum` is the verdict on one
extent; `artifact_verdict` folds the verdicts of a file's extents into one.

Hostile items are bounded before use (tree-checker.c:365-405 rejects them all): a key offset that
is not sector-aligned, a size that is zero or not a multiple of the csum size, or a range past
2^64 is skipped and reported. Overlapping items are kept: a sector given two different checksums
is a conflict, and data that matches either of them matches, with the conflict reported. The
index holds the items' own bytes and nothing more; a lookup is a bisection.
"""

import bisect
from collections.abc import Iterable
from dataclasses import dataclass

from btrfska.substrate import csum, ondisk
from btrfska.substrate.node import Item, NodeReader
from btrfska.substrate.roots import TreeRoot
from btrfska.substrate.tree import walk

EXTENT_CSUM = ondisk.ITEM_KEYS["EXTENT_CSUM"]
MAX_LISTED = 64  # sector addresses listed per extent; the counts are always complete
MAX_PROBLEMS = 16  # findings kept per tree; the rest are counted

# Extent kinds without a data checksum by nature: their bytes are zeros, or are in a tree block
# whose own checksum covers them.
NO_DATA = ("inline", "prealloc", "hole", "implicit_hole")
VERDICTS = ("match", "mismatch", "partial_match", "no_csum", "unavailable")


class CsumTree:
    """The data checksums one tree holds, indexed by logical address.

    `source` names the tree (`current`, `state:ID`, `backup:GEN`, `log:BYTENR@GEN`, …);
    `complete` is False when the tree could not be read without a gap, or is not there at all.
    Call `add` for every item, then look sectors up with `lookup`.
    """

    def __init__(self, source: str, csum_type: int, sectorsize: int, *, complete: bool = True):
        self.source, self.csum_type, self.sectorsize = source, csum_type, sectorsize
        self.size = csum.csum_size(csum_type)  # raises UnknownCsumType
        self.complete = complete
        self.problems: list[str] = []
        self.skipped = 0  # findings beyond MAX_PROBLEMS
        self.items = 0
        self._pending: list[tuple[int, bytes]] = []
        self._starts: list[int] = []
        self._sums: list[bytearray] = []
        self._conflicts: dict[int, tuple[bytes, ...]] = {}

    def _problem(self, text: str) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(text)
        else:
            self.skipped += 1

    def add(self, item: Item, where: str = "") -> None:
        """One leaf item; anything but a well-formed EXTENT_CSUM item is ignored or reported."""
        key = item.key
        if key.objectid != ondisk.EXTENT_CSUM_OBJECTID or key.type != EXTENT_CSUM:
            return
        at = f"EXTENT_CSUM at {key.offset}{f' ({where})' if where else ''}"
        data = bytes(item.data)
        if key.offset % self.sectorsize:
            self._problem(f"{at}: key offset not aligned to the sector size {self.sectorsize}")
            return
        if not data or len(data) % self.size:
            self._problem(f"{at}: size {len(data)} is not a positive multiple of {self.size}")
            return
        if key.offset + len(data) // self.size * self.sectorsize > 1 << 64:
            self._problem(f"{at}: the range it covers passes 2^64")
            return
        self.items += 1
        self._pending.append((key.offset, data))

    def _index(self) -> None:
        """Merge the pending items into disjoint runs; record conflicting sectors."""
        if not self._pending:
            return
        merged = sorted(
            [*zip(self._starts, (bytes(s) for s in self._sums), strict=True), *self._pending],
            key=lambda pair: pair[0],
        )
        self._pending = []
        starts: list[int] = []
        sums: list[bytearray] = []
        size, sector = self.size, self.sectorsize
        for start, data in merged:
            end = start + len(data) // size * sector
            if starts:
                last_start, last = starts[-1], sums[-1]
                last_end = last_start + len(last) // size * sector
                if start <= last_end:  # overlaps or touches the run before it
                    overlap_end = min(end, last_end)
                    for address in range(start, overlap_end, sector):
                        old_at = (address - last_start) // sector * size
                        new_at = (address - start) // sector * size
                        old, new = bytes(last[old_at : old_at + size]), data[new_at : new_at + size]
                        if old != new:
                            known = self._conflicts.get(address, (old,))
                            self._conflicts[address] = (*known, *(() if new in known else (new,)))
                    if start < last_end:
                        self._problem(
                            f"EXTENT_CSUM items overlap at [{start}, {overlap_end}) "
                            f"({len(range(start, overlap_end, sector))} sectors)"
                        )
                    if end > last_end:
                        last += data[(last_end - start) // sector * size :]
                    continue
            starts.append(start)
            sums.append(bytearray(data))
        self._starts, self._sums = starts, sums
        if self._conflicts:
            self._problem(f"{len(self._conflicts)} sectors have two different checksums")

    def lookup(self, logical: int) -> tuple[bytes, ...]:
        """The checksums the tree gives the sector at `logical`: none, one, or several (a
        conflict)."""
        if self._pending:
            self._index()
        if logical in self._conflicts:
            return self._conflicts[logical]
        at = bisect.bisect_right(self._starts, logical) - 1
        if at < 0:
            return ()
        start, sums = self._starts[at], self._sums[at]
        index = (logical - start) // self.sectorsize
        if (logical - start) % self.sectorsize or index * self.size >= len(sums):
            return ()
        return (bytes(sums[index * self.size : (index + 1) * self.size]),)

    def notes(self) -> list[str]:
        found = [f"csum tree {self.source}: {p}" for p in self.problems]
        if self.skipped:
            found.append(f"csum tree {self.source}: and {self.skipped} more findings")
        return found


class Csums:
    """Csum trees asked in order: the first that has a checksum for a sector, or that is complete
    and has none, decides it."""

    def __init__(self, trees: Iterable[CsumTree], csum_type: int, sectorsize: int) -> None:
        self.trees = tuple(trees)
        self.csum_type, self.sectorsize = csum_type, sectorsize

    def lookup(self, logical: int) -> tuple[CsumTree | None, tuple[bytes, ...]]:
        """(the tree that decided, its checksums): no checksums from a complete tree means the
        sector has none; (None, ()) means no tree could say."""
        for tree in self.trees:
            found = tree.lookup(logical)
            if found or tree.complete:
                return tree, found
        return None, ()

    def compute(self, data) -> bytes:
        return csum.compute(self.csum_type, data)


@dataclass(frozen=True)
class DataCsum:
    """The verdict on one extent's data checksums. JSON-ready via asdict.

    `verdict`: match, mismatch, partial_match, no_csum or unavailable (plan.md M6a, decision 3).
    `reason`: why there is nothing to check (an extent kind of NO_DATA, `nodatasum`, `misaligned`);
    None when the sectors were looked up. `sectors` were checked, `matched` matched, `mismatched`
    did not (`bad_sectors` lists the first 64 logical addresses), `uncovered` had no checksum.
    `repaired` lists (logical, mirror) of sectors whose first copy failed and that the named copy
    supplied (the kernel's read repair, bio.c:302-341). `sources` names the trees that decided.
    `conflicts` counts sectors two items gave different checksums; `tail_rewritten` is 1 when the
    sector holding the end of the file matched only with the bytes past the end zeroed.
    """

    verdict: str
    reason: str | None = None
    sources: tuple[str, ...] = ()
    sectors: int = 0
    matched: int = 0
    mismatched: int = 0
    uncovered: int = 0
    bad_sectors: tuple[int, ...] = ()
    repaired: tuple[tuple[int, int], ...] = ()
    repaired_count: int = 0
    conflicts: int = 0
    tail_rewritten: int = 0


def tree_from_image(reader: NodeReader, root: TreeRoot | None, source: str) -> CsumTree:
    """The csum tree at `root`, walked through the image. No root gives an empty tree that is not
    complete; an invalid node or a hop finding makes the tree not complete."""
    ctx = reader.ctx
    tree = CsumTree(source, ctx.csum_type, ctx.sectorsize, complete=root is not None)
    if root is None:
        return tree
    for visit in walk(reader, root.bytenr, root.expect()):
        node = visit.node
        if visit.problems:
            tree.complete = False
            tree._problem(f"node {node.logical}: {'; '.join(visit.problems)}")
        if not node.valid:
            tree.complete = False
            tree._problem(f"node {node.logical} is invalid: {'; '.join(node.problems)}")
            continue
        for item in node.items if node.level == 0 else ():
            tree.add(item, f"leaf {node.logical} slot {item.slot}")
    return tree


def without_lookup(reason: str) -> DataCsum:
    """The verdict on an extent that has no data checksum to look up."""
    return DataCsum("unavailable" if reason == "misaligned" else "no_csum", reason=reason)


def verdict_of(matched: int, mismatched: int, sectors: int, undecided: int) -> str:
    """One extent's verdict from its sector counts; `undecided` sectors had no complete tree."""
    if mismatched:
        return "mismatch"
    if matched == sectors:
        return "match"
    if matched:
        return "partial_match"
    return "unavailable" if undecided else "no_csum"


def artifact_verdict(checks: Iterable[DataCsum | None]) -> tuple[str | None, list[str]]:
    """(verdict, sources) for a file from its extents' checks (plan.md M6a, decision 3).

    Extents without data (inline, prealloc, holes) do not take part unless there is nothing
    else; extents that could not be read (None) never do. None when no extent was checked.
    """
    checks = [c for c in checks if c is not None]
    data = [c for c in checks if c.reason not in NO_DATA]
    sources = list(dict.fromkeys(s for c in checks for s in c.sources))
    if not data:
        return ("no_csum" if checks else None), sources
    verdicts = {c.verdict for c in data}
    if "mismatch" in verdicts:
        return "mismatch", sources
    if verdicts == {"match"}:
        return "match", sources
    if verdicts & {"match", "partial_match"}:
        return "partial_match", sources
    return ("unavailable" if "unavailable" in verdicts else "no_csum"), sources
