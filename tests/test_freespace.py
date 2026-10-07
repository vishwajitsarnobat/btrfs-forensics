"""Free space (substrate/freespace.py, plan.md M6b): the free space tree's items with hostile
ones among them, free space derived from an extent tree, placing a range, the overwrite-risk
rules, the observed discard mode, and the reverse chunk mapping (chunks.ChunkMap.logical_of).
"""

import random
import struct

import pytest

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.freespace import (
    BlockGroup,
    Discard,
    ExtentTree,
    FreeSpaceTree,
    Placement,
    Ranges,
    SpaceView,
    fold,
    observed_discard,
    overwrite_risk,
    super_stripes,
    verdict_of,
)
from btrfska.substrate.node import Item, Key
from tests.helpers import DEV_UUID

K = ondisk.ITEM_KEYS
BG = ondisk.BLOCK_GROUP_FLAGS
S = 4096
MIB = 1 << 20
NODE = 16384


def item(objectid: int, type_: int, offset: int, data: bytes = b"", slot: int = 0) -> Item:
    return Item(slot, Key(objectid, type_, offset), 0, len(data), data)


def info(start: int, length: int, count: int, bitmaps: bool = False) -> Item:
    return item(start, K["FREE_SPACE_INFO"], length, struct.pack("<II", count, int(bitmaps)))


def extent(start: int, length: int) -> Item:
    return item(start, K["FREE_SPACE_EXTENT"], length)


def bitmap(start: int, sectors: list[bool]) -> Item:
    raw = bytearray((len(sectors) + 7) // 8)
    for index, bit in enumerate(sectors):
        if bit:
            raw[index >> 3] |= 1 << (index & 7)
    return item(start, K["FREE_SPACE_BITMAP"], len(sectors) * S, bytes(raw))


def tree(*items_) -> FreeSpaceTree:
    found = FreeSpaceTree("test", S)
    for entry in items_:
        found.add(entry)
    return found


# ---------------------------------------------------------------------------
# The free space tree
# ---------------------------------------------------------------------------
def test_free_extents_of_a_block_group():
    found = tree(info(MIB, MIB, 2), extent(MIB, S), extent(MIB + 4 * S, 2 * S))
    assert found.free.pairs == [(MIB, MIB + S), (MIB + 4 * S, MIB + 6 * S)]
    assert (found.inconsistent, found.problems, found.items) == ([], [], 3)
    assert [(g.start, g.length, g.flags) for g in found.block_groups()] == [(MIB, MIB, None)]


def test_bitmaps_are_runs_of_set_bits_least_significant_first_and_a_run_carries_over():
    # sectors 1-2 free, then a run from the last sector of the first bitmap into the second one
    first = [False, True, True, False, False, False, False, True]
    second = [True, True, False, False, False, False, False, True, False]
    found = tree(
        info(MIB, 17 * S, 3, bitmaps=True), bitmap(MIB, first), bitmap(MIB + 8 * S, second)
    )
    assert found.free.pairs == [
        (MIB + S, MIB + 3 * S), (MIB + 7 * S, MIB + 10 * S), (MIB + 15 * S, MIB + 16 * S),
    ]  # fmt: skip
    assert (found.inconsistent, found.problems) == ([], [])


def test_a_wrong_extent_count_marks_the_block_group_inconsistent_and_keeps_its_ranges():
    found = tree(info(MIB, MIB, 5), extent(MIB, S), info(2 * MIB, MIB, 0))
    assert found.inconsistent == [MIB] and found.free.pairs == [(MIB, MIB + S)]
    assert "1 free extents, but its FREE_SPACE_INFO says 5" in found.problems[0]
    last = tree(info(MIB, MIB, 0, bitmaps=True), bitmap(MIB, [True] * 8))
    assert last.free.total() == 8 * S and last.inconsistent == [MIB]  # checked at the end too


@pytest.mark.parametrize(
    ("entry", "phrase"),
    [
        (item(MIB, K["FREE_SPACE_INFO"], MIB, b"\0" * 7), "size 7, not 8"),
        (item(MIB, K["FREE_SPACE_INFO"], 0, b"\0" * 8), "empty range"),
        (item((1 << 64) - S, K["FREE_SPACE_INFO"], 2 * S, b"\0" * 8), "past 2^64"),
        (item(MIB + 1, K["FREE_SPACE_EXTENT"], S), "not aligned"),
        (item(MIB, K["FREE_SPACE_EXTENT"], 0), "zero"),
        (item(MIB, K["FREE_SPACE_EXTENT"], 2 * MIB), "not inside the block group"),
        (item(3 * MIB, K["FREE_SPACE_EXTENT"], S), "not inside the block group"),
        (item(MIB, K["FREE_SPACE_BITMAP"], 8 * S, b"\xff"), "says extents"),
    ],
)
def test_hostile_items_are_skipped_and_reported(entry, phrase):
    found = tree(info(MIB, MIB, 0), entry)
    assert any(phrase in p for p in found.problems), found.problems
    assert found.free.total() == 0


def test_an_entry_before_any_info_and_an_overlapping_info_are_skipped():
    found = tree(extent(MIB, S), info(MIB, MIB, 0), info(MIB + S, MIB, 0))
    assert [g.start for g in found.block_groups()] == [MIB]
    assert any("not inside the block group" in p for p in found.problems)
    assert any("overlaps the block group before it" in p for p in found.problems)


def test_a_bitmap_whose_size_does_not_match_its_key_allocates_nothing_from_the_key():
    huge = item(MIB, K["FREE_SPACE_BITMAP"], 1 << 40, b"\xff" * 32)
    found = tree(info(MIB, 1 << 41, 0, bitmaps=True), huge)
    assert any("32 bytes, not" in p for p in found.problems) and found.free.total() == 0


def test_overlapping_free_ranges_are_merged_and_reported():
    found = tree(info(MIB, MIB, 2), extent(MIB, 4 * S), extent(MIB + 2 * S, 4 * S))
    assert found.free.pairs == [(MIB, MIB + 6 * S)]
    assert any("overlap by 8192 bytes" in p for p in found.problems)


def test_bitmaps_that_do_not_continue_each_other_are_reported():
    found = tree(info(MIB, MIB, 2, bitmaps=True), bitmap(MIB, [True] * 8),
                 bitmap(MIB + 16 * S, [True] * 8))  # fmt: skip
    assert any("does not continue the bitmap before it" in p for p in found.problems)
    # the kernel carries the run over the gap and counts one extent; the gap is not made free
    assert found.inconsistent == [MIB] and found.free.total() == 16 * S


def test_random_items_never_raise():
    rng = random.Random(50)
    for _ in range(300):
        found = FreeSpaceTree("fuzz", S)
        for slot in range(rng.randrange(1, 12)):
            type_ = rng.choice([K["FREE_SPACE_INFO"], K["FREE_SPACE_EXTENT"],
                                K["FREE_SPACE_BITMAP"], K["EXTENT_ITEM"]])  # fmt: skip
            start = rng.choice([0, MIB, MIB + S, rng.randrange(1 << 64)])
            length = rng.choice([0, S, 8 * S, MIB, rng.randrange(1 << 64)])
            found.add(item(start, type_, length, rng.randbytes(rng.choice([0, 1, 8, 9, 64])), slot))
        found.free.total()
        found.block_groups()
        extents = ExtentTree("fuzz", NODE)
        for slot in range(rng.randrange(1, 12)):
            type_ = rng.choice([K["EXTENT_ITEM"], K["METADATA_ITEM"], K["BLOCK_GROUP_ITEM"],
                                K["EXTENT_DATA_REF"], K["SHARED_DATA_REF"]])  # fmt: skip
            extents.add(item(rng.randrange(1 << 64), type_, rng.randrange(1 << 64),
                             rng.randbytes(rng.choice([0, 8, 24, 40, 53])), slot))  # fmt: skip
        SpaceView(extents, found).cross_check()


# ---------------------------------------------------------------------------
# The extent tree, the view, and placing
# ---------------------------------------------------------------------------
def block_group(start: int, length: int, used: int, flags: int) -> Item:
    return item(start, K["BLOCK_GROUP_ITEM"], length, struct.pack("<QQQ", used, 256, flags))


def extent_item(start, length, generation, *, root=5, objectid=257, tree_block=False) -> Item:
    flags = ondisk.EXTENT_FLAG_TREE_BLOCK if tree_block else ondisk.EXTENT_FLAG_DATA
    head = struct.pack("<QQQ", 1, generation, flags)
    if tree_block:
        return item(start, K["METADATA_ITEM"], 0, head + struct.pack("<BQ", K["TREE_BLOCK_REF"], 5))
    ref = struct.pack("<BQQQI", K["EXTENT_DATA_REF"], root, objectid, 0, 1)
    return item(start, K["EXTENT_ITEM"], length, head + ref)


def extents_of(*items_) -> ExtentTree:
    found = ExtentTree("test", NODE)
    for entry in items_:
        found.add(entry)
    return found


DATA_BG = block_group(8 * MIB, 8 * MIB, 3 * S, BG["DATA"])


def test_free_space_derived_from_the_extent_tree_equals_the_tree_s_own():
    extents = extents_of(
        DATA_BG, extent_item(8 * MIB, S, 7), extent_item(8 * MIB + 4 * S, 2 * S, 8)
    )
    fst = tree(info(8 * MIB, 8 * MIB, 2), extent(8 * MIB + S, 3 * S),
               extent(8 * MIB + 6 * S, 8 * MIB - 6 * S))  # fmt: skip
    view = SpaceView(extents, fst)
    assert view.source == "free_space_tree" and view.derived.pairs == view.free.pairs
    assert view.cross_check() == {"free_space_tree_only": 0, "extent_tree_only": 0, "ranges": []}
    alone = SpaceView(extents, None)
    assert alone.source == "extent_tree" and alone.free.pairs == fst.free.pairs
    wrong = SpaceView(extents, tree(info(8 * MIB, 8 * MIB, 1), extent(8 * MIB, 8 * MIB)))
    assert wrong.cross_check()["free_space_tree_only"] == 3 * S


def test_superblock_stripes_are_neither_free_nor_disagreement():
    # a single chunk at logical 0 on physical 0: the copy at 64 MiB lies in it
    chunk_map = ChunkMap("t", [Chunk(0, 128 * MIB, BG["DATA"], (Stripe(1, 0, DEV_UUID),))],
                         {1: DEV_UUID})  # fmt: skip
    extents = extents_of(block_group(0, 128 * MIB, 0, BG["DATA"]))
    excluded = super_stripes(chunk_map, extents.groups.values(), 256 * MIB)
    assert excluded == [(0, 65536), (65536, 131072), (64 * MIB, 64 * MIB + 65536)]
    # the tree holds the whole block group free, as a new block group enters it
    view = SpaceView(extents, tree(info(0, 128 * MIB, 1), extent(0, 128 * MIB)), excluded)
    assert view.free.total() == 128 * MIB - 3 * 65536
    assert view.cross_check()["free_space_tree_only"] == 0


def test_placing_counts_free_allocated_and_outside_bytes():
    view = SpaceView(extents_of(DATA_BG, extent_item(8 * MIB, S, 7)), None)
    assert view.place(8 * MIB, 8 * MIB + 2 * S) == (S, S, 0)
    assert view.place(8 * MIB - S, 8 * MIB + S) == (0, S, S)
    assert view.place(0, S) == (0, 0, S)


def test_the_same_allocation_needs_the_same_address_length_and_owner():
    extents = extents_of(DATA_BG, extent_item(8 * MIB, 2 * S, 9, objectid=300),
                         extent_item(9 * MIB, NODE, 12, tree_block=True))  # fmt: skip
    view = SpaceView(extents, None)
    never = lambda parent: False  # noqa: E731
    assert view.holds_data(8 * MIB, 2 * S, 300, never)
    assert not view.holds_data(8 * MIB, 2 * S, 301, never)  # another inode's extent now
    assert not view.holds_data(8 * MIB, S, 300, never)
    assert view.holds_block(9 * MIB, 12) and not view.holds_block(9 * MIB, 11)
    shared = extents_of(DATA_BG, item(8 * MIB, K["EXTENT_ITEM"], S, struct.pack(
        "<QQQBQI", 1, 9, 1, K["SHARED_DATA_REF"], 7 * MIB, 1)))  # fmt: skip
    asked = []
    assert SpaceView(shared, None).holds_data(8 * MIB, S, 300, lambda p: asked.append(p) or True)
    assert asked == [7 * MIB]


def test_verdicts_from_byte_counts():
    assert verdict_of(True, 0, 4, 0) == "in_use"
    assert verdict_of(False, 4, 0, 0) == "free"
    assert verdict_of(False, 0, 4, 0) == "allocated"
    assert verdict_of(False, 2, 2, 0) == "partial"
    assert verdict_of(False, 0, 0, 4) == "no_block_group"
    assert verdict_of(False, 2, 0, 2) == "free"


# ---------------------------------------------------------------------------
# The overwrite risk
# ---------------------------------------------------------------------------
DATA = BlockGroup(0, MIB, BG["DATA"], S)
META = BlockGroup(0, MIB, BG["METADATA"] | BG["DUP"], S)
EMPTY = BlockGroup(0, MIB, BG["DATA"], 0)


@pytest.mark.parametrize(
    ("verdict", "groups", "discard", "zoned", "expected"),
    [
        ("in_use", [DATA], "sync", False, (0, ("in_use",))),
        ("no_block_group", [], "sync", False, (1, ("no_block_group",))),
        ("free", [DATA], None, False, (2, ("free_in_block_group",))),
        ("free", [DATA], "sync", False, (3, ("free_in_block_group", "discard_sync"))),
        ("free", [META], "sync", False, (3, ("free_in_block_group", "discard_sync"))),
        ("free", [DATA], "async", False, (3, ("free_in_block_group", "discard_async"))),
        ("free", [META], "async", False, (2, ("free_in_block_group",))),  # data-only groups
        ("free", [META], "trimmed_metadata", False,
         (3, ("free_in_block_group", "discard_trimmed_metadata"))),
        ("free", [META], "trimmed_data", False, (2, ("free_in_block_group",))),
        ("free", [DATA], "not_trimmed", False, (2, ("free_in_block_group",))),
        ("free", [EMPTY], None, False, (3, ("free_in_block_group", "unused_block_group"))),
        ("free", [DATA], None, True, (3, ("free_in_block_group", "reclaim_eligible"))),
        ("free", [BlockGroup(0, 100, BG["DATA"], 75)], None, True, (2, ("free_in_block_group",))),
        ("allocated", [DATA], None, False, (4, ("reallocated",))),
        ("partial", [DATA], None, False, (4, ("partly_reallocated",))),
    ],
)  # fmt: skip
def test_each_risk_rule(verdict, groups, discard, zoned, expected):
    mode = None if discard is None else Discard(discard if discard in ("sync", "async") else None,
                                                discard)  # fmt: skip
    assert overwrite_risk(verdict, groups, mode, zoned) == expected


def test_a_file_takes_its_highest_risk_and_one_verdict_or_partial():
    low = Placement("in_use", "free_space_tree", S, risk=0, level="none", reasons=("in_use",))
    high = Placement("free", "free_space_tree", S, risk=3, level="high",
                     reasons=("free_in_block_group", "discard_sync"))  # fmt: skip
    assert fold([low, low]) == ("in_use", 0, ["in_use"])
    assert fold([low, None, high]) == ("partial", 3, ["free_in_block_group", "discard_sync"])
    assert fold([None]) == (None, None, [])


def test_the_observed_discard_mode():
    assert observed_discard(1, 0, 50) == "trimmed_metadata"
    assert observed_discard(0, 2, 50) == "trimmed_data"
    assert observed_discard(0, 0, 3) == "not_trimmed"
    assert observed_discard(0, 0, 0) == "unknown"
    assert Discard("async", "not_trimmed").scope == "data"
    assert Discard(None, "trimmed_metadata").scope == "all"


def test_ranges_cover_and_clip():
    ranges = Ranges([(10, 20), (30, 40), (15, 25)])
    assert ranges.pairs == [(10, 25), (30, 40)] and ranges.overlap == 5
    assert ranges.covered(0, 100) == 25 and ranges.covered(20, 35) == 10
    assert ranges.within(22, 32) == [(22, 25), (30, 32)]


# ---------------------------------------------------------------------------
# The reverse chunk mapping
# ---------------------------------------------------------------------------
def chunk_map(*chunks) -> ChunkMap:
    return ChunkMap("t", chunks, {1: DEV_UUID, 2: DEV_UUID})


def test_logical_of_follows_btrfs_rmap_block():
    dup = Chunk(MIB << 10, 8 * MIB, BG["METADATA"] | BG["DUP"],
                (Stripe(1, 10 * MIB, DEV_UUID), Stripe(1, 30 * MIB, DEV_UUID)))  # fmt: skip
    raid0 = Chunk(2 << 30, 4 * MIB, BG["DATA"] | BG["RAID0"],
                  (Stripe(1, 50 * MIB, DEV_UUID), Stripe(2, 50 * MIB, DEV_UUID)))  # fmt: skip
    raid10 = Chunk(3 << 30, 4 * MIB, BG["DATA"] | BG["RAID10"],
                   tuple(Stripe(1 + i % 2, 60 * MIB + (i // 2) * 8 * MIB, DEV_UUID)
                         for i in range(4)), sub_stripes=2)  # fmt: skip
    raid5 = Chunk(4 << 30, 4 * MIB, BG["DATA"] | BG["RAID5"],
                  (Stripe(1, 90 * MIB, DEV_UUID), Stripe(2, 90 * MIB, DEV_UUID),
                   Stripe(1, 95 * MIB, DEV_UUID)))  # fmt: skip
    found = chunk_map(dup, raid0, raid10, raid5)
    assert found.logical_of(1, 10 * MIB + 5)[:2] == ((MIB << 10) + 5, 8 * MIB - 5)
    assert found.logical_of(1, 30 * MIB + 7)[0] == (MIB << 10) + 7  # the second copy
    # RAID0: device 2's first stripe is logical stripe 1
    assert found.logical_of(2, 50 * MIB + 3)[:2] == ((2 << 30) + 65536 + 3, 65536 - 3)
    assert found.logical_of(1, 50 * MIB + 65536)[0] == (2 << 30) + 2 * 65536
    # RAID10, 4 stripes, 2 sub stripes: stripes 2 and 3 hold logical stripe 1
    assert found.logical_of(1, 68 * MIB)[0] == (3 << 30) + 65536
    for copy in found.copies((3 << 30) + 65536, 10):
        assert found.logical_of(copy.devid, copy.physical)[0] == (3 << 30) + 65536
    for logical in ((2 << 30) + 3 * 65536 + 9, (MIB << 10) + 99):
        for copy in found.copies(logical, 1):
            assert found.logical_of(copy.devid, copy.physical)[0] == logical
    assert found.logical_of(1, 91 * MIB) is None  # RAID5 is not mapped back
    assert found.logical_of(1, 5 * MIB) is None and found.logical_of(None, 10 * MIB) is not None


def test_logical_ranges_split_at_stripe_ends_and_gaps():
    single = Chunk(MIB << 10, 2 * MIB, BG["DATA"], (Stripe(1, 10 * MIB, DEV_UUID),))
    other = Chunk(2 << 30, 2 * MIB, BG["DATA"], (Stripe(1, 13 * MIB, DEV_UUID),))
    found = list(chunk_map(single, other).logical_ranges(1, 11 * MIB, 3 * MIB))
    assert found == [((MIB << 10) + MIB, MIB), (None, MIB), (2 << 30, MIB)]
