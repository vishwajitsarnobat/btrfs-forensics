"""Data checksums (substrate/datacsum.py, and their use in substrate/extents.py; plan.md M6a):
the EXTENT_CSUM index with hostile items, the order csum trees are asked in, the verdicts, and
synthetic extents that match, mismatch, are repaired from a mirror, or lie past the end of a file.
"""

import random
import zlib

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate.datacsum import (
    Csums,
    CsumTree,
    DataCsum,
    artifact_verdict,
    without_lookup,
)
from btrfska.substrate.extents import read_file
from btrfska.substrate.node import Item, Key
from tests.helpers import sector_pad
from tests.test_extents import (
    DATA_LOGICAL,
    DATA_PHYS,
    INODE,
    MIB,
    ROOT,
    SECTOR,
    content,
    data_chunk,
    filesystem,
    inline,
    regular,
)

XX = csum.XXHASH  # the csum type of node_ctx(), which test_extents' filesystems use


def sums(data: bytes, csum_type: int = XX) -> bytes:
    """The checksums of `data`, one per sector, as an EXTENT_CSUM item holds them."""
    return b"".join(
        csum.compute(csum_type, data[i : i + SECTOR]) for i in range(0, len(data), SECTOR)
    )


def item(offset: int, data: bytes, slot: int = 0, objectid: int = ondisk.EXTENT_CSUM_OBJECTID):
    return Item(slot, Key(objectid, ondisk.ITEM_KEYS["EXTENT_CSUM"], offset), 0, len(data), data)


def tree(*items_, complete: bool = True, source: str = "current", csum_type: int = XX):
    found = CsumTree(source, csum_type, SECTOR, complete=complete)
    for entry in items_:
        found.add(entry)
    return found


def checks(*trees) -> Csums:
    return Csums(trees, XX, SECTOR)


# ---------------------------------------------------------------------------
# The index
# ---------------------------------------------------------------------------
def test_an_item_gives_one_checksum_per_sector_from_its_key_offset():
    blob = sums(random.Random(1).randbytes(3 * SECTOR))
    index = tree(item(1 << 20, blob))
    assert index.lookup((1 << 20) + SECTOR) == (blob[8:16],)
    assert index.lookup((1 << 20) + 3 * SECTOR) == ()
    assert index.lookup((1 << 20) - SECTOR) == ()
    assert index.lookup((1 << 20) + 1) == ()  # not a sector address
    assert (index.items, index.problems) == (1, [])


@pytest.mark.parametrize("csum_type", [csum.CRC32C, csum.XXHASH, csum.SHA256, csum.BLAKE2])
def test_the_csum_size_follows_the_csum_type(csum_type):
    blob = sums(b"x" * 2 * SECTOR, csum_type)
    index = tree(item(0, blob), csum_type=csum_type)
    assert index.lookup(SECTOR) == (csum.compute(csum_type, b"x" * SECTOR),)
    with pytest.raises(csum.UnknownCsumType):
        CsumTree("current", 7, SECTOR)


@pytest.mark.parametrize(
    ("offset", "size", "finding"),
    [
        (SECTOR + 1, 8, "not aligned"),
        (0, 7, "not a positive multiple of 8"),
        (0, 0, "not a positive multiple of 8"),
        ((1 << 64) - SECTOR, 16, "passes 2^64"),
    ],
)
def test_malformed_items_are_skipped_and_reported(offset, size, finding):
    index = tree(item(offset, bytes(size)))
    assert index.items == 0 and finding in index.problems[0]
    assert index.lookup(offset - offset % SECTOR) == ()


def test_items_of_other_keys_are_ignored():
    index = tree(item(0, bytes(8), objectid=5))
    assert (index.items, index.problems, index.lookup(0)) == (0, [], ())


def test_touching_and_identically_overlapping_items_merge():
    blob = sums(random.Random(2).randbytes(4 * SECTOR))
    index = tree(item(0, blob[:16]), item(2 * SECTOR, blob[16:]), item(SECTOR, blob[8:24]))
    assert [index.lookup(i * SECTOR) for i in range(4)] == [(blob[i * 8 : i * 8 + 8],)
                                                            for i in range(4)]  # fmt: skip
    assert any("overlap" in p for p in index.problems)
    assert not any("different" in p for p in index.problems)


def test_conflicting_items_give_both_checksums_and_are_reported():
    index = tree(item(0, b"A" * 16), item(SECTOR, b"B" * 16))
    assert index.lookup(0) == (b"A" * 8,)
    assert index.lookup(SECTOR) == (b"A" * 8, b"B" * 8)
    assert index.lookup(2 * SECTOR) == (b"B" * 8,)
    assert any("1 sectors have two different checksums" in p for p in index.problems)


def test_items_added_after_a_lookup_are_indexed_too():
    index = tree(item(0, b"A" * 8))
    assert index.lookup(SECTOR) == ()
    index.add(item(SECTOR, b"B" * 8))
    assert index.lookup(SECTOR) == (b"B" * 8,) and index.lookup(0) == (b"A" * 8,)


def test_findings_are_capped_and_counted():
    index = tree(*(item(i * SECTOR + 1, bytes(8)) for i in range(40)))
    assert len(index.problems) == 16 and index.skipped == 24
    assert index.notes()[-1] == "csum tree current: and 24 more findings"


def test_a_hostile_leaf_full_of_overlaps_stays_bounded():
    entries = [item(0, bytes(8 * 2000), slot) for slot in range(50)]
    index = tree(*entries)
    assert index.lookup(1999 * SECTOR) == (bytes(8),) and index.lookup(2000 * SECTOR) == ()


# ---------------------------------------------------------------------------
# Which tree decides
# ---------------------------------------------------------------------------
def test_a_complete_tree_without_the_checksum_decides_and_later_trees_are_not_asked():
    own = tree(source="backup:9")
    later = tree(item(0, b"C" * 8))
    assert checks(own, later).lookup(0) == (own, ())


def test_an_incomplete_tree_passes_the_sector_on():
    own = tree(complete=False, source="state:3")
    later = tree(item(0, b"C" * 8))
    assert checks(own, later).lookup(0) == (later, (b"C" * 8,))
    assert checks(own).lookup(0) == (None, ())


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------
def test_the_file_verdict_folds_the_extent_verdicts():
    match, miss = DataCsum("match", sources=("current",)), DataCsum("mismatch")
    none, gone = DataCsum("no_csum"), DataCsum("unavailable")
    part = DataCsum("partial_match")
    assert artifact_verdict([match, without_lookup("implicit_hole")]) == ("match", ["current"])
    assert artifact_verdict([match, miss])[0] == "mismatch"
    assert artifact_verdict([match, none])[0] == "partial_match"
    assert artifact_verdict([part])[0] == "partial_match"
    assert artifact_verdict([none, gone])[0] == "unavailable"
    assert artifact_verdict([none])[0] == "no_csum"
    assert artifact_verdict([without_lookup("inline")])[0] == "no_csum"
    assert artifact_verdict([without_lookup("nodatasum")])[0] == "no_csum"
    assert artifact_verdict([None, None]) == (None, [])
    assert artifact_verdict([]) == (None, [])


# ---------------------------------------------------------------------------
# Synthetic extents
# ---------------------------------------------------------------------------
DISK = random.Random(3).randbytes(4 * SECTOR)


def read_with(trees, extents, size, data, **options):
    with filesystem(extents, size=size, data=data, **options) as reader:
        result = read_file(reader, ROOT, INODE, no_holes=True, csums=checks(*trees))
        return result, content(result) if result.complete else None


def test_an_extent_whose_sectors_all_match():
    result, data = read_with([tree(item(DATA_LOGICAL, sums(DISK)))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))],
                             4 * SECTOR, {DATA_PHYS: DISK})  # fmt: skip
    check = result.extents[0].csum
    assert (check.verdict, check.sectors, check.matched, check.sources) == (
        "match", 4, 4, ("current",),
    )  # fmt: skip
    assert data == DISK and result.record()["csum"] == "match"


def test_only_the_sectors_the_file_takes_are_checked():
    blob = sums(DISK)
    forged = blob[:8] + bytes(8) + blob[16:]  # sector 1 is not read: offset skips it
    item_ = regular(DATA_LOGICAL, 4 * SECTOR, 2 * SECTOR, 2 * SECTOR)
    result, _ = read_with([tree(item(DATA_LOGICAL, forged))], [(0, item_)], 2 * SECTOR,
                          {DATA_PHYS: DISK})  # fmt: skip
    assert (result.extents[0].csum.verdict, result.extents[0].csum.sectors) == ("match", 2)


def test_a_forged_checksum_is_a_mismatch_naming_the_sector_and_the_bytes_stay():
    blob = sums(DISK)
    forged = blob[:16] + bytes(8) + blob[24:]
    result, data = read_with([tree(item(DATA_LOGICAL, forged))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))],
                             4 * SECTOR, {DATA_PHYS: DISK})  # fmt: skip
    check = result.extents[0].csum
    assert (check.verdict, check.matched, check.mismatched) == ("mismatch", 3, 1)
    assert check.bad_sectors == (DATA_LOGICAL + 2 * SECTOR,)
    assert data == DISK and result.complete  # complete: read; the verdict says it is not right
    assert any("do not match their data checksum" in p for p in result.extents[0].problems)
    assert result.record()["csum"] == "mismatch"


def test_a_failing_first_mirror_is_repaired_from_the_copy_that_matches():
    second = DATA_PHYS + 32 * MIB
    damaged = DISK[:SECTOR] + bytes(SECTOR) + DISK[2 * SECTOR :]
    chunk = data_chunk("DUP", stripes=((1, DATA_PHYS), (1, second)))
    result, data = read_with([tree(item(DATA_LOGICAL, sums(DISK)))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], 4 * SECTOR,
                             {DATA_PHYS: damaged, second: DISK}, chunk=chunk)  # fmt: skip
    check = result.extents[0].csum
    assert (check.verdict, check.repaired, check.repaired_count) == (
        "match", ((DATA_LOGICAL + SECTOR, 2),), 1,
    )  # fmt: skip
    assert data == DISK  # the matching copy's sector, the rest from mirror 1
    assert any("read from another copy" in p for p in result.extents[0].problems)


def test_when_no_mirror_matches_the_first_copy_stays_and_it_is_a_mismatch():
    second = DATA_PHYS + 32 * MIB
    one, two = bytes(4 * SECTOR), b"\x01" * 4 * SECTOR
    chunk = data_chunk("DUP", stripes=((1, DATA_PHYS), (1, second)))
    result, data = read_with([tree(item(DATA_LOGICAL, sums(DISK)))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], 4 * SECTOR,
                             {DATA_PHYS: one, second: two}, chunk=chunk)  # fmt: skip
    assert result.extents[0].csum.mismatched == 4 and data == one


def test_bytes_past_the_end_of_the_file_written_again_still_match_as_a_rewritten_tail():
    size = 3 * SECTOR + 100
    checked = DISK[:size] + bytes(4 * SECTOR - size)  # the kernel zeroes past i_size
    result, data = read_with([tree(item(DATA_LOGICAL, sums(checked)))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], size,
                             {DATA_PHYS: DISK})  # fmt: skip
    check = result.extents[0].csum
    assert (check.verdict, check.tail_rewritten) == ("match", 1) and data == DISK[:size]
    # a change before the end of the file is a mismatch all the same
    changed = DISK[: size - 1] + b"\x00" + DISK[size:]
    result, _ = read_with([tree(item(DATA_LOGICAL, sums(checked)))],
                          [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], size,
                          {DATA_PHYS: changed})  # fmt: skip
    assert result.extents[0].csum.verdict == "mismatch"


def test_an_extent_wholly_past_the_end_of_the_file_is_not_checked():
    result, _ = read_with([tree(item(DATA_LOGICAL, bytes(32)))],
                          [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], 0,
                          {DATA_PHYS: DISK})  # fmt: skip
    assert result.extents[0].csum is None and result.record()["csum"] is None


@pytest.mark.parametrize(
    ("trees", "verdict"),
    [
        ([tree(complete=False), tree(complete=False)], "unavailable"),
        ([tree()], "no_csum"),
        ([tree(item(DATA_LOGICAL, sums(DISK[: 2 * SECTOR])))], "partial_match"),
        ([tree(complete=False), tree(item(DATA_LOGICAL, sums(DISK)))], "match"),
        ([tree(source="backup:9"), tree(item(DATA_LOGICAL, sums(DISK)))], "no_csum"),
    ],
)
def test_sectors_without_a_checksum(trees, verdict):
    result, _ = read_with(trees, [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))],
                          4 * SECTOR, {DATA_PHYS: DISK})  # fmt: skip
    assert result.extents[0].csum.verdict == verdict


def test_an_inode_with_nodatasum_is_not_looked_up():
    result, data = read_with([tree(item(DATA_LOGICAL, bytes(32)))],
                             [(0, regular(DATA_LOGICAL, 4 * SECTOR, 0, 4 * SECTOR))], 4 * SECTOR,
                             {DATA_PHYS: DISK}, flags=ondisk.INODE_NODATASUM)  # fmt: skip
    assert result.extents[0].csum == without_lookup("nodatasum") and data == DISK


def test_extents_without_data_checksums_by_nature():
    small = b"inline bytes"
    result, _ = read_with([tree()], [(0, inline(small, len(small)))], len(small), {})
    assert result.extents[0].csum.reason == "inline"
    prealloc = regular(DATA_LOGICAL, SECTOR, 0, SECTOR, kind=ondisk.FILE_EXTENT_PREALLOC)
    hole = regular(0, 0, 0, SECTOR)
    result, _ = read_with([tree()], [(0, prealloc), (SECTOR, hole)], 3 * SECTOR, {})
    assert [e.csum.reason for e in result.extents] == ["prealloc", "hole", "implicit_hole"]
    assert result.record()["csum"] == "no_csum"


def test_a_compressed_extent_is_checked_over_its_disk_bytes():
    plain = b"".join(b"%08d\n" % i for i in range(1400))[: 3 * SECTOR]
    stored = sector_pad(zlib.compress(plain))
    extent = regular(DATA_LOGICAL, len(stored), 0, 3 * SECTOR, ram_bytes=3 * SECTOR,
                     compression=1)  # fmt: skip
    result, data = read_with([tree(item(DATA_LOGICAL, sums(stored)))], [(0, extent)],
                             3 * SECTOR, {DATA_PHYS: stored})  # fmt: skip
    assert data == plain
    assert (result.extents[0].csum.verdict, result.extents[0].csum.sectors) == (
        "match", len(stored) // SECTOR,
    )  # fmt: skip


def test_a_misaligned_extent_cannot_be_checked():
    extent = regular(DATA_LOGICAL + 512, SECTOR, 0, SECTOR)
    result, _ = read_with([tree()], [(0, extent)], SECTOR, {DATA_PHYS: DISK})
    assert result.extents[0].csum == without_lookup("misaligned")
    assert result.extents[0].csum.verdict == "unavailable"


def test_without_csum_trees_nothing_is_checked():
    with filesystem([(0, regular(DATA_LOGICAL, SECTOR, 0, SECTOR))], size=SECTOR,
                    data={DATA_PHYS: DISK}) as reader:  # fmt: skip
        result = read_file(reader, ROOT, INODE, no_holes=True)
    assert result.extents[0].csum is None
