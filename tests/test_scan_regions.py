"""Scan regions: typed chunk stripes, unmapped gaps, skipped DATA chunks and superblock copies."""

import json
from pathlib import Path

import pytest

from btrfska.scan.regions import (
    RESERVED_END,
    Region,
    build_regions,
    plan_scan,
    read_block_groups,
    stripe_extents,
)
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import DEV_UUID, SANDBOX_INCOMPAT, SCENARIOS

BG = ondisk.BLOCK_GROUP_FLAGS
MIB = 1 << 20
MIXED = ondisk.INCOMPAT["MIXED_GROUPS"]
LEGACY = json.loads(
    (Path(__file__).parent / "ground_truth" / "sandbox_legacy_scan.json").read_text()
)
SB1 = ondisk.sb_offset(1)


def chunk(logical, length, type_, *stripes, sub=1, problems=()):
    placed = tuple(Stripe(devid, physical, DEV_UUID) for devid, physical in stripes)
    return Chunk(logical, length, type_, placed, sub, problems=problems)


def cmap(*chunks):
    return ChunkMap("test", chunks, {1: DEV_UUID})


def plan(*chunks, size=256 * MIB, incompat=SANDBOX_INCOMPAT, block_groups=None, full=False):
    return build_regions(
        cmap(*chunks),
        size,
        devid=1,
        incompat=incompat,
        block_groups=block_groups,
        full_sweep=full,
    )


def spans(regions):
    return [(r.start, r.end, r.kind) for r in regions]


# The sandbox.img chunk layout (tests/ground_truth/sandbox.json).
DATA = chunk(13631488, 8 * MIB, BG["DATA"], (1, 13631488))
SYSTEM = chunk(22020096, 8 * MIB, BG["SYSTEM"] | BG["DUP"], (1, 22020096), (1, 30408704))
METADATA = chunk(30408704, 32 * MIB, BG["METADATA"] | BG["DUP"], (1, 38797312), (1, 72351744))


def test_regions_are_typed_stripes_and_unmapped_gaps_with_data_and_superblocks_skipped():
    result = plan(DATA, SYSTEM, METADATA)
    assert result.regions == (
        Region(RESERVED_END, 13631488, "unmapped_gap"),
        Region(22020096, 30408704, "SYSTEM|DUP", 22020096, 0),
        Region(30408704, 38797312, "SYSTEM|DUP", 22020096, 1),
        Region(38797312, SB1, "METADATA|DUP", 30408704, 0),
        Region(SB1 + 4096, 72351744, "METADATA|DUP", 30408704, 0),
        Region(72351744, 105906176, "METADATA|DUP", 30408704, 1),
        Region(105906176, 256 * MIB, "unmapped_gap"),
    )
    assert result.skipped == (
        Region(0, RESERVED_END, "reserved"),
        Region(13631488, 22020096, "DATA|single", 13631488, 0),
        Region(SB1, SB1 + 4096, "superblock"),
    )
    assert result.problems == ()
    assert RESERVED_END == ondisk.SUPER_INFO_OFFSET + ondisk.SUPER_INFO_SIZE


def test_regions_and_skipped_ranges_partition_the_image():
    for full in (False, True):
        result = plan(DATA, SYSTEM, METADATA, size=200 * MIB + 123, full=full)
        ranges = sorted((r.start, r.end) for r in (*result.regions, *result.skipped))
        assert ranges[0][0] == 0 and ranges[-1][1] == 200 * MIB + 123
        assert all(a[1] == b[0] for a, b in zip(ranges, ranges[1:], strict=False))


def test_full_sweep_scans_data_chunks_too():
    result = plan(DATA, SYSTEM, METADATA, full=True)
    assert Region(13631488, 22020096, "DATA|single", 13631488, 0) in result.regions
    assert [r.kind for r in result.skipped] == ["reserved", "superblock"]


def test_mixed_groups_data_chunks_are_scanned():
    # With MIXED_GROUPS, block groups hold data and metadata alike (block-group.c:2429).
    result = plan(DATA, incompat=SANDBOX_INCOMPAT | MIXED)
    assert (13631488, 22020096, "DATA|single") in spans(result.regions)
    assert [r.kind for r in result.skipped] == ["reserved", "superblock"]


def test_a_data_and_metadata_chunk_is_always_scanned():
    mixed = chunk(13631488, 8 * MIB, BG["DATA"] | BG["METADATA"], (1, 13631488))
    assert (13631488, 22020096, "DATA|METADATA|single") in spans(plan(mixed).regions)


def test_block_groups_must_agree_before_a_data_chunk_is_skipped():
    agree = plan(DATA, block_groups={13631488: (8 * MIB, BG["DATA"])})
    assert Region(13631488, 22020096, "DATA|single", 13631488, 0) in agree.skipped
    assert agree.problems == ()

    for groups in ({13631488: (8 * MIB, BG["METADATA"])}, {13631488: (4 * MIB, BG["DATA"])}, {}):
        result = plan(DATA, block_groups=groups)
        assert (13631488, 22020096, "DATA|single") in spans(result.regions)
        assert len(result.problems) == 1
        assert "block group" in result.problems[0] and "13631488" in result.problems[0]


@pytest.mark.parametrize(
    ("profile", "stripes", "sub", "device_length"),
    [
        ("DUP", 2, 1, 64 * MIB),
        ("RAID1", 2, 1, 64 * MIB),
        ("RAID0", 2, 1, 32 * MIB),
        ("RAID10", 4, 2, 32 * MIB),
        ("RAID5", 3, 1, 32 * MIB),
        ("RAID6", 4, 1, 32 * MIB),
    ],
)
def test_stripe_extents_use_the_kernels_data_stripe_count(profile, stripes, sub, device_length):
    # volumes.c:4023-4030 calc_data_stripes and l.7271-7276 btrfs_calc_stripe_length.
    placed = [(1, (i + 1) * 128 * MIB) for i in range(stripes)]
    item = chunk(1 << 30, 64 * MIB, BG["METADATA"] | BG[profile], *placed, sub=sub)
    extents = stripe_extents(cmap(item), devid=1)
    assert [(r.start, r.end, r.stripe) for r in extents] == [
        (p, p + device_length, i) for i, (_, p) in enumerate(placed)
    ]


def test_stripes_on_other_devices_leave_a_gap_on_this_one():
    item = chunk(1 << 30, 16 * MIB, BG["DATA"] | BG["RAID1"], (1, 16 * MIB), (2, 32 * MIB))
    result = plan(item)
    assert Region(16 * MIB, 32 * MIB, "DATA|RAID1", 1 << 30, 0) in result.skipped
    assert (32 * MIB, SB1, "unmapped_gap") in spans(result.regions)


def test_physically_overlapping_chunks_are_scanned_and_reported():
    data = chunk(1 << 30, 16 * MIB, BG["DATA"], (1, 16 * MIB))
    meta = chunk(2 << 30, 16 * MIB, BG["METADATA"], (1, 24 * MIB))
    result = plan(data, meta)
    assert Region(16 * MIB, 24 * MIB, "DATA|single", 1 << 30, 0) in result.skipped
    assert Region(24 * MIB, 40 * MIB, "METADATA|single", 2 << 30, 0) in result.regions
    assert len(result.problems) == 1
    assert str(1 << 30) in result.problems[0] and str(2 << 30) in result.problems[0]


def test_rejected_chunks_never_exclude_a_range():
    bad = chunk(1 << 30, 16 * MIB, BG["DATA"], (1, 16 * MIB), problems=("invalid length",))
    result = plan(bad)
    assert (RESERVED_END, SB1, "unmapped_gap") in spans(result.regions)


def test_stripes_are_clipped_to_the_image():
    tail = chunk(1 << 30, 16 * MIB, BG["DATA"], (1, 60 * MIB))
    beyond = chunk(2 << 30, 16 * MIB, BG["DATA"], (1, 90 * MIB))
    result = plan(tail, beyond, size=64 * MIB)
    assert result.regions == (Region(RESERVED_END, 60 * MIB, "unmapped_gap"),)
    assert Region(60 * MIB, 64 * MIB, "DATA|single", 1 << 30, 0) in result.skipped


def test_tiny_images_have_no_regions():
    result = plan(size=4096)
    assert result.regions == ()
    assert result.skipped == (Region(0, 4096, "reserved"),)


def _merge(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


@pytest.mark.sandbox
def test_sandbox_regions_are_the_legacy_regions_less_the_superblock_mirror(sandbox_img):
    with open_image(sandbox_img) as img:
        fs = open_filesystem(img)
        groups, problems = read_block_groups(fs)
        result = plan_scan(fs, img.size)
    nodesize = fs.fields["nodesize"]
    assert problems == ()
    assert {logical: flags for logical, (_, flags) in groups.items()} == {
        13631488: BG["DATA"],
        22020096: BG["SYSTEM"] | BG["DUP"],
        30408704: BG["METADATA"] | BG["DUP"],
    }
    assert result.problems == ()
    superblocks = [r for r in result.skipped if r.kind == "superblock"]
    assert [(r.start, r.end) for r in superblocks] == [(SB1, SB1 + 4096)]
    # Legacy snaps its regions to nodesize and keeps the 64 MiB superblock mirror in them.
    covered = _merge([(r.start, r.end) for r in (*result.regions, *superblocks)])
    snapped = [
        [-(-start // nodesize) * nodesize, end // nodesize * nodesize] for start, end in covered
    ]
    assert snapped == LEGACY["regions"]


@pytest.mark.vm
@pytest.mark.parametrize("name", ["m1_xxhash", "m1_sha256_bgt"])
def test_generated_images_read_block_groups_from_the_right_tree(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent")
    with open_image(path) as img:
        fs = open_filesystem(img)
        groups, problems = read_block_groups(fs)
        result = plan_scan(fs, img.size)
    assert problems == ()
    assert set(groups) == {c.logical for c in fs.chunk_map.chunks}
    assert result.problems == ()
    assert any(r.kind.startswith("DATA|") for r in result.skipped)
