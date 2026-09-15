"""Chunk maps: sys_chunk_array, chunk items and logical-to-physical stripe math."""

import json
import random
import struct
from pathlib import Path

import pytest

from btrfska.substrate import chunks, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.chunks import (
    STRIPE_LEN,
    Chunk,
    ChunkMap,
    MappingError,
    Stripe,
    UnmappedAddress,
    parse_chunk,
    parse_sys_chunk_array,
)
from btrfska.substrate.image import open_image
from tests.helpers import DEV_UUID, make_block

BG = ondisk.BLOCK_GROUP_FLAGS
GROUND_TRUTH = json.loads((Path(__file__).parent / "ground_truth" / "sandbox.json").read_text())
LOGICAL = 1 << 30
GIB = 1 << 30


def striped(profile: str, n: int, sub: int = 1, devids=None) -> Chunk:
    devids = devids or range(1, n + 1)
    return Chunk(
        logical=LOGICAL,
        length=GIB,
        type=BG["DATA"] | (BG[profile] if profile != "SINGLE" else 0),
        stripes=tuple(Stripe(d, (i + 1) * 10 * GIB, DEV_UUID) for i, d in enumerate(devids)),
        sub_stripes=sub,
    )


def mapping(*chunk_list: Chunk) -> ChunkMap:
    devices = {s.devid: s.dev_uuid for c in chunk_list for s in c.stripes}
    return ChunkMap("test", chunk_list, devices)


def physical(chunk_map: ChunkMap, logical: int, length: int = 4096):
    return [(c.mirror, c.devid, c.physical) for c in chunk_map.copies(logical, length)]


# ---------------------------------------------------------------------------
# Stripe math (kernel v7.0 volumes.c:6632-6850)
# ---------------------------------------------------------------------------
OFFSET = 5 * STRIPE_LEN + 100  # stripe_nr 5, stripe_offset 100


def test_single_maps_linearly():
    assert physical(mapping(striped("SINGLE", 1)), LOGICAL + OFFSET) == [(1, 1, 10 * GIB + OFFSET)]


@pytest.mark.parametrize(
    ("profile", "n"), [("DUP", 2), ("RAID1", 2), ("RAID1C3", 3), ("RAID1C4", 4)]
)
def test_mirrored_profiles_return_every_copy_in_stripe_order(profile, n):
    devids = [1, 1] if profile == "DUP" else None
    chunk_map = mapping(striped(profile, n, devids=devids))
    expected = [
        (i + 1, 1 if profile == "DUP" else i + 1, (i + 1) * 10 * GIB + OFFSET) for i in range(n)
    ]
    assert physical(chunk_map, LOGICAL + OFFSET) == expected


def test_raid0():
    # stripe_index = 5 % 3 = 2, stripe_nr = 5 // 3 = 1
    assert physical(mapping(striped("RAID0", 3)), LOGICAL + OFFSET) == [
        (1, 3, 30 * GIB + STRIPE_LEN + 100)
    ]


def test_raid10():
    # factor 4 // 2 = 2; stripe_index = (5 % 2) * 2 = 2, stripe_nr = 5 // 2 = 2; mirrors 2 and 3
    assert physical(mapping(striped("RAID10", 4, sub=2)), LOGICAL + OFFSET) == [
        (1, 3, 30 * GIB + 2 * STRIPE_LEN + 100),
        (2, 4, 40 * GIB + 2 * STRIPE_LEN + 100),
    ]


def test_raid5_data_stripe():
    # 2 data stripes: index 5 % 2 = 1, stripe_nr 5 // 2 = 2, rotated (2 + 1) % 3 = 0
    assert physical(mapping(striped("RAID5", 3)), LOGICAL + OFFSET) == [
        (1, 1, 10 * GIB + 2 * STRIPE_LEN + 100)
    ]


def test_raid6_data_stripe():
    # 2 data stripes of 4: index 1, stripe_nr 2, rotated (2 + 1) % 4 = 3
    assert physical(mapping(striped("RAID6", 4)), LOGICAL + OFFSET) == [
        (1, 4, 40 * GIB + 2 * STRIPE_LEN + 100)
    ]


@pytest.mark.parametrize(
    ("profile", "n", "sub"), [("RAID0", 2, 1), ("RAID10", 4, 2), ("RAID5", 3, 1)]
)
def test_striped_reads_may_not_cross_a_stripe_boundary(profile, n, sub):
    chunk_map = mapping(striped(profile, n, sub))
    with pytest.raises(MappingError, match="stripe boundary"):
        chunk_map.copies(LOGICAL + STRIPE_LEN - 100, 4096)


def test_mirrored_reads_may_cross_a_stripe_boundary():
    assert (
        len(mapping(striped("DUP", 2, devids=[1, 1])).copies(LOGICAL + STRIPE_LEN - 100, 4096)) == 2
    )


@pytest.mark.parametrize(
    ("logical", "length"),
    [(LOGICAL - 1, 1), (LOGICAL + GIB, 1), (LOGICAL + GIB - 100, 4096), (0, 4096)],
)
def test_addresses_outside_every_chunk_raise_unmapped(logical, length):
    with pytest.raises(UnmappedAddress, match="test chunk map"):
        mapping(striped("SINGLE", 1)).copies(logical, length)


def test_missing_device_copies_are_flagged():
    chunk = striped("RAID1", 2)
    chunk_map = ChunkMap("test", [chunk], {1: DEV_UUID})
    copies = chunk_map.copies(LOGICAL, 4096)
    assert [(c.devid, c.missing_device) for c in copies] == [(1, False), (2, True)]
    assert f"chunk {LOGICAL} stripe 1: devid 2 is missing" in chunk_map.problems


def test_wrong_device_uuid_counts_as_missing():
    chunk_map = ChunkMap("test", [striped("SINGLE", 1)], {1: b"\x99" * 16})
    assert chunk_map.copies(LOGICAL, 4096)[0].missing_device


def test_overlapping_chunks_are_flagged_and_the_later_one_ignored():
    first = striped("SINGLE", 1)
    second = Chunk(LOGICAL + GIB // 2, GIB, BG["DATA"], (Stripe(1, 99 * GIB, DEV_UUID),))
    chunk_map = mapping(first, second)
    assert chunk_map.chunks == (first,)
    assert f"chunk {second.logical} overlaps chunk {LOGICAL}; ignored" in chunk_map.problems


# ---------------------------------------------------------------------------
# Chunk items (kernel v7.0 tree-checker.c:825-1020 btrfs_check_chunk_valid)
# ---------------------------------------------------------------------------
def raw_chunk(
    length=GIB,
    type_=BG["METADATA"] | BG["DUP"],
    stripes=((1, 10 * GIB), (1, 20 * GIB)),
    num_stripes=None,
    sub_stripes=1,
    stripe_len=STRIPE_LEN,
    sector_size=4096,
):
    n = len(stripes) if num_stripes is None else num_stripes
    data = struct.pack(
        ondisk.CHUNK.format,
        length,
        2,
        stripe_len,
        type_,
        STRIPE_LEN,
        STRIPE_LEN,
        sector_size,
        n,
        sub_stripes,
    )
    for devid, offset in stripes:
        data += struct.pack(ondisk.STRIPE.format, devid, offset, DEV_UUID)
    return data


def test_valid_chunk_item():
    chunk = parse_chunk(LOGICAL, raw_chunk(), sectorsize=4096, origin="unit")
    assert chunk.problems == ()
    assert (chunk.logical, chunk.length, chunk.num_stripes, chunk.origin) == (
        LOGICAL,
        GIB,
        2,
        "unit",
    )
    assert chunk.stripes == (Stripe(1, 10 * GIB, DEV_UUID), Stripe(1, 20 * GIB, DEV_UUID))
    assert chunks.type_name(chunk.type) == "METADATA|DUP"
    assert chunks.type_name(BG["DATA"]) == "DATA|single"


INVALID_CHUNKS = [
    pytest.param(LOGICAL, raw_chunk(stripes=()), "num_stripes 0 without REMAPPED", id="no-stripes"),
    pytest.param(LOGICAL, raw_chunk(stripes=((1, 0),)), "num_stripes 1 < ncopies 2", id="ncopies"),
    pytest.param(LOGICAL + 1, raw_chunk(), "logical", id="unaligned-logical"),
    pytest.param(LOGICAL, raw_chunk(length=GIB + 1), "length", id="unaligned-length"),
    pytest.param(LOGICAL, raw_chunk(length=0), "length", id="zero-length"),
    pytest.param(LOGICAL, raw_chunk(sector_size=8192), "sector_size", id="sector-size"),
    pytest.param(LOGICAL, raw_chunk(stripe_len=4096), "stripe_len", id="stripe-len"),
    pytest.param(
        LOGICAL, raw_chunk(type_=BG["METADATA"] | 1 << 40), "unknown type bits", id="bits"
    ),
    pytest.param(
        LOGICAL,
        raw_chunk(type_=BG["METADATA"] | BG["DUP"] | BG["RAID1"]),
        "profile",
        id="two-profiles",
    ),
    pytest.param(LOGICAL, raw_chunk(type_=BG["DUP"]), "no type", id="no-type"),
    pytest.param(
        LOGICAL, raw_chunk(type_=BG["SYSTEM"] | BG["DATA"] | BG["DUP"]), "system", id="system-mixed"
    ),
    pytest.param(
        LOGICAL, raw_chunk(type_=BG["METADATA"] | BG["DATA"] | BG["DUP"]), "mixed", id="mixed"
    ),
    pytest.param(
        LOGICAL,
        raw_chunk(type_=BG["DATA"] | BG["RAID1"], stripes=((1, 0), (2, 0), (3, 0))),
        "num_stripes 3",
        id="raid1-three",
    ),
    pytest.param(
        LOGICAL,
        raw_chunk(type_=BG["DATA"] | BG["RAID10"], stripes=((1, 0), (2, 0), (3, 0), (4, 0))),
        "sub_stripes",
        id="raid10-sub",
    ),
    pytest.param(LOGICAL, raw_chunk()[:-1], "item size", id="short-item"),
    pytest.param(LOGICAL, raw_chunk()[:20], "item size", id="truncated-header"),
]


@pytest.mark.parametrize(("logical", "data", "problem"), INVALID_CHUNKS)
def test_invalid_chunk_items_are_flagged_and_refuse_to_map(logical, data, problem):
    chunk = parse_chunk(logical, data, sectorsize=4096)
    assert any(problem in p for p in chunk.problems), chunk.problems
    chunk_map = ChunkMap("test", [chunk], {1: DEV_UUID})
    if chunk.length:
        with pytest.raises(MappingError, match="invalid"):
            chunk_map.copies(chunk.logical, 1)


def test_mixed_groups_allow_data_and_metadata():
    data = raw_chunk(type_=BG["METADATA"] | BG["DATA"] | BG["DUP"])
    incompat = ondisk.INCOMPAT["MIXED_GROUPS"]
    assert parse_chunk(LOGICAL, data, sectorsize=4096, incompat=incompat).problems == ()


REMAPPED_RAID10_NO_SUB = BG["SYSTEM"] | BG["RAID10"] | BG["REMAPPED"]


def test_remapped_chunks_with_stripes_still_get_stripe_count_checks():
    # tree-checker.c:1002-1009 skips valid_stripe_count for REMAPPED chunks, but a REMAPPED chunk
    # the remap tree does not translate is still mapped through its stripes (volumes.c:6914-6930).
    data = raw_chunk(type_=REMAPPED_RAID10_NO_SUB, stripes=((1, 0), (2, 0)), sub_stripes=0)
    problems = parse_chunk(LOGICAL, data, sectorsize=4096).problems
    assert "num_stripes 2 sub_stripes 0 invalid for RAID10 (checked although REMAPPED)" in problems

    data = raw_chunk(type_=BG["DATA"] | BG["RAID6"] | BG["REMAPPED"], stripes=((1, 0),))
    problems = parse_chunk(LOGICAL, data, sectorsize=4096).problems
    assert "num_stripes 1 < nparity 2" in problems


def test_raid10_stripes_must_be_a_multiple_of_sub_stripes():
    data = raw_chunk(
        type_=BG["DATA"] | BG["RAID10"], stripes=((1, 0), (2, 0), (3, 0)), sub_stripes=2
    )
    assert "num_stripes 3 is not a multiple of sub_stripes 2" in (
        parse_chunk(LOGICAL, data, sectorsize=4096).problems
    )


@pytest.mark.parametrize(
    ("profile", "n", "sub"),
    [("RAID10", 2, 0), ("RAID10", 3, 2), ("RAID10", 2, 4), ("RAID5", 1, 1), ("RAID6", 2, 1),
     ("RAID6", 1, 1)],
)  # fmt: skip
def test_uncomputable_geometry_raises_mapping_error_even_without_problems(profile, n, sub):
    chunk_map = mapping(striped(profile, n, sub))
    with pytest.raises(MappingError, match="geometry"):
        chunk_map.copies(LOGICAL + OFFSET, 4096)


def test_remapped_raid6_with_one_stripe_never_translates():
    data = raw_chunk(type_=BG["DATA"] | BG["RAID6"] | BG["REMAPPED"], stripes=((1, 10 * GIB),))
    chunk_map = ChunkMap("test", [parse_chunk(LOGICAL, data, sectorsize=4096)], {1: DEV_UUID})
    result = None
    with pytest.raises(MappingError):
        result = chunk_map.copies(LOGICAL + OFFSET, 4096)
    assert result is None


def _assert_lookups_raise_only_mapping_errors(chunk_map: ChunkMap, rng: random.Random) -> int:
    """Translate addresses in every chunk the map accepted; return how many translated."""
    translated = 0
    for chunk in chunk_map.chunks:
        for _ in range(4):
            logical = chunk.logical + rng.randrange(0, chunk.length)
            try:
                copies = chunk_map.copies(logical, rng.choice([1, 4096, 16384]))
            except MappingError:
                continue
            translated += 1
            n = chunk.num_stripes
            assert copies and all(0 <= c.physical for c in copies) and len(copies) <= n
    return translated


def test_random_chunk_geometry_translates_or_raises_mapping_error():
    rng = random.Random(11)
    profiles = [0, *(BG[p] for p in ("RAID0", "RAID1", "RAID1C3", "RAID1C4", "RAID5", "RAID6",
                                     "DUP", "RAID10"))]  # fmt: skip
    translated = 0
    for _ in range(3000):
        n, sub = rng.randrange(0, 6), rng.randrange(0, 4)
        type_ = BG["DATA"] | rng.choice(profiles) | rng.choice([0, BG["REMAPPED"]])
        if rng.random() < 0.1:
            type_ |= rng.choice(profiles)  # sometimes two profile bits
        stripes = tuple((1, rng.randrange(0, 64) * GIB) for _ in range(n))
        parsed = parse_chunk(LOGICAL, raw_chunk(type_=type_, stripes=stripes, sub_stripes=sub),
                             sectorsize=4096)  # fmt: skip
        direct = Chunk(LOGICAL, GIB, type_, tuple(Stripe(d, o, DEV_UUID) for d, o in stripes), sub)
        for chunk in (parsed, direct):
            translated += _assert_lookups_raise_only_mapping_errors(
                ChunkMap("fuzz", [chunk], {1: DEV_UUID}), rng
            )
    assert translated > 1000  # the property is not vacuous


def test_zero_stripe_remapped_chunk_is_tolerated_and_flagged():
    data = raw_chunk(type_=BG["DATA"] | BG["REMAPPED"], stripes=())
    chunk = parse_chunk(LOGICAL, data, sectorsize=4096)
    assert chunk.problems == () and chunk.num_stripes == 0
    chunk_map = ChunkMap("test", [chunk], {1: DEV_UUID})
    assert chunk_map.problems == (
        f"chunk {LOGICAL} has no stripes (REMAPPED): its addresses resolve through the remap "
        "tree, which btrfska does not read",
    )
    with pytest.raises(UnmappedAddress, match="no stripes"):
        chunk_map.copies(LOGICAL, 4096)


# ---------------------------------------------------------------------------
# sys_chunk_array
# ---------------------------------------------------------------------------
def sys_array(*entries: bytes) -> dict:
    raw = b"".join(entries)
    block = make_block(sys_chunk_array=raw, sys_chunk_array_size=len(raw))
    return sb.parse_copy(block, 0).fields


def entry(logical, data, key_type=ondisk.ITEM_KEYS["CHUNK_ITEM"]):
    return (
        struct.pack(ondisk.DISK_KEY.format, ondisk.FIRST_CHUNK_TREE_OBJECTID, key_type, logical)
        + data
    )


SYSTEM_DUP = BG["SYSTEM"] | BG["DUP"]


def test_sys_chunk_array_entries():
    fields = sys_array(
        entry(LOGICAL, raw_chunk(type_=SYSTEM_DUP)), entry(2 * GIB, raw_chunk(type_=SYSTEM_DUP))
    )
    parsed, problems = parse_sys_chunk_array(fields)
    assert problems == ()
    assert [(c.logical, c.origin) for c in parsed] == [
        (LOGICAL, "sys_chunk_array"),
        (2 * GIB, "sys_chunk_array"),
    ]


@pytest.mark.parametrize(
    ("raw", "problem"),
    [
        (entry(LOGICAL, raw_chunk(type_=SYSTEM_DUP))[:-5], "truncated"),
        (entry(LOGICAL, raw_chunk(type_=SYSTEM_DUP), key_type=1), "key type 1"),
        (entry(LOGICAL, raw_chunk()), "not a SYSTEM chunk"),
    ],
)
def test_sys_chunk_array_problems_are_reported(raw, problem):
    block = bytearray(make_block(sys_chunk_array_size=len(raw)))
    offset = ondisk.SUPERBLOCK.offset("sys_chunk_array")
    block[offset : offset + len(raw)] = raw
    fields = ondisk.SUPERBLOCK.unpack_from(bytes(block))
    parsed, problems = parse_sys_chunk_array(fields)
    assert any(problem in p for p in problems + tuple(q for c in parsed for q in c.problems)), (
        problems
    )


def test_sys_chunk_array_garbage_never_raises():
    rng = random.Random(7)
    for _ in range(500):
        raw = rng.randbytes(rng.randrange(0, ondisk.SYSTEM_CHUNK_ARRAY_SIZE + 1))
        size = rng.choice([len(raw), rng.randrange(0, 5000)])
        fields = {
            "sys_chunk_array": raw.ljust(ondisk.SYSTEM_CHUNK_ARRAY_SIZE, b"\0"),
            "sys_chunk_array_size": size,
            "incompat_flags": 0,
            "sectorsize": 4096,
        }
        parsed, problems = parse_sys_chunk_array(fields)
        _assert_lookups_raise_only_mapping_errors(
            ChunkMap("fuzz", parsed, {1: DEV_UUID}, problems), rng
        )


@pytest.mark.sandbox
def test_sandbox_sys_chunk_array_matches_dump_tree(sandbox_img):
    with open_image(sandbox_img) as img:
        fields = sb.read_superblock(img).selected.fields
    parsed, problems = parse_sys_chunk_array(fields)
    assert problems == ()
    system = [c for c in GROUND_TRUTH["chunks"] if c["type"].startswith("SYSTEM")]
    assert [
        {
            "logical": c.logical,
            "length": c.length,
            "type": chunks.type_name(c.type),
            "stripes": [[s.devid, s.offset] for s in c.stripes],
        }
        for c in parsed
    ] == system
