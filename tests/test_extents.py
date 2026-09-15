"""Extent reads and file assembly (substrate/extents.py) on synthetic images in images/scratch/."""

import hashlib
import json
import random
import struct
import time
import tracemalloc
import zlib
from compression import zstd
from contextlib import contextmanager
from dataclasses import asdict, replace

import pytest

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import STRIPE_LEN, Chunk, ChunkMap, Stripe
from btrfska.substrate.extents import IncompleteRead, read_file
from btrfska.substrate.image import open_image
from btrfska.substrate.node import NodeReader
from btrfska.substrate.roots import TreeRoot
from tests.helpers import (
    DEV_UUID,
    lzo_extent,
    lzo_literal_stream,
    make_node,
    node_ctx,
    scratch_dir,
    sector_pad,
    write_sparse_image,
)

BG = ondisk.BLOCK_GROUP_FLAGS
K = ondisk.ITEM_KEYS
MIB = 1 << 20
META_LOGICAL, META_PHYS = 1 << 30, 1 * MIB
DATA_LOGICAL, DATA_PHYS = 2 << 30, 4 * MIB
INODE = 257
SECTOR = 4096


def inode_item(size: int, mode: int = 0o100644) -> bytes:
    values = dict.fromkeys(ondisk.INODE_ITEM.fields, 0) | {"size": size, "mode": mode}
    return struct.pack(ondisk.INODE_ITEM.format, *(values[f] for f in ondisk.INODE_ITEM.fields))


def regular(disk_bytenr, disk_num_bytes, offset, num_bytes, ram_bytes=None, compression=0,
            kind=ondisk.FILE_EXTENT_REG, encryption=0) -> bytes:  # fmt: skip
    ram = disk_num_bytes if ram_bytes is None else ram_bytes
    return struct.pack(
        ondisk.FILE_EXTENT_ITEM.format, 9, ram, compression, encryption, 0, kind,
        disk_bytenr, disk_num_bytes, offset, num_bytes,
    )  # fmt: skip


def inline(data: bytes, ram_bytes: int, compression: int = 0) -> bytes:
    return struct.pack("<QQBBHB", 9, ram_bytes, compression, 0, 0, ondisk.FILE_EXTENT_INLINE) + data


def data_chunk(profile: str = "SINGLE", stripes=((1, DATA_PHYS),)) -> Chunk:
    bits = BG["DATA"] | (0 if profile == "SINGLE" else BG[profile])
    return Chunk(DATA_LOGICAL, 64 * MIB, bits, tuple(Stripe(d, p, DEV_UUID) for d, p in stripes))


@contextmanager
def filesystem(extents, size, data=None, chunk=None, mode=0o100644):
    """A one-leaf fs tree holding inode 257 and `extents` ((file offset, item bytes) pairs), with
    `data` ({physical: bytes}) written into a 128 MiB sparse image."""
    items = [((INODE, K["INODE_ITEM"], 0), inode_item(size, mode))]
    items += [((INODE, K["EXTENT_DATA"], offset), item) for offset, item in extents]
    leaf = make_node(META_LOGICAL, items=items, owner=ondisk.FS_TREE_OBJECTID, generation=7)
    chunks = [
        Chunk(META_LOGICAL, 2 * MIB, BG["METADATA"], (Stripe(1, META_PHYS, DEV_UUID),)),
        chunk or data_chunk(),
    ]
    with scratch_dir("test_extents_") as directory:
        blocks = {META_PHYS: leaf, **(data or {})}
        path = write_sparse_image(directory / "fs.img", 128 * MIB, blocks)
        with open_image(path) as img:
            yield NodeReader(img, ChunkMap("test", chunks, {1: DEV_UUID}), node_ctx())


ROOT = TreeRoot(ondisk.FS_TREE_OBJECTID, META_LOGICAL, 0, 7, "test")


def read(reader, no_holes=True):
    return read_file(reader, ROOT, INODE, no_holes=no_holes)


def content(result) -> bytes:
    return b"".join(result.chunks())


# ---------------------------------------------------------------------------
# One extent of each kind
# ---------------------------------------------------------------------------
def test_uncompressed_inline_extent():
    data = b"this is the target file content"
    with filesystem([(0, inline(data, len(data)))], size=len(data)) as reader:
        result = read(reader)
    assert result.complete and content(result) == data
    (extent,) = result.extents
    assert (extent.kind, extent.file_offset, extent.length, extent.compression) == (
        "inline", 0, 31, "none",
    )  # fmt: skip
    assert (extent.leaf, extent.slot, extent.ranges) == (META_LOGICAL, 1, ())
    assert extent.sha256 == hashlib.sha256(data).hexdigest()


def test_compressed_inline_extent_decodes_a_whole_sector_but_supplies_ram_bytes():
    stream = zstd.compress(b"gen1\n" + bytes(SECTOR - 5))
    with filesystem([(0, inline(stream, 5, compression=3))], size=5) as reader:
        result = read(reader)
    assert content(result) == b"gen1\n"
    (extent,) = result.extents
    assert (extent.compression, extent.decoded_bytes, extent.problems) == ("zstd", SECTOR, ())


def test_non_zero_bytes_past_ram_bytes_in_an_inline_stream_are_reported():
    stream = zstd.compress(b"gen1\n" + b"residue" + bytes(SECTOR - 12))
    with filesystem([(0, inline(stream, 5, compression=3))], size=5) as reader:
        result = read(reader)
    assert content(result) == b"gen1\n"
    assert any("past ram_bytes" in p for p in result.extents[0].problems)


def test_regular_extent_honours_offset_and_num_bytes():
    disk = random.Random(1).randbytes(3 * SECTOR)
    item = regular(DATA_LOGICAL, 3 * SECTOR, SECTOR, SECTOR)
    with filesystem([(0, item)], size=SECTOR, data={DATA_PHYS: disk}) as reader:
        result = read(reader)
    assert content(result) == disk[SECTOR : 2 * SECTOR]
    (extent,) = result.extents
    (piece,) = extent.ranges
    assert (piece.logical, piece.length) == (DATA_LOGICAL + SECTOR, SECTOR)
    assert [(c.mirror, c.physical, c.readable, c.used) for c in piece.copies] == [
        (1, DATA_PHYS + SECTOR, True, True)
    ]
    assert extent.chunk_map == "test"


@pytest.mark.parametrize("compression", ["zlib", "zstd", "lzo"])
def test_compressed_regular_extent_decodes_ram_bytes_then_applies_offset(compression):
    plain = b"".join(b"%08d\n" % i for i in range(1400))[: 3 * SECTOR]
    if compression == "zlib":
        code, stored = 1, sector_pad(zlib.compress(plain))
    elif compression == "zstd":
        code, stored = 3, sector_pad(zstd.compress(plain))
    else:
        segments = [lzo_literal_stream(plain[i : i + SECTOR]) for i in range(0, 3 * SECTOR, SECTOR)]
        code, stored = 2, sector_pad(lzo_extent(segments))
    item = regular(
        DATA_LOGICAL, len(stored), SECTOR, 2 * SECTOR, ram_bytes=3 * SECTOR, compression=code
    )
    with filesystem([(0, item)], size=2 * SECTOR, data={DATA_PHYS: stored}) as reader:
        result = read(reader)
    assert result.complete
    assert content(result) == plain[SECTOR:]
    (extent,) = result.extents
    assert (extent.compression, extent.decoded_bytes) == (compression, 3 * SECTOR)
    assert [(r.logical, r.length) for r in extent.ranges] == [(DATA_LOGICAL, len(stored))]


def test_explicit_hole_and_prealloc_read_as_zeros_without_touching_the_disk():
    extents = [
        (0, regular(0, 0, 0, SECTOR)),
        (SECTOR, regular(DATA_LOGICAL, SECTOR, 0, SECTOR, kind=ondisk.FILE_EXTENT_PREALLOC)),
    ]
    data = {DATA_PHYS: b"\xff" * SECTOR}
    with filesystem(extents, size=2 * SECTOR, data=data) as reader:
        result = read(reader)
    assert content(result) == bytes(2 * SECTOR)
    assert [(e.kind, e.ranges, e.sha256) for e in result.extents] == [
        ("hole", (), None),
        ("prealloc", (), None),
    ]


# ---------------------------------------------------------------------------
# File assembly
# ---------------------------------------------------------------------------
def test_no_holes_gaps_and_the_tail_are_implicit_holes():
    a, b = b"A" * SECTOR, b"B" * SECTOR
    extents = [
        (0, regular(DATA_LOGICAL, SECTOR, 0, SECTOR)),
        (3 * SECTOR, regular(DATA_LOGICAL + SECTOR, SECTOR, 0, SECTOR)),
    ]
    data = {DATA_PHYS: a + b}
    with filesystem(extents, size=20000, data=data) as reader:
        result = read(reader)
        without_no_holes = read(reader, no_holes=False)
    assert content(result) == a + bytes(2 * SECTOR) + b + bytes(20000 - 4 * SECTOR)
    assert [(e.kind, e.file_offset, e.length) for e in result.extents] == [
        ("regular", 0, SECTOR),
        ("implicit_hole", SECTOR, 2 * SECTOR),
        ("regular", 3 * SECTOR, SECTOR),
        ("implicit_hole", 4 * SECTOR, 20000 - 4 * SECTOR),
    ]
    assert result.problems == ()
    assert without_no_holes.complete
    assert len(without_no_holes.problems) == 2
    assert all("NO_HOLES" in p for p in without_no_holes.problems)


def test_extents_are_clipped_to_the_inode_size():
    extents = [
        (0, regular(DATA_LOGICAL, 2 * SECTOR, 0, 2 * SECTOR)),
        (2 * SECTOR, regular(DATA_LOGICAL, SECTOR, 0, SECTOR, kind=ondisk.FILE_EXTENT_PREALLOC)),
    ]
    disk = random.Random(2).randbytes(2 * SECTOR)
    with filesystem(extents, size=5000, data={DATA_PHYS: disk}) as reader:
        result = read(reader)
    assert result.complete and content(result) == disk[:5000]
    first, beyond = result.extents
    assert first.length == 5000 and first.sha256 == hashlib.sha256(disk[:5000]).hexdigest()
    assert first.problems == ()  # a partial last sector is normal: nothing to report
    assert beyond.length == 0 and any("i_size" in p for p in beyond.problems)


def test_clipping_past_the_sector_holding_eof_is_reported():
    disk = random.Random(3).randbytes(3 * SECTOR)
    item = regular(DATA_LOGICAL, 3 * SECTOR, 0, 3 * SECTOR)
    with filesystem([(0, item)], size=5000, data={DATA_PHYS: disk}) as reader:
        result = read(reader)
    assert content(result) == disk[:5000]
    (extent,) = result.extents
    assert extent.problems == ("clipped from 12288 to 5000 bytes by i_size 5000",)


def test_overlapping_extents_make_the_read_incomplete():
    extents = [
        (0, regular(DATA_LOGICAL, 2 * SECTOR, 0, 2 * SECTOR)),
        (SECTOR, regular(DATA_LOGICAL, SECTOR, 0, SECTOR)),
    ]
    with filesystem(extents, size=2 * SECTOR, data={DATA_PHYS: bytes(2 * SECTOR)}) as reader:
        result = read(reader)
    assert not result.complete
    assert any("overlap" in e for e in result.errors)
    with pytest.raises(IncompleteRead):
        content(result)


def test_decode_failure_yields_no_content():
    stored = sector_pad(zstd.compress(bytes(3 * SECTOR)))
    corrupt = stored[:8] + bytes(len(stored) - 8)
    item = regular(DATA_LOGICAL, len(stored), 0, 3 * SECTOR, ram_bytes=3 * SECTOR, compression=3)
    with filesystem([(0, item)], size=3 * SECTOR, data={DATA_PHYS: corrupt}) as reader:
        result = read(reader)
    assert not result.complete
    (extent,) = result.extents
    assert extent.error_kind in {"corrupt_stream", "truncated_stream"} and extent.sha256 is None
    with pytest.raises(IncompleteRead, match=extent.error_kind):
        list(result.chunks())


@pytest.mark.parametrize(
    ("item", "kind"),
    [
        (regular(DATA_LOGICAL, SECTOR, 0, 2 * SECTOR), "invalid_extent"),  # past disk_num_bytes
        (regular(DATA_LOGICAL, SECTOR, SECTOR, SECTOR, ram_bytes=SECTOR, compression=3),
         "invalid_extent"),  # offset + num_bytes > ram_bytes
        (regular(DATA_LOGICAL, SECTOR, 0, SECTOR, ram_bytes=1 << 40, compression=1),
         "invalid_extent"),  # ram_bytes above BTRFS_MAX_UNCOMPRESSED
        (regular(DATA_LOGICAL, 1 << 20, 0, SECTOR, ram_bytes=SECTOR, compression=2),
         "invalid_extent"),  # disk_num_bytes above BTRFS_MAX_COMPRESSED
        (regular(DATA_LOGICAL, SECTOR, 0, SECTOR, compression=4), "unsupported_compression"),
        (regular(DATA_LOGICAL, SECTOR, 0, SECTOR, encryption=1), "unsupported_encoding"),
        (regular(5 << 30, SECTOR, 0, SECTOR), "unmapped"),
        (regular(DATA_LOGICAL, SECTOR, 0, SECTOR, kind=3), "invalid_extent"),
        (b"\0" * 20, "malformed_item"),
    ],
)  # fmt: skip
def test_invalid_extents_are_errors_not_content(item, kind):
    with filesystem([(0, item)], size=SECTOR, data={DATA_PHYS: bytes(SECTOR)}) as reader:
        result = read(reader)
    assert not result.complete
    assert result.extents[0].error_kind == kind


@pytest.mark.parametrize(
    ("disk_num_bytes", "num_bytes"), [(1 << 48, 1 << 48), (1 << 48, SECTOR), (SECTOR, 1 << 48)]
)
def test_extent_lengths_beyond_the_image_are_rejected_quickly_in_bounded_memory(
    disk_num_bytes, num_bytes
):
    """A hostile uncompressed extent in a 2^48-byte RAID0 chunk of a 128 MiB image: one piece per
    64 KiB would be 2^32 tuples. It must be an error record, not an allocation."""
    chunk = replace(data_chunk("RAID0", stripes=((1, DATA_PHYS), (1, DATA_PHYS + 32 * MIB))),
                    length=1 << 48)  # fmt: skip
    item = regular(DATA_LOGICAL, disk_num_bytes, 0, num_bytes)
    with filesystem([(0, item)], size=num_bytes, data={DATA_PHYS: bytes(SECTOR)},
                    chunk=chunk) as reader:  # fmt: skip
        tracemalloc.start()
        started = time.monotonic()
        result = read(reader)
        elapsed = time.monotonic() - started
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    (extent,) = result.extents
    assert (extent.error_kind, extent.ranges, extent.sha256) == ("invalid_extent", (), None)
    assert "image size" in extent.error_detail
    assert not result.complete and elapsed < 2 and peak < 4 * MIB


def test_a_striped_read_stops_at_the_first_unreadable_piece():
    """Stripe 2 is on a missing device: the read stops there instead of mapping every piece."""
    chunk = data_chunk("RAID0", stripes=((1, DATA_PHYS), (2, DATA_PHYS)))
    item = regular(DATA_LOGICAL, 64 * MIB, 0, 64 * MIB)
    with filesystem([(0, item)], size=64 * MIB, data={DATA_PHYS: bytes(SECTOR)},
                    chunk=chunk) as reader:  # fmt: skip
        result = read(reader)
    (extent,) = result.extents
    assert extent.error_kind == "unreadable"
    assert [(r.logical, r.length) for r in extent.ranges] == [
        (DATA_LOGICAL, STRIPE_LEN), (DATA_LOGICAL + STRIPE_LEN, STRIPE_LEN),
    ]  # fmt: skip


def test_missing_inode_and_directories_are_errors():
    with filesystem([], size=0, mode=0o40755) as reader:
        directory = read(reader)
        missing = read_file(reader, ROOT, 999, no_holes=True)
    assert not directory.complete and any("directory" in e for e in directory.errors)
    assert not missing.complete and missing.size is None
    assert any("INODE_ITEM" in e for e in missing.errors)


def test_empty_file_is_complete_and_empty():
    with filesystem([], size=0) as reader:
        result = read(reader)
    assert result.complete and content(result) == b"" and result.extents == ()


# ---------------------------------------------------------------------------
# Physical copies
# ---------------------------------------------------------------------------
def test_striped_extent_is_read_piecewise_across_a_stripe_boundary():
    second = DATA_PHYS + 32 * MIB
    chunk = data_chunk("RAID0", stripes=((1, DATA_PHYS), (1, second)))
    start = STRIPE_LEN - SECTOR
    left, right = b"L" * SECTOR, b"R" * SECTOR
    data = {DATA_PHYS + start: left, second: right}
    item = regular(DATA_LOGICAL + start, 2 * SECTOR, 0, 2 * SECTOR)
    with filesystem([(0, item)], size=2 * SECTOR, data=data, chunk=chunk) as reader:
        result = read(reader)
    assert content(result) == left + right
    assert [(r.logical, r.length, r.copies[0].physical) for r in result.extents[0].ranges] == [
        (DATA_LOGICAL + start, SECTOR, DATA_PHYS + start),
        (DATA_LOGICAL + STRIPE_LEN, SECTOR, second),
    ]


def test_dup_copies_are_compared_and_a_divergent_copy_is_reported():
    second = DATA_PHYS + 32 * MIB
    chunk = data_chunk("DUP", stripes=((1, DATA_PHYS), (1, second)))
    data = {DATA_PHYS: b"1" * SECTOR, second: b"2" * SECTOR}
    with filesystem([(0, regular(DATA_LOGICAL, SECTOR, 0, SECTOR))], size=SECTOR, data=data,
                    chunk=chunk) as reader:  # fmt: skip
        result = read(reader)
    assert content(result) == b"1" * SECTOR
    (piece,) = result.extents[0].ranges
    assert [(c.mirror, c.used, c.matches) for c in piece.copies] == [
        (1, True, None),
        (2, False, False),
    ]
    assert any("mirror 2 differs from mirror 1" in p for p in result.extents[0].problems)


def test_a_copy_on_a_missing_device_falls_back_to_the_next_mirror():
    second = DATA_PHYS + 32 * MIB
    chunk = data_chunk("RAID1", stripes=((2, DATA_PHYS), (1, second)))
    with filesystem([(0, regular(DATA_LOGICAL, SECTOR, 0, SECTOR))], size=SECTOR,
                    data={second: b"2" * SECTOR}, chunk=chunk) as reader:  # fmt: skip
        result = read(reader)
    assert content(result) == b"2" * SECTOR
    (piece,) = result.extents[0].ranges
    assert [(c.mirror, c.readable, c.used) for c in piece.copies] == [
        (1, False, False),
        (2, True, True),
    ]


def test_records_are_json_ready():
    with filesystem([(0, regular(DATA_LOGICAL, SECTOR, 0, SECTOR))], size=SECTOR + 1) as reader:
        result = read(reader)
    for extent in result.extents:
        json.dumps(asdict(extent))
    json.dumps(result.record())


def test_garbage_extent_items_never_raise():
    rng = random.Random(20260915)
    for _ in range(300):
        item = rng.randbytes(rng.choice([0, 5, 21, 30, 53, 60]))
        if len(item) >= 53 and rng.random() < 0.7:  # keep some items structurally plausible
            item = regular(
                DATA_LOGICAL + rng.randrange(0, 8) * SECTOR,
                rng.choice([SECTOR, 1 << 60]),
                rng.randrange(0, 3) * SECTOR,
                rng.choice([SECTOR, 1 << 62]),
                ram_bytes=rng.choice([0, SECTOR, 1 << 63]),
                compression=rng.randrange(5),
                kind=rng.randrange(4),
            )
        with filesystem([(0, item)], size=rng.choice([0, SECTOR, 1 << 62]),
                        data={DATA_PHYS: rng.randbytes(SECTOR)}) as reader:  # fmt: skip
            result = read(reader)
            if result.complete and result.size <= 1 << 20:
                assert len(content(result)) == result.size
