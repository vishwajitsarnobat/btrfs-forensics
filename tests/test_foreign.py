"""Foreign-FSID discovery (plan.md M6f, scan/foreign.py) on synthetic input: the census and its
bounds, the context inference, the identity rules, hostile chunk-tree leaves, and copies of
sandbox.img with planted foreign blocks and with floods of header-shaped garbage."""

import json
import random
import shutil
import struct
import tracemalloc
import uuid

import pytest

from btrfska.cli import main
from btrfska.scan import foreign
from btrfska.scan.foreign import (
    CENSUS_SLOTS,
    KINDS,
    MAX_FOREIGN,
    SOURCES,
    _identity,
    _reduce,
    census,
    device_uuids,
    foreign_scan,
    infer_context,
    metadata_uuid_change,
)
from btrfska.scan.regions import Region, plan_scan
from btrfska.substrate import csum, ondisk
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import make_node, node_ctx, scratch_dir, write_sparse_image

SECTOR = 4096
OTHER = bytes(range(100, 116))  # a foreign fsid
# The sandbox's trailing unmapped gap, scanned by the targeted plan (tests/test_scan_hostile.py).
TRAILING_GAP = (105906176, 268435456)
# Peak Python heap of a foreign scan of a flood; the candidate-flood test's budget.
BUDGET = 16 << 20


def header_sector(fsid: bytes, bytenr: int = SECTOR, generation: int = 1) -> bytearray:
    """A sector whose header looks like a tree block's (WRITTEN, level 0), checksum garbage."""
    sector = bytearray(SECTOR)
    sector[0x20:0x30] = fsid
    struct.pack_into("<QQ", sector, 0x30, bytenr, ondisk.HEADER_FLAG_WRITTEN)
    struct.pack_into("<Q", sector, 0x50, generation)
    return sector


def whole(size: int) -> list[Region]:
    return [Region(0, size, "unmapped_gap")]


def test_census_counts_header_shaped_offsets_per_fsid_and_nothing_else():
    shaped = bytes(header_sector(OTHER))
    unwritten = bytearray(shaped)
    unwritten[0x38] = 0  # WRITTEN cleared
    level = bytearray(shaped)
    level[0x64] = 8
    unknown_flag = bytearray(shaped)
    unknown_flag[0x38] |= 4
    revision = bytearray(shaped)
    revision[0x3F] = 2  # backref revision 2 does not exist
    zero_fsid = header_sector(bytes(16))
    blocks = {SECTOR * i: shaped for i in (2, 5, 9)}
    for i, sector in enumerate((unwritten, level, unknown_flag, revision, zero_fsid)):
        blocks[SECTOR * (20 + i)] = bytes(sector)
    with scratch_dir("test_foreign_") as d:
        with open_image(write_sparse_image(d / "c.img", 64 * SECTOR, blocks)) as img:
            found = census(img, whole(img.size))
    assert found.header_shaped == 3
    assert found.counts == {OTHER: 3}
    assert found.undercount == 0


def test_the_census_summary_keeps_a_frequent_fsid_among_many_rare_ones():
    counts = {bytes([0, *divmod(i, 256), *bytes(13)]): 1 for i in range(CENSUS_SLOTS + 50)}
    counts[OTHER] = 200
    taken = _reduce(counts)
    assert taken == 1 and len(counts) <= CENSUS_SLOTS
    assert counts[OTHER] == 199  # undercounted by at most what was taken
    small = {OTHER: 3}
    assert _reduce(small) == 0 and small == {OTHER: 3}


@pytest.mark.parametrize(("nodesize", "csum_type"), [(8192, csum.SHA256), (16384, csum.CRC32C)])
def test_the_context_is_inferred_from_what_verifies(nodesize, csum_type):
    blocks = {
        SECTOR * 4 * i: make_node(SECTOR * 4 * i, nodesize=nodesize, csum_type=csum_type,
                                  fsid=OTHER)
        for i in range(1, 5)
    }  # fmt: skip
    with scratch_dir("test_foreign_") as d:
        with open_image(write_sparse_image(d / "i.img", 64 * SECTOR, blocks)) as img:
            context = infer_context(img, OTHER, whole(img.size), node_ctx())
    assert context.source == "inferred"
    assert (context.ctx.nodesize, context.ctx.csum_type) == (nodesize, csum_type)
    assert (context.sampled, context.verified, context.ctx.fsid) == (4, 4, OTHER)
    assert context.ctx.chunk_tree_uuid is None


def test_without_any_verifying_block_the_context_is_none():
    blocks = {SECTOR * 3: bytes(header_sector(OTHER))}
    with scratch_dir("test_foreign_") as d:
        with open_image(write_sparse_image(d / "n.img", 64 * SECTOR, blocks)) as img:
            context = infer_context(img, OTHER, whole(img.size), node_ctx())
    assert (context.source, context.sampled, context.verified) == ("none", 1, 0)
    assert context.source in SOURCES


def test_device_uuids_reads_dev_items_and_chunk_stripes():
    a, b = bytes(range(1, 17)), bytes(range(2, 18))
    chunk = bytearray(ondisk.CHUNK.size + ondisk.STRIPE.size)
    struct.pack_into("<QQQQIIIHH", chunk, 0, 1 << 22, 2, 65536, 2, 65536, 65536, 4096, 1, 0)
    struct.pack_into("<QQ16s", chunk, ondisk.CHUNK.size, 1, 1 << 20, b)
    items = [
        ((ondisk.DEV_ITEMS_OBJECTID, ondisk.ITEM_KEYS["DEV_ITEM"], 1), _dev_item(a)),
        ((256, ondisk.ITEM_KEYS["CHUNK_ITEM"], 1 << 22), bytes(chunk)),
    ]
    leaf = make_node(SECTOR, owner=ondisk.CHUNK_TREE_OBJECTID, items=items, fsid=OTHER)
    assert device_uuids(leaf, node_ctx(fsid=OTHER)) == [a, b]


def _dev_item(dev: bytes) -> bytes:
    item = bytearray(ondisk.DEV_ITEM.size)
    item[66:82] = dev
    assert ondisk.DEV_ITEM.unpack_from(item)["uuid"] == dev
    return bytes(item)


def test_device_uuids_never_raises_on_hostile_leaves():
    rng = random.Random(54)
    ctx = node_ctx(fsid=OTHER)
    for _ in range(300):
        leaf = bytearray(rng.randbytes(4096))
        struct.pack_into("<I", leaf, 0x60, rng.randrange(0, 400))
        found = device_uuids(bytes(leaf), ctx)
        assert all(len(dev) == 16 for dev in found)
    short = [((1, ondisk.ITEM_KEYS["DEV_ITEM"], 1), b"x" * 10),
             ((256, ondisk.ITEM_KEYS["CHUNK_ITEM"], 4096), b"y" * 20)]  # fmt: skip
    leaf = make_node(SECTOR, owner=ondisk.CHUNK_TREE_OBJECTID, items=short, fsid=OTHER)
    assert device_uuids(leaf, ctx) == []


CURRENT_DEV, OLD_DEV = bytes(range(16)), bytes(range(1, 17))


@pytest.mark.parametrize(
    ("uuids", "newest", "kind"),
    [
        ({CURRENT_DEV: 3}, 10, "fsid_change"),
        ({OLD_DEV: 3}, 10, "reformat"),
        ({}, 50, "reformat"),  # newer than this filesystem: not its own past
        ({}, 10, "undetermined"),
        ({}, None, "undetermined"),
        ({CURRENT_DEV: 1}, 50, "undetermined"),  # the two rules disagree
    ],
)
def test_identity_rules(uuids, newest, kind):
    found, evidence = _identity(uuids, [], CURRENT_DEV, newest, 20)
    assert found == kind and found in KINDS
    assert evidence


def test_metadata_uuid_change_needs_the_flag_and_two_different_uuids():
    flag = ondisk.INCOMPAT["METADATA_UUID"]
    fields = {"incompat_flags": flag, "fsid": OTHER, "metadata_uuid": bytes(16)}
    assert metadata_uuid_change(fields) == {
        "fsid": str(uuid.UUID(bytes=OTHER)),
        "metadata_uuid": str(uuid.UUID(bytes=bytes(16))),
    }
    assert metadata_uuid_change(fields | {"metadata_uuid": OTHER}) is None
    assert metadata_uuid_change(fields | {"incompat_flags": 0}) is None


# ---------------------------------------------------------------------------
# Copies of sandbox.img
# ---------------------------------------------------------------------------
def derived(sandbox_img, directory, name, patches):
    path = directory / name
    shutil.copyfile(sandbox_img, path)
    with open(path, "r+b") as f:
        for offset, data in patches:
            f.seek(offset)
            f.write(data)
    return path


def run(path, emit=None):
    with open_image(path) as img:
        fs = open_filesystem(img)
        plan = plan_scan(fs, img.size)
        return foreign_scan(img, fs, plan.regions, emit), fs.fields


PLANT = TRAILING_GAP[0] + (1 << 20)


@pytest.mark.sandbox
def test_planted_blocks_of_another_filesystem_are_found_validated_and_identified(sandbox_img):
    other_dev = bytes(range(200, 216))
    blocks = [make_node(PLANT + i * 8192, nodesize=8192, csum_type=csum.SHA256, fsid=OTHER,
                        owner=256, generation=5) for i in range(3)]  # fmt: skip
    dev_item = ((ondisk.DEV_ITEMS_OBJECTID, ondisk.ITEM_KEYS["DEV_ITEM"], 1), _dev_item(other_dev))
    blocks.append(make_node(
        PLANT + 3 * 8192, owner=ondisk.CHUNK_TREE_OBJECTID, nodesize=8192, csum_type=csum.SHA256,
        fsid=OTHER, generation=5, items=[dev_item],
    ))  # fmt: skip
    patches = [(PLANT + i * 8192, block) for i, block in enumerate(blocks)]
    records = []
    with scratch_dir("test_foreign_planted_") as d:
        summary, fields = run(derived(sandbox_img, d, "planted.img", patches), records.append)
    (found,) = summary["filesystems"]
    assert found["fsid"] == str(uuid.UUID(bytes=OTHER))
    assert (found["kind"], found["candidates"], found["valid"]) == ("reformat", 4, 4)
    assert found["census_blocks"] == 4
    assert found["device_uuids"] == {str(uuid.UUID(bytes=other_dev)): 1}
    context = found["context"]
    assert (context["source"], context["nodesize"], context["csum_name"]) == (
        "inferred", 8192, "sha256",
    )  # fmt: skip
    assert context["generation"] is None
    assert [r.physical for r in records] == [PLANT + i * 8192 for i in range(4)]
    for record in records:
        checks = {c.name: c.ok for c in record.checks}
        assert checks["generation"] is None and checks["csum"] and checks["fsid"]
    assert summary["current_blocks"] == 85 and summary["metadata_uuid_change"] is None


@pytest.mark.sandbox
def test_the_clean_sandbox_has_no_foreign_filesystem(sandbox_img, capsys):
    assert main(["scan", str(sandbox_img), "--foreign"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "foreign: no foreign filesystem found" in lines
    assert main(["scan", str(sandbox_img), "--foreign", "--json"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {r["record"] for r in records} == {"node"}


def flood_patches(fsids):
    """Every sector of the trailing gap header-shaped, with the fsid `fsids` gives for it."""
    start, end = TRAILING_GAP
    for offset in range(start, end, 1 << 20):
        chunk = bytearray()
        for _ in range(256):
            chunk += header_sector(next(fsids))
        yield offset, bytes(chunk)


def measured(path):
    tracemalloc.start()
    try:
        summary, _ = run(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return summary, peak


@pytest.mark.sandbox
def test_a_flood_of_random_fsids_stays_bounded_and_selects_nothing(sandbox_img):
    rng = random.Random(54)
    fsids = iter(lambda: rng.randbytes(16), None)
    sectors = (TRAILING_GAP[1] - TRAILING_GAP[0]) // SECTOR
    with scratch_dir("test_foreign_flood_") as d:
        summary, peak = measured(derived(sandbox_img, d, "random.img", flood_patches(fsids)))
    assert summary["filesystems"] == [] and summary["recurring"] == 0
    assert summary["header_shaped"] == 85 + sectors
    assert summary["fsids_held"] <= CENSUS_SLOTS and summary["undercount"] > 0
    assert peak < BUDGET, f"peak {peak} bytes"


@pytest.mark.sandbox
def test_a_flood_of_one_foreign_fsid_is_validated_within_the_budget(sandbox_img):
    sectors = (TRAILING_GAP[1] - TRAILING_GAP[0]) // SECTOR
    fsids = iter(lambda: OTHER, None)
    with scratch_dir("test_foreign_flood_") as d:
        summary, peak = measured(derived(sandbox_img, d, "one.img", flood_patches(fsids)))
    (found,) = summary["filesystems"]
    assert (found["candidates"], found["valid"], found["census_blocks"]) == (sectors, 0, sectors)
    assert found["context"]["source"] == "none" and found["kind"] == "undetermined"
    assert peak < BUDGET, f"peak {peak} bytes"


@pytest.mark.sandbox
def test_at_most_max_foreign_fsids_are_examined(sandbox_img):
    many = [bytes([7, i, *bytes(14)]) for i in range(MAX_FOREIGN + 3)]
    patches = [
        (TRAILING_GAP[0] + (2 * i + k) * SECTOR, bytes(header_sector(fsid)))
        for i, fsid in enumerate(many)
        for k in range(2)
    ]
    with scratch_dir("test_foreign_many_") as d:
        summary, _ = run(derived(sandbox_img, d, "many.img", patches))
    assert summary["recurring"] == MAX_FOREIGN + 3 and summary["left_out"] == 3
    assert len(summary["filesystems"]) == MAX_FOREIGN
    assert foreign.MIN_BLOCKS == 2
