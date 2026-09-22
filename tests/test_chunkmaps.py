"""Historical chunk maps (plan.md M5a): scan/chunkmaps.py, chunks.MapOrder, the catalog's
`chunk_maps` and `node_maps`, and `recover --maps`.

The rules are tested on forged items; the claims on `s01_discard_none_r1`, whose balance moved
all three chunks, and always relative to the image and its log, never as one build's counts.
"""

import json
import random
import re
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import u64
from btrfska.recover.engine import recover
from btrfska.scan import chunkmaps
from btrfska.scan.chunkmaps import BlockGroup, DevExtent, from_dev_extents, order_for, witnesses
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import (
    Chunk,
    ChunkMap,
    MapOrder,
    MappingError,
    Stripe,
    stripe_size,
)
from btrfska.substrate.extents import read_file
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import Item, Key, NodeReader
from btrfska.substrate.roots import TreeRoot
from tests.helpers import (
    DEV_UUID,
    SCENARIOS,
    make_node,
    node_ctx,
    scratch_dir,
    write_sparse_image,
)
from tests.test_extents import INODE, META_LOGICAL, META_PHYS, inode_item, regular

BG = ondisk.BLOCK_GROUP_FLAGS
K = ondisk.ITEM_KEYS
MIB = 1 << 20
DEVICES = {1: DEV_UUID}
S01 = SCENARIOS / "s01_discard_none_r1.img"
needs_s01 = pytest.mark.skipif(not S01.exists(), reason="corpus image not built (./setup.sh)")


def extent(physical, logical, length=8 * MIB, devid=1, leaf=100, generation=5) -> DevExtent:
    return DevExtent(devid, physical, logical, length, leaf, generation)


def rebuilt(extents, groups=(), num_devices=1) -> ChunkMap:
    return from_dev_extents(
        extents, groups, num_devices=num_devices, devices=DEVICES, sectorsize=4096
    )


# ---------------------------------------------------------------------------
# DEV_EXTENTs: the second witness and the fallback map
# ---------------------------------------------------------------------------


def test_stripe_size_is_what_a_dev_extent_records():
    stripes = tuple(Stripe(i, i * 100 * MIB, DEV_UUID) for i in range(1, 5))
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"], stripes[:1])) == 64 * MIB
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["DUP"], stripes[:2])) == 64 * MIB
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID1C3"], stripes[:3])) == 64 * MIB
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID0"], stripes)) == 16 * MIB
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID10"], stripes, 2)) == 32 * MIB
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID5"], stripes)) == 64 * MIB // 3
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID6"], stripes[:2])) == 0
    assert stripe_size(Chunk(0, 64 * MIB, BG["DATA"] | BG["RAID10"], stripes, 0)) == 0
    assert stripe_size(Chunk(0, 64 * MIB, BG["RAID0"] | BG["DUP"], stripes)) == 0  # forged


def test_dev_extent_items_of_another_size_are_skipped_not_parsed():
    good = struct.pack("<QQQQ16s", 3, 256, 13 * MIB, 8 * MIB, bytes(16))
    items = [
        Item(0, Key(1, K["DEV_EXTENT"], 20 * MIB), 0, len(good), good),
        Item(1, Key(1, K["DEV_EXTENT"], 30 * MIB), 0, len(good) - 1, good[:-1]),
        Item(2, Key(1, K["DEV_ITEM"], 1), 0, len(good), good),
    ]
    assert chunkmaps.parse_dev_extents(items, leaf=7, generation=9) == [
        DevExtent(1, 20 * MIB, 13 * MIB, 8 * MIB, 7, 9)
    ]


def test_a_stripe_is_witnessed_by_each_dev_tree_leaf_that_agrees_with_it():
    chunk = Chunk(13 * MIB, 8 * MIB, BG["DATA"] | BG["DUP"],
                  (Stripe(1, 20 * MIB, DEV_UUID), Stripe(1, 40 * MIB, DEV_UUID)))  # fmt: skip
    chunk_map = ChunkMap("test", [chunk], DEVICES)
    seen = [
        extent(20 * MIB, 13 * MIB, leaf=100),
        extent(20 * MIB, 13 * MIB, leaf=200),
        extent(20 * MIB, 13 * MIB, leaf=200),  # the same leaf twice counts once
        extent(40 * MIB, 13 * MIB, length=4 * MIB),  # another length: not this stripe
        extent(40 * MIB, 99 * MIB),  # names another chunk
        extent(40 * MIB, 13 * MIB, devid=2),  # another device
    ]
    assert witnesses(chunk_map, seen) == {(13 * MIB, 0): 2, (13 * MIB, 1): 0}


def test_one_device_without_block_groups_single_and_dup_are_the_only_possible_profiles():
    found = rebuilt([extent(20 * MIB, 13 * MIB), extent(40 * MIB, 64 * MIB),
                     extent(80 * MIB, 64 * MIB), extent(80 * MIB, 64 * MIB, leaf=9),
                     extent(40 * MIB, 64 * MIB, leaf=9)])  # fmt: skip
    assert found.source == "dev_extents" and not found.rejected
    single, dup = found.chunks
    assert (single.logical, single.length, single.num_stripes) == (13 * MIB, 8 * MIB, 1)
    assert [c.physical for c in found.copies(64 * MIB + 4096, 4096)] == [
        40 * MIB + 4096, 80 * MIB + 4096,
    ]  # fmt: skip
    assert dup.type == BG["DUP"]


@pytest.mark.parametrize(
    ("extents", "groups", "num_devices", "reason"),
    [
        ([extent(20 * MIB, 13 * MIB), extent(40 * MIB, 13 * MIB, length=4 * MIB)], [], 1,
         "different lengths"),
        ([extent(20 * MIB, 13 * MIB), extent(24 * MIB, 13 * MIB)], [], 1, "overlap"),
        ([extent(20 * MIB, 13 * MIB), extent(40 * MIB, 13 * MIB), extent(60 * MIB, 13 * MIB)],
         [], 1, "address was reused"),
        ([extent(20 * MIB, 13 * MIB)], [], 2, "profile is unknown"),
        ([extent(20 * MIB, 13 * MIB), extent(40 * MIB, 13 * MIB, devid=2)],
         [BlockGroup(13 * MIB, 16 * MIB, BG["DATA"] | BG["RAID0"], 5)], 2, "stripe order"),
        ([extent(20 * MIB, 13 * MIB)],
         [BlockGroup(13 * MIB, 8 * MIB, BG["DATA"] | BG["RAID5"], 5)], 2, "stripe order"),
        ([extent(20 * MIB, 13 * MIB), extent(40 * MIB, 13 * MIB)],
         [BlockGroup(13 * MIB, 8 * MIB, BG["DATA"], 5)], 1, "address was reused"),
        ([extent(20 * MIB, 13 * MIB)], [BlockGroup(13 * MIB, 16 * MIB, BG["DATA"], 5)], 1,
         "block group length"),
        ([extent(20 * MIB, 13 * MIB)],
         [BlockGroup(13 * MIB, 8 * MIB, BG["DATA"] | BG["RAID0"] | BG["DUP"], 5)], 1,
         "not one profile"),
        ([extent(20 * MIB, 13 * MIB, length=0)], [], 1, "not aligned"),
        ([extent(20 * MIB, 13 * MIB + 1)], [], 1, "not aligned"),
        ([extent(20 * MIB, 13 * MIB, length=1 << 63)], [], 1, "overflows"),
        ([extent(20 * MIB, (1 << 64) - 4096, length=8192)], [], 1, "overflows"),
    ],
)  # fmt: skip
def test_what_dev_extents_cannot_settle_is_rejected_with_the_reason(
    extents, groups, num_devices, reason
):
    found = rebuilt(extents, groups, num_devices)
    assert not found.chunks
    (chunk,) = found.rejected
    assert any(reason in problem for problem in chunk.problems), chunk.problems
    with pytest.raises(MappingError):
        found.copies(chunk.logical, 4096)


def test_two_extents_for_one_address_that_no_leaf_holds_together_are_not_mirrors():
    """A SINGLE chunk at L lived at P1, was balanced away, and a later chunk at L lives at P2:
    two dev-tree leaves of different generations each hold one extent. Not a DUP chunk."""
    apart = [extent(20 * MIB, 13 * MIB, leaf=100, generation=10),
             extent(40 * MIB, 13 * MIB, leaf=200, generation=50)]  # fmt: skip
    found = rebuilt(apart)
    assert not found.chunks
    (chunk,) = found.rejected
    assert any("had this address at different times" in p for p in chunk.problems)
    # the same two extents in one leaf are the two copies of a DUP chunk
    together = [extent(20 * MIB, 13 * MIB, leaf=300), extent(40 * MIB, 13 * MIB, leaf=300)]
    assert rebuilt(together).chunks[0].type == BG["DUP"]
    # and a block group naming DUP does not make the apart pair mirrors either
    group = [BlockGroup(13 * MIB, 8 * MIB, BG["DATA"] | BG["DUP"], 50)]
    assert not rebuilt(apart, group).chunks


def test_a_mirrored_block_group_is_accepted_with_the_newest_item_and_even_with_one_copy_found():
    groups = [
        BlockGroup(13 * MIB, 4 * MIB, BG["DATA"], 3),  # an older item of the address: not used
        BlockGroup(13 * MIB, 8 * MIB, BG["METADATA"] | BG["RAID1"], 9),
    ]
    found = rebuilt([extent(20 * MIB, 13 * MIB)], groups, num_devices=2)
    (chunk,) = found.chunks
    assert chunk.type == BG["METADATA"] | BG["RAID1"] and "generation 9" in chunk.origin
    assert [c.physical for c in found.copies(13 * MIB, 4096)] == [20 * MIB]


def test_a_stripe_on_a_device_the_image_does_not_hold_is_a_missing_device_not_a_read():
    found = rebuilt(
        [extent(20 * MIB, 13 * MIB, devid=7)], [BlockGroup(13 * MIB, 8 * MIB, BG["DATA"], 5)], 2
    )
    (copy,) = found.copies(13 * MIB, 4096)
    assert copy.missing_device


def test_forged_dev_extents_and_block_groups_never_raise():
    rng = random.Random(7)
    values = [0, 1, 4095, 4096, 8 * MIB, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
    for _ in range(300):
        extents = [
            DevExtent(rng.choice([0, 1, 2, 1 << 40]), rng.choice(values), rng.choice(values),
                      rng.choice(values), rng.randrange(4), rng.randrange(9))
            for _ in range(rng.randrange(1, 9))
        ]  # fmt: skip
        groups = [
            BlockGroup(
                rng.choice(values), rng.choice(values), rng.getrandbits(64), rng.randrange(9)
            )
            for _ in range(rng.randrange(4))
        ]
        found = rebuilt(extents, groups, num_devices=rng.choice([1, 2]))
        witnesses(found, extents)
        for chunk in found.chunks:  # whatever was accepted can be used without an error
            found.copies(chunk.logical, 4096)


# ---------------------------------------------------------------------------
# The order of maps, and what a read says about it
# ---------------------------------------------------------------------------


def named(name, generation):
    return (name, generation, ChunkMap(name, [], DEVICES))


def test_a_state_reads_through_its_own_map_then_through_the_newer_ones_oldest_first():
    maps = [named("current", 38), named("h30", 30), named("h17", 17), named("h6", 6)]
    assert [m.source for m in order_for(20, "h17", maps)] == ["h17", "h30", "current"]
    assert [m.source for m in order_for(38, "current", maps)] == ["current"]
    # a lone leaf has no map of its own: the newest map not newer than the leaf stands in
    assert [m.source for m in order_for(29, None, maps)] == ["h17", "h30", "current"]
    assert [m.source for m in order_for(3, None, maps)] == ["h6", "h17", "h30", "current"]
    assert order_for(3, None, []) == []


OLD_DATA, NEW_DATA = 4 * MIB, 40 * MIB
DATA_LOGICAL = 2 << 30


def reader_with(img, *maps, fallback=()):
    return NodeReader(img, MapOrder(maps, fallback), node_ctx())


def data_map(name, logical=DATA_LOGICAL, physical=OLD_DATA, length=8 * MIB):
    meta = Chunk(META_LOGICAL, 2 * MIB, BG["METADATA"], (Stripe(1, META_PHYS, DEV_UUID),))
    chunks = [meta]
    if physical is not None:
        chunks.append(Chunk(logical, length, BG["DATA"], (Stripe(1, physical, DEV_UUID),)))
    return ChunkMap(name, chunks, DEVICES)


@pytest.fixture
def image():
    items = [
        ((INODE, K["INODE_ITEM"], 0), inode_item(8192)),
        ((INODE, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, 8192, 0, 8192)),
    ]
    leaf = make_node(META_LOGICAL, items=items, owner=ondisk.FS_TREE_OBJECTID, generation=7)
    with scratch_dir("test_chunkmaps_") as directory:
        blocks = {META_PHYS: leaf, OLD_DATA: b"old!" * 2048, NEW_DATA: b"new!" * 2048}
        path = write_sparse_image(directory / "fs.img", 128 * MIB, blocks)
        with open_image(path) as img:
            yield img


ROOT = TreeRoot(ondisk.FS_TREE_OBJECTID, META_LOGICAL, 0, 7, "test")


def test_the_first_map_that_places_the_extent_is_used_and_named(image):
    own, current = data_map("historical:7@1"), data_map("current", physical=None)
    result = read_file(reader_with(image, own, current), ROOT, INODE, no_holes=True)
    assert result.complete and b"".join(result.chunks()) == b"old!" * 2048
    (record,) = result.extents
    assert record.chunk_map == "historical:7@1" and record.problems == ()


def test_an_extent_the_own_map_does_not_place_falls_to_a_newer_map_and_says_so(image):
    own = data_map("historical:7@1", physical=None)
    newer, current = data_map("historical:9@2"), data_map("current", physical=None)
    result = read_file(reader_with(image, own, newer, current), ROOT, INODE, no_holes=True)
    (record,) = result.extents
    assert result.complete and record.chunk_map == "historical:9@2"
    assert any("not placed by the historical:7@1 chunk map" in p for p in record.problems)


def test_the_dev_extents_map_comes_last(image):
    own, current = data_map("historical:7@1", physical=None), data_map("current", physical=None)
    last = data_map("dev_extents", physical=NEW_DATA)
    result = read_file(reader_with(image, own, current, fallback=[last]), ROOT, INODE,
                       no_holes=True)  # fmt: skip
    assert b"".join(result.chunks()) == b"new!" * 2048
    assert result.extents[0].chunk_map == "dev_extents"


def test_no_map_places_it_the_failure_names_every_map_tried(image):
    maps = [data_map(n, physical=None) for n in ("historical:7@1", "current")]
    result = read_file(reader_with(image, *maps), ROOT, INODE, no_holes=True)
    (record,) = result.extents
    assert not result.complete and record.error_kind == "unmapped"
    assert record.chunk_map == "historical:7@1" and "nor by current" in record.error_detail


def test_a_reused_logical_address_is_reported_and_the_states_own_map_is_still_the_one_used(image):
    own, current = data_map("historical:7@1"), data_map("current", physical=NEW_DATA)
    result = read_file(reader_with(image, own, current), ROOT, INODE, no_holes=True)
    (record,) = result.extents
    assert b"".join(result.chunks()) == b"old!" * 2048 and record.chunk_map == "historical:7@1"
    assert any("the address was reused" in p for p in record.problems)


def test_disk_space_a_newer_map_gave_out_again_is_reported_as_possibly_overwritten(image):
    own = data_map("historical:7@1")
    current = data_map("current", logical=3 << 30, physical=OLD_DATA - MIB, length=2 * MIB)
    result = read_file(reader_with(image, own, current), ROOT, INODE, no_holes=True)
    (record,) = result.extents
    assert result.complete  # every byte was read; whether they are the file's is another matter
    assert any("may have been overwritten" in p for p in record.problems)
    # the same chunk in a newer map is not a reuse
    same = read_file(reader_with(image, own, data_map("current")), ROOT, INODE, no_holes=True)
    assert same.extents[0].problems == ()


def test_an_unreadable_copy_under_the_own_map_does_not_fall_through_to_another_map(image):
    own = data_map("historical:7@1", physical=image.size - 4096)  # the extent ends past the image
    current = data_map("current", physical=NEW_DATA)
    result = read_file(reader_with(image, own, current), ROOT, INODE, no_holes=True)
    (record,) = result.extents
    assert record.error_kind == "unreadable" and record.chunk_map == "historical:7@1"


# ---------------------------------------------------------------------------
# s01: a full balance, three of three chunks relocated
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def s01():
    with scratch_dir("test_chunkmaps_s01_") as directory:
        build_catalog(S01, directory / "evidence.db", full_sweep=True)
        yield directory


def stored_map(conn, map_id) -> ChunkMap:
    chunks = []
    for row in conn.execute("SELECT * FROM chunks WHERE map_id = ? AND accepted", (map_id,)):
        stripes = tuple(
            Stripe(u64(s["devid"]), u64(s["physical"]), bytes.fromhex(s["dev_uuid"]))
            for s in conn.execute(
                "SELECT * FROM stripes WHERE chunk_id = ? ORDER BY stripe_index", (row["chunk_id"],)
            )
        )
        chunks.append(
            Chunk(u64(row["logical"]), u64(row["length"]), u64(row["type"]), stripes,
                  row["sub_stripes"])
        )  # fmt: skip
    devices = {s.devid: s.dev_uuid for c in chunks for s in c.stripes}
    return ChunkMap(str(map_id), chunks, devices)


@needs_s01
def test_the_current_map_is_stored_as_the_filesystem_gives_it_whatever_else_was_found(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    with open_image(S01) as img:
        current = open_filesystem(img).chunk_map
    (row,) = conn.execute("SELECT map_id, name FROM chunk_maps WHERE kind = 'current'").fetchall()
    assert tuple(row) == (1, "current")
    stored = stored_map(conn, 1)
    assert [(c.logical, c.length, c.type, c.stripes) for c in stored.chunks] == [
        (c.logical, c.length, c.type, c.stripes) for c in current.chunks
    ]


@needs_s01
def test_every_chunk_root_the_scan_found_is_a_map_and_every_state_names_its_own(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    roots = {
        (r["bytenr"], r["generation"])
        for r in conn.execute(
            "SELECT bytenr, generation FROM content_blocks b WHERE owner = 3 AND NOT EXISTS"
            " (SELECT 1 FROM key_ptrs k WHERE k.blockptr = b.bytenr"
            "  AND k.ptr_generation = b.generation)"
        )
    }
    maps = {
        (r["root_bytenr"], r["root_generation"]): r["map_id"]
        for r in conn.execute("SELECT * FROM chunk_maps WHERE kind != 'dev_extents'")
    }
    assert set(maps) == roots and len(maps) > 1
    for state in conn.execute("SELECT * FROM states"):
        key = (state["chunk_root_bytenr"], state["chunk_root_generation"])
        assert state["map_id"] == maps[key]
        assert (state["map_id"] != 1) == bool(state["chunk_root_differs"])
    assert not conn.execute("SELECT 1 FROM problems WHERE source = 'chunk_maps'").fetchall()


@needs_s01
def test_the_balance_left_maps_that_name_chunks_the_current_map_no_longer_has(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    current = {r[0] for r in conn.execute("SELECT logical FROM chunks WHERE map_id = 1")}
    older = {
        r[0] for r in conn.execute(
            "SELECT logical FROM chunks JOIN chunk_maps USING (map_id)"
            " WHERE kind = 'historical' AND accepted"
        )
    }  # fmt: skip
    assert older - current  # the relocated chunks
    assert min(older - current) < min(current)


@needs_s01
def test_node_maps_holds_exactly_the_placements_the_stored_chunks_give(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    nodesize = conn.execute("SELECT nodesize FROM scan_runs").fetchone()[0]
    maps = {
        r["map_id"]: stored_map(conn, r["map_id"])
        for r in conn.execute("SELECT map_id FROM chunk_maps WHERE kind != 'current'")
    }
    expected = set()
    outside = conn.execute("SELECT * FROM nodes WHERE valid AND NOT maps_here").fetchall()
    for node in outside:
        for map_id, chunk_map in maps.items():
            try:
                copies = chunk_map.copies(u64(node["bytenr"]), nodesize)
            except MappingError:
                continue
            if any(copy.physical == node["physical"] for copy in copies):
                expected.add((node["node_id"], map_id))
    stored = {tuple(r) for r in conn.execute("SELECT node_id, map_id FROM node_maps")}
    assert stored == expected
    # every valid block of a removed chunk lies where some older map says it should
    assert outside and {node["node_id"] for node in outside} == {n for n, _ in stored}


@needs_s01
def test_stripe_witness_counts_equal_a_recount_from_the_stored_dev_extent_items(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    leaves: dict[tuple, set] = {}
    query = (
        "SELECT i.key_objectid, i.key_offset, i.data, b.bytenr FROM items i"
        " JOIN content_blocks b USING (content_id) WHERE i.key_type = 204 AND b.owner = 4"
    )
    for devid, physical, data, leaf in conn.execute(query):
        fields = ondisk.DEV_EXTENT.unpack_from(data)
        key = (u64(devid), u64(physical), fields["chunk_offset"], fields["length"])
        leaves.setdefault(key, set()).add(leaf)
    rows = conn.execute(
        "SELECT s.devid, s.physical, c.logical, c.length, s.dev_extents FROM stripes s"
        " JOIN chunks c USING (chunk_id)"
    ).fetchall()
    assert rows
    for devid, physical, logical, length, count in rows:  # SINGLE and DUP only on this image
        assert count == len(leaves.get((u64(devid), u64(physical), u64(logical), u64(length)), ()))
    assert all(row["dev_extents"] for row in rows)


@needs_s01
def test_the_map_from_dev_extents_alone_translates_like_the_chunk_item_maps(s01):
    conn = db.open_readonly(s01 / "evidence.db")
    (last,) = conn.execute("SELECT map_id FROM chunk_maps WHERE kind = 'dev_extents'").fetchall()
    alone = {c.logical: c for c in stored_map(conn, last[0]).chunks}
    known = {}
    for row in conn.execute("SELECT map_id FROM chunk_maps WHERE kind != 'dev_extents'"):
        for chunk in stored_map(conn, row[0]).chunks:
            known.setdefault(chunk.logical, set()).add(
                (chunk.length, tuple(sorted((s.devid, s.offset) for s in chunk.stripes)))
            )
    assert set(alone) == set(known)  # on this image every chunk is known both ways
    for logical, chunk in alone.items():
        placement = (chunk.length, tuple(sorted((s.devid, s.offset) for s in chunk.stripes)))
        assert known[logical] == {placement}


@needs_s01
def test_a_bound_on_the_maps_that_bites_is_reported_and_keeps_the_maps_the_superblock_names():
    with scratch_dir("test_chunkmaps_bound_") as directory:
        build_catalog(S01, directory / "evidence.db", max_maps=1)
        conn = db.open_readonly(directory / "evidence.db")
        maps = conn.execute("SELECT * FROM chunk_maps WHERE kind = 'historical'").fetchall()
        (problem,) = conn.execute("SELECT detail FROM problems WHERE source = 'chunk_maps'")
        assert len(maps) == 1 and json.loads(maps[0]["known_as"])  # a backup slot names it
        assert "only 1 built" in problem[0]
        # a state whose map was not built has none, and says so by being NULL
        assert conn.execute(
            "SELECT COUNT(*) FROM states WHERE chunk_root_differs AND map_id IS NULL"
        ).fetchone()[0]


@pytest.fixture(scope="module")
def s01_recovered(s01):
    runs = {}
    for maps in ("current", "own"):
        done = recover(S01, s01 / "evidence.db", s01 / f"out_{maps}", roots=("all",),
                       tree_id=None, maps=maps)  # fmt: skip
        runs[maps] = done.recovery_id
    return runs


def logged_hashes() -> dict[str, str]:
    found = re.findall(r"([0-9a-f]{64})\s+/mnt/sv1/(\S+)", S01.with_suffix(".log").read_text())
    return {name: digest for digest, name in found}


def files_of(conn, recovery_id):
    rows = conn.execute(
        "SELECT * FROM artifacts WHERE recovery_id = ? AND kind = 'file'", (recovery_id,)
    ).fetchall()
    return {(r["state_id"], r["tree_id"], r["objectid"], r["inode_generation"]): r for r in rows}


@needs_s01
def test_files_of_pre_balance_states_come_back_complete_and_equal_to_the_logged_hashes(
    s01, s01_recovered
):
    conn = db.open_readonly(s01 / "evidence.db")
    truth = logged_hashes()
    before, after = (files_of(conn, s01_recovered[m]) for m in ("current", "own"))
    assert before.keys() == after.keys()
    unmapped = {
        key
        for key, row in before.items()
        if row["status"] == "partial"
        and any(reason == "unmapped" for _, _, reason in json.loads(row["missing"]))
    }
    assert unmapped  # the current map cannot place what the balance moved
    for key in unmapped:
        row = after[key]
        assert row["status"] in ("complete", "duplicate"), dict(row)
        if row["status"] == "duplicate":
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (row["duplicate_of"],)
            ).fetchone()
        name = row["path"].rsplit("/", 1)[-1]
        assert name in truth and row["sha256"] == truth[name]
        maps = json.loads(row["chunk_maps"])
        assert maps and all(m.startswith("historical:") for m in maps)
    # nothing else changed: what the current map could read is read the same way
    for key in before.keys() - unmapped:
        assert (before[key]["status"], before[key]["sha256"]) == (
            after[key]["status"], after[key]["sha256"],
        )  # fmt: skip
    assert not [r for r in after.values() if r["status"] == "partial"]


@needs_s01
def test_every_extent_read_names_its_map_and_the_map_gives_the_offsets_that_were_read(
    s01, s01_recovered
):
    conn = db.open_readonly(s01 / "evidence.db")
    names = {r["name"]: r["map_id"] for r in conn.execute("SELECT * FROM chunk_maps")}
    rows = conn.execute(
        "SELECT p.read_record, a.chunk_maps FROM provenance p JOIN artifacts a USING (artifact_id)"
        " WHERE a.recovery_id = ? AND p.role = 'extent_data' AND p.read_record IS NOT NULL",
        (s01_recovered["own"],),
    ).fetchall()
    historical = 0
    for row in rows:
        record = json.loads(row["read_record"])
        if not record["ranges"]:
            continue  # inline data and holes go through no map
        assert record["chunk_map"] in json.loads(row["chunk_maps"])
        chunk_map = stored_map(conn, names[record["chunk_map"]])
        historical += record["chunk_map"] != "current"
        for piece in record["ranges"]:
            copies = chunk_map.copies(piece["logical"], piece["length"])
            assert [c.physical for c in copies] == [c["physical"] for c in piece["copies"]]
    assert historical


@needs_s01
def test_the_current_root_is_read_through_the_current_map_alone(s01, s01_recovered):
    conn = db.open_readonly(s01 / "evidence.db")
    rows = conn.execute(
        "SELECT a.chunk_maps FROM artifacts a JOIN states s USING (state_id)"
        " WHERE a.recovery_id = ? AND s.map_id = 1",
        (s01_recovered["own"],),
    ).fetchall()
    assert rows and {r[0] for r in rows} <= {"[]", '["current"]'}
