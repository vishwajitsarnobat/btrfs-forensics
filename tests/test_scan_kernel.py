"""Scan kernel: strided FSID prefilter, per-candidate validation, mapping and region provenance."""

import json
import random
from contextlib import contextmanager
from dataclasses import asdict

import pytest

from btrfska.scan.kernel_numpy import iter_candidate_nodes, iter_prefilter_hits
from btrfska.scan.regions import Region
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.image import open_image
from btrfska.substrate.node import CHECK_NAMES
from tests.helpers import DEV_UUID, FSID, flip, make_node, node_ctx, scratch_dir, write_sparse_image

MIB = 1 << 20
NODESIZE = 16384
SIZE = 64 * MIB
CTX = node_ctx(nodesize=NODESIZE)
META_LOGICAL, META_PHYS = 1 << 30, 8 * MIB
META_CHUNK = Chunk(
    META_LOGICAL, 16 * MIB, ondisk.BLOCK_GROUP_FLAGS["METADATA"], (Stripe(1, META_PHYS, DEV_UUID),)
)
CHUNK_MAP = ChunkMap("test", [META_CHUNK], {1: DEV_UUID})
WHOLE = (Region(0, SIZE, "test"),)


def node(bytenr, **kw):
    items = [((256, ondisk.ITEM_KEYS["INODE_ITEM"], 0), bytes(160))]
    return make_node(bytenr, items=items, nodesize=NODESIZE, **kw)


def at(physical):
    """A valid node at `physical` whose header bytenr maps there."""
    return node(META_LOGICAL + physical - META_PHYS)


@contextmanager
def image(blocks, size=SIZE):
    with scratch_dir("test_scan_kernel_") as directory:
        with open_image(write_sparse_image(directory / "scan.img", size, blocks)) as img:
            yield img


def scan(blocks, regions=WHOLE, size=SIZE, **kw):
    with image(blocks, size) as img:
        return list(iter_candidate_nodes(img, regions, CTX, CHUNK_MAP, **kw))


def test_nodes_are_found_at_sector_alignment_not_only_nodesize():
    off_grid = META_PHYS + 5 * 4096
    records = scan({META_PHYS: at(META_PHYS), off_grid: at(off_grid)})
    assert [(r.physical, r.bytenr, r.valid, r.maps_here) for r in records] == [
        (META_PHYS, META_LOGICAL, True, True),
        (off_grid, META_LOGICAL + 5 * 4096, True, True),
    ]
    first = records[0]
    assert (first.generation, first.owner, first.level, first.nritems) == (7, 5, 0, 1)
    assert first.region == WHOLE[0] and first.problems == ()


def test_every_check_is_recorded_and_failed_candidates_are_kept():
    (record,) = scan({META_PHYS: flip(at(META_PHYS), NODESIZE - 1)})
    assert tuple(c.name for c in record.checks) == CHECK_NAMES
    results = {c.name: c.ok for c in record.checks}
    assert results["csum"] is False and record.valid is False
    # No referrer: the checks that need one are not run.
    for name in ("bytenr", "owner", "parent_generation", "first_key"):
        assert results[name] is None
    assert results["fsid"] is True and results["layout"] is True


def test_an_fsid_match_with_garbage_after_it_is_a_recorded_invalid_candidate():
    garbage = bytearray(random.Random(7).randbytes(NODESIZE))
    garbage[0x20:0x30] = FSID
    (record,) = scan({12 * MIB: bytes(garbage)})
    assert record.physical == 12 * MIB and record.valid is False
    assert {c.name: c.ok for c in record.checks}["csum"] is False
    assert record.bytenr == int.from_bytes(garbage[0x30:0x38], "little")


def test_other_filesystems_blocks_are_not_candidates():
    assert scan({META_PHYS: node(META_LOGICAL, fsid=bytes(16))}) == []


def test_the_claimed_logical_address_is_checked_against_the_chunk_map():
    elsewhere, unmapped = 2 * MIB, 3 * MIB
    records = scan(
        {META_PHYS: at(META_PHYS), elsewhere: node(META_LOGICAL), unmapped: node(1 << 40)}
    )
    assert [(r.physical, r.bytenr_mapped, r.maps_here) for r in records] == [
        (elsewhere, True, False),
        (unmapped, False, False),
        (META_PHYS, True, True),
    ]
    assert all(r.valid for r in records)  # bytenr is not a check without a referrer


def test_overlapping_unsorted_regions_yield_each_node_once_from_the_first_region():
    regions = [Region(4 * MIB, 20 * MIB, "b"), Region(0, 10 * MIB, "a")]
    blocks = {p: at(p) for p in (2 * MIB, META_PHYS, 16 * MIB)}
    records = scan(blocks, regions)
    assert [(r.physical, r.region.kind) for r in records] == [
        (2 * MIB, "a"),
        (META_PHYS, "a"),
        (16 * MIB, "b"),
    ]


def test_regions_beyond_the_image_are_clipped():
    regions = [Region(60 * MIB, 100 * MIB, "tail"), Region(200 * MIB, 300 * MIB, "beyond")]
    records = scan({62 * MIB: at(62 * MIB)}, regions)
    assert [(r.physical, r.region.kind) for r in records] == [(62 * MIB, "tail")]


def test_a_truncated_final_block_is_recorded_not_dropped():
    size = 16 * MIB
    (record,) = scan({size - 8192: at(size - 8192)[:8192]}, size=size)
    assert record.physical == size - 8192
    assert record.checks == () and record.valid is False
    assert record.generation == 7
    assert record.problems == (f"truncated: {8192} of {NODESIZE} bytes before the image end",)


def test_a_header_cut_by_the_image_end_is_recorded_without_header_fields():
    size = 16 * MIB + 0x40
    (record,) = scan({16 * MIB: bytes(0x20) + FSID + bytes(0x10)}, size=size)
    assert (record.bytenr, record.generation, record.owner, record.level) == (None,) * 4
    assert record.bytenr_mapped is False and record.maps_here is False
    assert record.problems == (f"truncated: {0x40} of {NODESIZE} bytes before the image end",)


def test_an_fsid_cut_by_the_image_end_is_not_a_candidate():
    size = 16 * MIB + 0x28
    assert scan({16 * MIB: bytes(0x20) + FSID[:8]}, size=size) == []


def test_a_node_straddling_a_region_end_belongs_to_the_region_holding_its_header():
    blocks = {META_PHYS: at(META_PHYS)}
    split = [Region(0, META_PHYS + 4096, "head"), Region(META_PHYS + 4096, SIZE, "tail")]
    assert [(r.physical, r.region.kind, r.valid) for r in scan(blocks, split)] == [
        (META_PHYS, "head", True)
    ]
    assert scan(blocks, [Region(0, META_PHYS, "before")]) == []


def test_unaligned_region_starts_round_up_to_the_next_sector():
    blocks = {META_PHYS: at(META_PHYS)}
    assert len(scan(blocks, [Region(META_PHYS - 100, SIZE, "x")])) == 1
    assert scan(blocks, [Region(META_PHYS + 1, SIZE, "x")]) == []


def test_workers_return_the_same_records_in_the_same_order():
    blocks = {p * MIB: at(p * MIB) for p in range(1, 60, 3)}
    blocks[33 * MIB] = flip(at(33 * MIB), 200)
    regions = [Region(0, 30 * MIB, "a"), Region(30 * MIB, SIZE, "b")]
    with image(blocks) as img:
        one = list(iter_candidate_nodes(img, regions, CTX, CHUNK_MAP))
        two = list(iter_candidate_nodes(img, regions, CTX, CHUNK_MAP, workers=2, piece=4 * MIB))
    assert len(one) == len(blocks)
    assert two == one


@pytest.mark.parametrize("workers", [0, 5])
def test_workers_are_bounded(workers):
    with image({}) as img, pytest.raises(ValueError, match="workers"):
        list(iter_candidate_nodes(img, WHOLE, CTX, CHUNK_MAP, workers=workers))


def test_prefilter_hits_are_offsets_with_their_region():
    garbage = bytes(0x20) + FSID + bytes(NODESIZE - 0x30)
    with image({META_PHYS: at(META_PHYS), 12 * MIB: garbage}) as img:
        hits = list(iter_prefilter_hits(img, WHOLE, FSID, 4096))
    assert hits == [(META_PHYS, WHOLE[0]), (12 * MIB, WHOLE[0])]


def test_records_are_json_ready():
    records = scan({META_PHYS: at(META_PHYS), 12 * MIB: flip(at(12 * MIB), 99)})
    assert json.loads(json.dumps([asdict(r) for r in records]))[1]["valid"] is False


def test_the_image_closes_while_an_iteration_is_suspended():
    with image({META_PHYS: at(META_PHYS), 12 * MIB: at(12 * MIB)}) as img:
        iterator = iter_candidate_nodes(img, WHOLE, CTX, CHUNK_MAP)
        assert next(iterator).physical == META_PHYS
    # Closing the image above raises BufferError if a numpy view of the map were still alive.
    assert img.fd == -1
