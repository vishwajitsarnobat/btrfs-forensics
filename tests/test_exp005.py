"""experiments/exp005.py: the slack range, its measurement, the pairing, and the claim itself.

The claim is checked against the image it is read from: on `m3_wide`, no block newer than the
generation the pinned mkfs leaves behind has a non-zero slack byte. That generation is measured
here from a never-mounted image; it is not a constant of this file.
"""

import struct
import subprocess

import pytest

from btrfska.substrate import ondisk
from experiments import exp005
from tests.helpers import NODESIZE, SCENARIOS, make_node, scratch_dir

HEADER = ondisk.HEADER.size
INODE = (257, 1, 0)


def test_leaf_slack_lies_between_the_item_array_and_the_lowest_item_data():
    block = make_node(0x100000, items=[(INODE, b"a" * 160), ((257, 12, 256), b"b" * 20)])
    assert exp005.slack_range(block, NODESIZE) == (HEADER + 2 * 25, NODESIZE - 180)


def test_an_empty_leaf_is_all_slack_after_the_header():
    assert exp005.slack_range(make_node(0x100000), NODESIZE) == (HEADER, NODESIZE)


def test_internal_node_slack_runs_from_the_last_key_pointer_to_the_end_of_the_block():
    ptrs = [((256 + i, 1, 0), 0x200000 + i * NODESIZE, 7) for i in range(3)]
    block = make_node(0x100000, level=1, ptrs=ptrs)
    assert exp005.slack_range(block, NODESIZE) == (HEADER + 3 * 33, NODESIZE)


def test_a_block_as_the_kernel_writes_it_has_no_non_zero_slack():
    block = make_node(0x100000, items=[(INODE, b"a" * 160)])
    row = exp005.measure_slack(block, NODESIZE)
    assert row["nonzero"] == 0 and row["slack_len"] == NODESIZE - HEADER - 25 - 160
    assert "sample_hex" not in row


def test_a_stale_item_header_beyond_nritems_is_counted_and_decoded():
    """What mkfs leaves behind: a leaf of two items whose header says one."""
    items = [(INODE, b"a" * 160), ((257, 12, 256), b"b" * 20)]
    block = make_node(0x100000, items=items, nritems=1)
    row = exp005.measure_slack(block, NODESIZE)
    assert row["slack_start"] == HEADER + 25
    assert row["first_nonzero"] == HEADER + 25
    assert row["last_nonzero"] == NODESIZE - 160 - 1  # the stale item's data is slack too
    assert row["stale_headers"] == [[257, 12, 256, NODESIZE - HEADER - 180, 20]]


def test_stale_headers_stop_at_the_first_all_zero_slot_and_skip_internal_nodes():
    block = bytearray(make_node(0x100000, items=[(INODE, b"a" * 160)]))
    struct.pack_into(ondisk.ITEM.format, block, HEADER + 3 * 25, 300, 1, 0, 9000, 160)
    start, end = exp005.slack_range(block, NODESIZE)
    assert exp005.stale_headers(block, start, end) == []  # slot 1 is zero: nothing is read
    node = make_node(0x100000, level=1, ptrs=[((256, 1, 0), 0x200000, 7)])
    assert exp005.stale_headers(node, *exp005.slack_range(node, NODESIZE)) == []


def test_a_hostile_leaf_gives_a_range_inside_the_block():
    block = bytearray(make_node(0x100000, items=[(INODE, b"a" * 160)]))
    struct.pack_into("<I", block, ondisk.HEADER.offset("nritems"), 0xFFFFFFFF)
    start, end = exp005.slack_range(block, NODESIZE)
    assert 0 <= start <= NODESIZE and 0 <= end <= NODESIZE
    assert exp005.measure_slack(block, NODESIZE)["slack_len"] == max(0, end - start)


def _block(bytenr, generation, nonzero=0, status="unreferenced", key=INODE, level=0, owner=5):
    return {
        "bytenr": bytenr,
        "generation": generation,
        "nonzero": nonzero,
        "status": status,
        "first_key": list(key) if key else None,
        "level": level,
        "owner": owner,
    }


def test_blocks_of_one_tree_level_and_first_key_are_paired_generation_by_generation():
    blocks = [_block(300, 9, status="live"), _block(100, 7, nonzero=4), _block(200, 8)]
    pairs = exp005.pair_up(blocks)
    assert [(p["older"], p["newer"], p["live_ended"]) for p in pairs] == [
        ([100, 7, 4], [200, 8, 0], False),
        ([200, 8, 0], [300, 9, 0], True),
    ]


def test_blocks_of_another_tree_level_or_key_and_empty_blocks_are_not_paired():
    blocks = [
        _block(100, 7),
        _block(200, 8, owner=7),
        _block(300, 8, level=1),
        _block(400, 8, key=(258, 1, 0)),
        _block(500, 8, key=None),
        _block(600, 7),  # the same generation as the first: a sibling, not a successor
    ]
    assert exp005.pair_up(blocks) == []


def test_count_splits_writers_at_the_mkfs_generation():
    record = {
        "classes": [
            ["leaf", "live", "inside", 6, "blocks", 3],
            ["leaf", "live", "inside", 6, "with_nonzero", 2],
            ["leaf", "unreferenced", "outside", 9, "blocks", 5],
            ["internal", "live", "inside", 9, "blocks", 1],
        ]
    }
    assert exp005.count(record, "blocks") == 9
    assert exp005.count(record, "blocks", 6, writer="mkfs") == 3
    assert exp005.count(record, "blocks", 6, writer="kernel", kind="leaf") == 5
    assert exp005.count(record, "with_nonzero", 6, writer="kernel") == 0


def test_the_pinned_controls_must_agree_on_one_generation():
    records = {
        "control_pinned_a.img": {"control": True, "superblock_generation": 6},
        "control_pinned_b.img": {"control": True, "superblock_generation": 6},
        "control_host_default.img": {"control": True, "superblock_generation": 8},
    }
    assert exp005.pinned_mkfs_generation(records) == 6
    records["control_pinned_b.img"]["superblock_generation"] = 7
    with pytest.raises(SystemExit):
        exp005.pinned_mkfs_generation(records)


def test_on_m3_wide_only_mkfs_written_blocks_have_non_zero_slack():
    image = SCENARIOS / "m3_wide.img"
    if not image.exists():
        pytest.skip("m3_wide.img absent: build it with corpus/build.py")
    if subprocess.run(
        [str(exp005.PINNED), "mkfs.btrfs", "--version"], capture_output=True
    ).returncode:
        pytest.skip("the pinned mkfs.btrfs is absent: run corpus/vm/fetch_vm.sh")
    with scratch_dir("test_exp005_") as tmp:
        control = tmp / "control.img"
        subprocess.run(["truncate", "-s", "512M", str(control)], check=True)
        subprocess.run(
            [str(exp005.PINNED), "mkfs.btrfs", "-q", "-f", "--csum", "xxhash", str(control)],
            check=True,
        )
        never_mounted = exp005.measure(control)
    mkfs_generation = never_mounted["superblock_generation"]
    # mkfs does leave stale content behind, or this test would prove nothing about the kernel
    assert never_mounted["nonzero_blocks"]

    record = exp005.measure(image)
    assert record["superblock_generation"] > mkfs_generation
    assert all(b["generation"] <= mkfs_generation for b in record["nonzero_blocks"])
    kernel_leaves = exp005.count(record, "blocks", mkfs_generation, writer="kernel", kind="leaf")
    kernel_nodes = exp005.count(record, "blocks", mkfs_generation, writer="kernel", kind="internal")
    assert kernel_leaves > 0 and kernel_nodes > 0
    assert exp005.count(record, "nonzero_bytes", mkfs_generation, writer="kernel") == 0
    kernel_pairs = [p for p in record["pairs"] if p["older"][1] > mkfs_generation]
    assert any(p["level"] > 0 for p in kernel_pairs) and any(p["level"] == 0 for p in kernel_pairs)
    assert not any(p["older"][2] or p["newer"][2] for p in kernel_pairs)
