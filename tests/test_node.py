"""Node reader: per-check validation, bounds-safe parsing and mirror handling (synthetic input)."""

import random
import struct

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.image import open_image
from btrfska.substrate.node import (
    CHECK_NAMES,
    NO_EXPECTATIONS,
    Expect,
    InvalidNode,
    Key,
    NodeContext,
    check_block,
    parse_items,
    parse_key_ptrs,
    read_node,
)
from tests.helpers import (
    CHUNK_TREE_UUID,
    DEV_UUID,
    FSID,
    NODESIZE,
    SANDBOX_INCOMPAT,
    flip,
    make_block,
    make_node,
    node_ctx,
    recsum,
    scratch_dir,
    set_header,
    write_sparse_image,
)

INODE_ITEM = ondisk.ITEM_KEYS["INODE_ITEM"]
INODE_REF = ondisk.ITEM_KEYS["INODE_REF"]
BYTENR = 0x110000
HEADER = ondisk.HEADER.size
ITEMS = [((256, INODE_ITEM, 0), bytes(160)), ((256, INODE_REF, 256), bytes(10) + b"..")]
PTRS = [((256, INODE_ITEM, 0), 0x120000, 7), ((300, INODE_ITEM, 0), 0x130000, 7)]


def leaf(**kw):
    return make_node(BYTENR, items=kw.pop("items", ITEMS), **kw)


def internal(**kw):
    return make_node(BYTENR, level=kw.pop("level", 1), ptrs=kw.pop("ptrs", PTRS), **kw)


def results(block, expect=NO_EXPECTATIONS, ctx=None, logical=BYTENR):
    return {c.name: c.ok for c in check_block(block, ctx or node_ctx(), logical, expect)}


def failed(block, expect=NO_EXPECTATIONS, ctx=None, logical=BYTENR):
    return [name for name, ok in results(block, expect, ctx, logical).items() if ok is False]


def patch_item(block, slot, **fields):
    """Rewrite an item header's offset/size and recompute the checksum."""
    block = bytearray(block)
    base = HEADER + slot * ondisk.ITEM.size
    for name, value in fields.items():
        struct.pack_into("<I", block, base + ondisk.ITEM.offset(name), value)
    return recsum(block)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------
def test_valid_leaf_passes_every_check_in_order():
    expect = Expect(level=0, owner=5, generation=7, first_key=Key(256, INODE_ITEM, 0))
    checks = check_block(leaf(), node_ctx(), BYTENR, expect)
    assert tuple(c.name for c in checks) == CHECK_NAMES
    assert [c.name for c in checks if c.ok is not True] == []


def test_valid_internal_node_passes_every_check():
    expect = Expect(level=1, owner=5, generation=7, first_key=Key(256, INODE_ITEM, 0))
    assert failed(internal(), expect) == []


def test_unknown_expectations_are_recorded_as_not_checked():
    r = results(leaf(), ctx=node_ctx(chunk_tree_uuid=None), logical=None)
    for name in ("bytenr", "chunk_tree_uuid", "owner", "parent_generation", "first_key"):
        assert r[name] is None, name
    assert r["csum"] and r["fsid"] and r["layout"] and r["level"]


def _escaping_item():
    return patch_item(leaf(), 0, offset=NODESIZE)


def _hole_between_items():
    block = leaf()
    offset = struct.unpack_from(
        "<I", block, HEADER + ondisk.ITEM.size + ondisk.ITEM.offset("offset")
    )
    return patch_item(block, 1, offset=offset[0] - 1)


def _item_data_over_item_headers():
    # One item whose data claims the whole leaf data area, overlapping its own item header.
    return make_node(BYTENR, items=[((256, INODE_ITEM, 0), bytes(NODESIZE - HEADER))])


MUTATIONS = [
    pytest.param(lambda: flip(leaf(), NODESIZE - 1), Expect(), ["csum"], id="payload-byte"),
    pytest.param(lambda: flip(leaf(), 1), Expect(), ["csum"], id="csum-byte"),
    pytest.param(
        lambda: set_header(leaf(), bytenr=BYTENR + 4096), Expect(), ["bytenr"], id="bytenr"
    ),
    pytest.param(lambda: leaf(fsid=b"\xff" * 16), Expect(), ["fsid"], id="fsid"),
    pytest.param(
        lambda: leaf(chunk_tree_uuid=b"\xee" * 16), Expect(), ["chunk_tree_uuid"], id="chunk-uuid"
    ),
    pytest.param(lambda: leaf(generation=101), Expect(), ["generation"], id="newer-than-sb"),
    pytest.param(lambda: internal(level=8), Expect(), ["level"], id="level-8"),
    pytest.param(lambda: leaf(), Expect(level=1), ["level"], id="unexpected-level"),
    pytest.param(lambda: leaf(nritems=1000), Expect(), ["nritems"], id="leaf-nritems"),
    pytest.param(lambda: internal(ptrs=[]), Expect(), ["nritems"], id="node-nritems-0"),
    pytest.param(
        lambda: make_node(BYTENR, owner=ondisk.ROOT_TREE_OBJECTID),
        Expect(),
        ["nritems"],
        id="empty-root-tree",
    ),
    pytest.param(lambda: leaf(flags=0), Expect(), ["written"], id="written-flag"),
    pytest.param(lambda: leaf(items=ITEMS[::-1]), Expect(), ["layout"], id="key-order"),
    pytest.param(
        lambda: leaf(items=[ITEMS[0], ITEMS[0]]), Expect(), ["layout"], id="duplicate-key"
    ),
    pytest.param(_escaping_item, Expect(), ["layout"], id="item-escapes-node"),
    pytest.param(_hole_between_items, Expect(), ["layout"], id="item-hole"),
    pytest.param(_item_data_over_item_headers, Expect(), ["layout"], id="data-over-headers"),
    pytest.param(
        lambda: internal(ptrs=[PTRS[1], PTRS[0]]), Expect(), ["layout"], id="node-key-order"
    ),
    pytest.param(
        lambda: internal(ptrs=[PTRS[0], (PTRS[1][0], 0, 7)]), Expect(), ["layout"], id="null-ptr"
    ),
    pytest.param(
        lambda: internal(ptrs=[(PTRS[0][0], 0x120001, 7), PTRS[1]]),
        Expect(),
        ["layout"],
        id="unaligned-ptr",
    ),
    pytest.param(lambda: leaf(owner=5), Expect(owner=2), ["owner"], id="owner-non-fs-tree"),
    pytest.param(lambda: leaf(owner=2), Expect(owner=5), ["owner"], id="owner-not-a-subvolume"),
    pytest.param(lambda: leaf(), Expect(generation=8), ["parent_generation"], id="parent-gen"),
    pytest.param(
        lambda: leaf(), Expect(first_key=Key(257, INODE_ITEM, 0)), ["first_key"], id="first-key"
    ),
]


@pytest.mark.parametrize(("build", "expect", "expected"), MUTATIONS)
def test_each_failure_is_recorded_by_its_own_check(build, expect, expected):
    assert failed(build(), expect) == expected


def test_subvolume_trees_may_share_blocks_owned_by_another_subvolume():
    # kernel tree-checker.c:2247-2297 btrfs_check_eb_owner: fs-tree owners may differ.
    assert failed(leaf(owner=257), Expect(owner=256)) == []
    assert failed(leaf(owner=256), Expect(owner=ondisk.FS_TREE_OBJECTID)) == []
    assert results(leaf(owner=5), Expect(owner=ondisk.TREE_RELOC_OBJECTID))["owner"] is None


LOG = ondisk.TREE_LOG_OBJECTID


def test_log_tree_blocks_carry_exactly_the_superblock_generation_plus_one():
    # The log is written in the running transaction, one past the committed superblock
    # (transaction.c:392-393, extent-tree.c:5306); the kernel reads the log root with
    # transid generation + 1 (disk-io.c:2017-2019). Only a log context accepts it.
    log = Expect(owner=LOG, log=True)
    assert failed(leaf(owner=LOG, generation=101), log) == []
    assert failed(leaf(owner=LOG, generation=100), log) == ["generation"]
    assert failed(leaf(owner=LOG, generation=102), log) == ["generation"]
    assert failed(leaf(owner=LOG, generation=101), Expect(owner=LOG)) == ["generation"]
    checks = {c.name: c for c in check_block(leaf(owner=LOG), node_ctx(), BYTENR, log)}
    assert checks["generation"].detail == (
        "generation 7 != superblock generation + 1 (101), required for a log tree block"
    )


def test_log_tree_blocks_are_owned_by_the_log_tree_objectid():
    # Every log block is allocated with owner BTRFS_TREE_LOG_OBJECTID (-6: btrfs_tree.h:92;
    # disk-io.c:861-867, 887; ctree.c:520). The kernel skips the check (tree-checker.c:2270),
    # btrfska does not.
    log = Expect(owner=LOG, log=True)
    assert failed(leaf(owner=LOG, generation=101), log) == []
    assert failed(leaf(owner=5, generation=101), log) == ["owner"]
    assert failed(leaf(owner=LOG - 1, generation=101), log) == ["owner"]


def test_empty_leaf_of_a_tree_that_may_be_empty_is_valid():
    assert failed(make_node(BYTENR, owner=ondisk.CSUM_TREE_OBJECTID)) == []


def test_level_8_skips_layout_rather_than_guessing():
    block = leaf(nritems=1000)
    assert results(block)["layout"] is None


def test_check_details_name_the_values():
    checks = {c.name: c for c in check_block(leaf(generation=101), node_ctx(), BYTENR, Expect())}
    assert checks["generation"].detail == "generation 101 > superblock generation 100"


def test_check_block_rejects_a_block_of_the_wrong_size():
    with pytest.raises(ValueError, match="nodesize"):
        check_block(leaf()[:-1], node_ctx(), BYTENR, Expect())


def test_context_from_superblock_uses_the_metadata_uuid():
    metadata_uuid = b"\xcc" * 16
    fields = sb.parse_copy(
        make_block(
            fsid=FSID,
            metadata_uuid=metadata_uuid,
            incompat=SANDBOX_INCOMPAT | ondisk.INCOMPAT["METADATA_UUID"],
            csum_type=csum.XXHASH,
            nodesize=NODESIZE,
            generation=100,
        ),
        0,
    ).fields
    ctx = NodeContext.from_superblock(fields, chunk_tree_uuid=CHUNK_TREE_UUID)
    assert ctx.fsid == metadata_uuid and ctx.generation == 100 and ctx.csum_type == csum.XXHASH
    assert failed(leaf(fsid=metadata_uuid), ctx=ctx) == []
    assert failed(leaf(fsid=FSID), ctx=ctx) == ["fsid"]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_items_and_key_pointers_parse_with_the_ondisk_tables():
    items, problems = parse_items(leaf(), NODESIZE)
    assert problems == ()
    assert [(i.slot, i.key, i.size) for i in items] == [
        (0, Key(256, INODE_ITEM, 0), 160),
        (1, Key(256, INODE_REF, 256), 12),
    ]
    assert items[1].data == bytes(10) + b".."
    ptrs, problems = parse_key_ptrs(internal(), NODESIZE)
    assert problems == ()
    assert [(p.key, p.blockptr, p.generation) for p in ptrs] == [
        (Key(256, INODE_ITEM, 0), 0x120000, 7),
        (Key(300, INODE_ITEM, 0), 0x130000, 7),
    ]


def test_parse_items_never_slices_outside_the_node():
    block = patch_item(patch_item(leaf(), 0, offset=0xFFFFFF00, size=0x1000), 1, size=NODESIZE)
    items, problems = parse_items(block, NODESIZE)
    assert items == ()
    assert len(problems) == 2
    items, problems = parse_items(leaf(nritems=0xFFFFFFFF), NODESIZE)
    assert problems and len(items) <= (NODESIZE - HEADER) // ondisk.ITEM.size


def test_random_and_mutated_blocks_never_raise():
    """Property test: garbage and corrupted nodes produce check records, never exceptions."""
    rng = random.Random(20260915)
    ctx = node_ctx()
    bases = [leaf(), internal(), make_node(BYTENR, owner=7)]
    expects = [
        Expect(),
        Expect(level=0, owner=5, generation=7, first_key=Key(256, 1, 0)),
        Expect(level=1, owner=2, generation=9),
    ]
    for round_ in range(900):
        kind = round_ % 3
        if kind == 0:
            block = rng.randbytes(NODESIZE)
        else:
            block = bytearray(rng.choice(bases))
            for _ in range(rng.randint(1, 8)):
                position = rng.choice([rng.randrange(NODESIZE), rng.randrange(HEADER + 200)])
                block[position] = rng.randrange(256)
            if kind == 2:  # get past the csum so the layout checks see the damage
                block = recsum(block)
            block = bytes(block)
        checks = check_block(block, ctx, BYTENR, rng.choice(expects))
        assert tuple(c.name for c in checks) == CHECK_NAMES
        for parsed, problems in (parse_items(block, NODESIZE), parse_key_ptrs(block, NODESIZE)):
            assert isinstance(problems, tuple)
            for entry in parsed:
                data = getattr(entry, "data", b"")
                assert len(data) == getattr(entry, "size", 0)
        if kind == 1 and block not in bases:
            assert any(c.ok is False for c in checks)


# ---------------------------------------------------------------------------
# Reading all physical copies (DUP)
# ---------------------------------------------------------------------------
LOGICAL = 0x100000
PHYSICAL = (0x400000, 0x800000)
IMAGE_SIZE = 16 * 1024**2


def dup_map(devices=None, stripes=PHYSICAL, devids=(1, 1)):
    chunk = Chunk(
        logical=LOGICAL,
        length=0x100000,
        type=ondisk.BLOCK_GROUP_FLAGS["METADATA"] | ondisk.BLOCK_GROUP_FLAGS["DUP"],
        stripes=tuple(Stripe(devid, p, DEV_UUID) for devid, p in zip(devids, stripes, strict=True)),
    )
    return ChunkMap("test", [chunk], {1: DEV_UUID} if devices is None else devices)


def read_copies(blocks, chunk_map=None, logical=LOGICAL, ctx=None):
    with scratch_dir("test_node_") as d:
        path = write_sparse_image(d / "dup.img", IMAGE_SIZE, blocks)
        with open_image(path) as img:
            return read_node(
                img, chunk_map or dup_map(), logical, ctx or node_ctx(), Expect(level=0)
            )


def good(**kw):
    return make_node(LOGICAL, items=ITEMS, **kw)


def test_both_copies_are_validated_and_the_first_valid_one_is_used():
    node = read_copies({PHYSICAL[0]: good(), PHYSICAL[1]: good()})
    assert node.valid and node.chosen == 0
    assert [(c.mirror, c.devid, c.physical, c.ok) for c in node.copies] == [
        (1, 1, PHYSICAL[0], True),
        (2, 1, PHYSICAL[1], True),
    ]
    assert node.problems == ()
    assert [i.key for i in node.items] == [Key(*k) for k, _ in ITEMS]


def test_a_corrupt_first_copy_is_reported_and_the_good_copy_used():
    node = read_copies({PHYSICAL[0]: flip(good(), NODESIZE - 1), PHYSICAL[1]: good()})
    assert node.valid and node.chosen == 1
    assert [c.ok for c in node.copies] == [False, True]
    assert {c.name: c.ok for c in node.copies[0].checks}["csum"] is False
    assert len(node.problems) == 1 and node.problems[0].startswith("mirror 1: csum: stored ")
    assert len(node.items) == 2


def test_all_copies_corrupt_flags_the_node_and_withholds_items():
    node = read_copies({PHYSICAL[0]: flip(good(), 500), PHYSICAL[1]: flip(good(), 600)})
    assert not node.valid and node.chosen is None
    assert [c.ok for c in node.copies] == [False, False]
    assert node.header["bytenr"] == LOGICAL  # reported for provenance only
    assert [p.split(":")[:2] for p in node.problems] == [
        ["mirror 1", " csum"],
        ["mirror 2", " csum"],
    ]
    with pytest.raises(InvalidNode):
        _ = node.items
    with pytest.raises(InvalidNode):
        _ = node.key_ptrs


def test_valid_copies_differing_outside_the_checksum_are_reported():
    # crc32c covers csum[0:4] and bytes 32..; bytes 4..31 of the csum field are unprotected.
    first = good(csum_type=csum.CRC32C)
    second = bytearray(first)
    second[20] = 0x5A
    node = read_copies(
        {PHYSICAL[0]: first, PHYSICAL[1]: bytes(second)}, ctx=node_ctx(csum_type=csum.CRC32C)
    )
    assert node.valid and [c.ok for c in node.copies] == [True, True]
    assert node.problems == ("mirror 2 is valid but differs from mirror 1",)


def test_unmapped_address_is_a_flagged_node_with_no_copies():
    node = read_copies({}, logical=0x5000000)
    assert not node.valid and node.copies == () and node.header is None
    assert "not in any chunk" in node.problems[0]


def test_copy_beyond_the_image_end_and_missing_device_are_unreadable_copies():
    chunk_map = dup_map(stripes=(PHYSICAL[0], IMAGE_SIZE - 100))
    node = read_copies({PHYSICAL[0]: good()}, chunk_map=chunk_map)
    assert node.valid and node.chosen == 0
    assert [(c.name, c.ok) for c in node.copies[1].checks] == [("readable", False)]
    assert "beyond the image end" in node.copies[1].checks[0].detail

    chunk_map = dup_map(devids=(2, 1))
    node = read_copies({PHYSICAL[1]: good()}, chunk_map=chunk_map)
    assert node.chosen == 1
    assert node.copies[0].checks[0].detail == "devid 2 is not available"


def test_header_of_a_garbage_block_is_still_reported():
    node = read_copies({PHYSICAL[0]: bytes(NODESIZE), PHYSICAL[1]: b"\x07" * NODESIZE})
    assert not node.valid
    assert node.header is not None and node.level == 0
    assert FSID not in (node.header["fsid"],)
