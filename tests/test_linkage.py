"""Integrity and linkage checks (plan.md M5b): node.check_integrity, node.check_linkage,
read_node(linkage=), tree.walk(linkage=), `walk --linkage`, and what a recovery gap says.

Integrity: is this a well-formed block of this filesystem? Linkage: is it the block the referrer
meant? The kernel's verdict needs both and is unchanged; `report` adds the blocks that are sound
but not the ones their parent named, flagged, and never those that fail an integrity check.
"""

import json
import random
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.cli import main
from btrfska.recover.dbtree import Root, tree_leaves
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import (
    CHECK_NAMES,
    INTEGRITY_CHECKS,
    LINKAGE_CHECKS,
    NO_EXPECTATIONS,
    Expect,
    Key,
    NodeReader,
    check_block,
    check_integrity,
    check_linkage,
    read_node,
)
from btrfska.substrate.roots import RootNotFound, resolve_tree, root_sets
from btrfska.substrate.tree import leaf_items, walk
from tests.helpers import (
    DEV_UUID,
    SCENARIOS,
    flip,
    make_node,
    node_ctx,
    recsum,
    scratch_dir,
    write_sparse_image,
)

INODE_ITEM = ondisk.ITEM_KEYS["INODE_ITEM"]
MIB = 1 << 20
LOGICAL, PHYSICAL, MIRROR = 0x110000, 1 * MIB, 3 * MIB
ITEMS = [((256, INODE_ITEM, 0), bytes(160)), ((257, INODE_ITEM, 0), bytes(160))]
MEANT = Expect(level=0, owner=5, generation=7, first_key=Key(256, INODE_ITEM, 0))
CORPUS = ["m2_logtree", "m3_wide", "m4_deep", "s01_discard_none_r1", "m1_xxhash"]


def reader_of(img, stripes=((1, PHYSICAL),)) -> NodeReader:
    chunk = Chunk(LOGICAL, 2 * MIB, ondisk.BLOCK_GROUP_FLAGS["METADATA"],
                  tuple(Stripe(d, p, DEV_UUID) for d, p in stripes))  # fmt: skip
    return NodeReader(img, ChunkMap("test", [chunk], {1: DEV_UUID}), node_ctx())


def read(block, expect=MEANT, linkage="report", mirror=None):
    blocks = {PHYSICAL: block} | ({MIRROR: mirror} if mirror is not None else {})
    stripes = ((1, PHYSICAL), (1, MIRROR)) if mirror is not None else ((1, PHYSICAL),)
    with scratch_dir("test_linkage_") as directory:
        with open_image(write_sparse_image(directory / "n.img", 8 * MIB, blocks)) as img:
            reader = reader_of(img, stripes)
            return read_node(img, reader.chunk_map, LOGICAL, reader.ctx, expect, linkage)


# ---------------------------------------------------------------------------
# The partition
# ---------------------------------------------------------------------------


def test_every_check_is_an_integrity_or_a_linkage_check_and_only_level_is_both():
    assert set(INTEGRITY_CHECKS) | set(LINKAGE_CHECKS) == set(CHECK_NAMES)
    assert set(INTEGRITY_CHECKS) & set(LINKAGE_CHECKS) == {"level"}
    assert LINKAGE_CHECKS == ("level", "owner", "parent_generation", "first_key")


def test_check_block_is_the_two_halves_merged_with_the_impossible_level_first():
    rng = random.Random(5)
    ctx = node_ctx()
    for _ in range(400):
        level = rng.choice([0, 1, 7, 8, 255])
        kwargs = {"items": ITEMS} if level == 0 else {"ptrs": [((256, 1, 0), 0x120000, 7)]}
        block = make_node(LOGICAL, level=level, owner=rng.choice([1, 5, 256]),
                          generation=rng.choice([7, 101]), **kwargs)  # fmt: skip
        if rng.random() < 0.3:
            block = flip(block, rng.randrange(len(block)))
        expect = Expect(rng.choice([None, 0, 1, 8]), rng.choice([None, 1, 5]),
                        rng.choice([None, 7, 9]), rng.choice([None, Key(256, INODE_ITEM, 0)]),
                        rng.random() < 0.2)  # fmt: skip
        logical = rng.choice([None, LOGICAL, LOGICAL + 4096])
        whole = {c.name: c for c in check_block(block, ctx, logical, expect)}
        first = {c.name: c for c in check_integrity(block, ctx, logical, log=expect.log)}
        second = {c.name: c for c in check_linkage(block, ctx, expect)}
        assert tuple(whole) == CHECK_NAMES
        assert tuple(first) == tuple(n for n in CHECK_NAMES if n in INTEGRITY_CHECKS)
        assert tuple(second) == LINKAGE_CHECKS
        for name, check in whole.items():
            if name != "level":
                assert check == (first | second)[name]
        assert whole["level"] == (first["level"] if first["level"].ok is False else second["level"])


def test_neither_half_raises_on_garbage_and_both_refuse_a_block_of_the_wrong_size():
    rng = random.Random(11)
    ctx = node_ctx()
    expect = Expect(1, 5, 7, Key(1, 2, 3))
    for _ in range(300):
        block = rng.randbytes(ctx.nodesize)
        if rng.random() < 0.5:  # a plausible header over garbage
            block = bytearray(block)
            struct.pack_into(
                "<I", block, ondisk.HEADER.offset("nritems"), rng.choice([0, 3, 2**31])
            )
            block[ondisk.HEADER.offset("level")] = rng.choice([0, 1, 9])
            block = bytes(block)
        check_integrity(block, ctx, LOGICAL)
        check_linkage(block, ctx, expect)
    for check in (lambda b: check_integrity(b, ctx, None), lambda b: check_linkage(b, ctx, expect)):
        with pytest.raises(ValueError, match="nodesize"):
            check(bytes(100))


# ---------------------------------------------------------------------------
# read_node: enforce and report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("block", "failed"),
    [
        (make_node(LOGICAL, items=ITEMS, owner=7), ("owner",)),
        (make_node(LOGICAL, items=ITEMS, generation=9), ("parent_generation",)),
        (make_node(LOGICAL, items=ITEMS[1:]), ("first_key",)),
        (make_node(LOGICAL, level=1, ptrs=[((256, INODE_ITEM, 0), 0x120000, 7)]), ("level",)),
        (make_node(LOGICAL, items=ITEMS[1:], owner=2, generation=3),
         ("owner", "parent_generation", "first_key")),
    ],
)  # fmt: skip
def test_a_sound_block_that_is_not_the_one_meant_is_used_only_on_request_and_flagged(block, failed):
    strict = read(block, linkage="enforce")
    assert not strict.valid and not strict.usable and strict.linkage_mismatch == ()
    with pytest.raises(Exception, match="no valid copy"):
        _ = strict.items
    found = read(block, linkage="report")
    assert found.usable and not found.valid and found.linkage_mismatch == failed
    assert found.chosen == 0 and (found.items or found.key_ptrs)


@pytest.mark.parametrize(
    "block",
    [
        flip(make_node(LOGICAL, items=ITEMS, owner=7), 3000),  # csum, and a linkage failure
        make_node(LOGICAL + 4096, items=ITEMS, owner=7),  # another block's address
        make_node(LOGICAL, items=ITEMS, owner=7, fsid=bytes(16)),
        make_node(LOGICAL, items=ITEMS, owner=7, chunk_tree_uuid=bytes(16)),
        make_node(LOGICAL, items=ITEMS, owner=7, generation=101),  # above the superblock's
        make_node(LOGICAL, items=ITEMS, owner=7, flags=0),  # not WRITTEN
        make_node(LOGICAL, items=ITEMS, owner=7, nritems=10**6),
        make_node(LOGICAL, level=8, ptrs=[((256, INODE_ITEM, 0), 0x120000, 7)]),  # impossible
        make_node(LOGICAL, level=1, owner=7, ptrs=[((256, 1, 0), 0, 7)]),  # layout: null pointer
        bytes(4096),
    ],
)
def test_a_block_that_fails_an_integrity_check_is_never_used(block):
    found = read(block, linkage="report")
    assert not found.usable and found.chosen is None and found.linkage_mismatch == ()
    assert all(copy.linkage_mismatch is None for copy in found.copies)


def test_a_valid_copy_is_preferred_to_a_flagged_one_and_report_changes_nothing_then():
    other, meant = make_node(LOGICAL, items=ITEMS, generation=9), make_node(LOGICAL, items=ITEMS)
    for linkage in ("enforce", "report"):
        found = read(other, linkage=linkage, mirror=meant)
        assert found.valid and found.chosen == 1 and found.linkage_mismatch == ()
    assert read(meant, linkage="report").valid


def test_bit_flips_never_make_a_block_usable_unless_every_integrity_check_holds():
    rng = random.Random(3)
    base = make_node(LOGICAL, items=ITEMS, generation=9)  # sound, but not the block meant
    ctx = node_ctx()
    for _ in range(300):
        block = flip(base, rng.randrange(len(base)))
        if rng.random() < 0.5:
            block = recsum(block)  # a forger fixes the checksum
        found = read(block, linkage="report")
        sound = all(c.ok is not False for c in check_integrity(block, ctx, LOGICAL))
        assert found.usable == sound
        if found.usable:
            assert found.linkage_mismatch and set(found.linkage_mismatch) <= set(LINKAGE_CHECKS)


def test_an_unknown_mode_is_refused():
    with pytest.raises(ValueError, match="enforce or report"):
        read(make_node(LOGICAL, items=ITEMS), linkage="ignore")


# ---------------------------------------------------------------------------
# walk
# ---------------------------------------------------------------------------


def test_a_flagged_node_is_descended_and_each_child_is_checked_against_its_own_pointer():
    parent, left, right = LOGICAL, LOGICAL + 4096, LOGICAL + 8192
    blocks = {
        # a newer parent than the root pointer names; it points at one child that is what it
        # says and one that is not
        PHYSICAL: make_node(parent, level=1, generation=9, ptrs=[
            ((256, INODE_ITEM, 0), left, 9), ((300, INODE_ITEM, 0), right, 9)]),
        PHYSICAL + 4096: make_node(left, items=ITEMS, generation=9),
        PHYSICAL + 8192: make_node(right, items=[((300, INODE_ITEM, 0), bytes(160))], owner=2,
                                   generation=9),
    }  # fmt: skip
    expect = Expect(level=1, owner=5, generation=7)
    with scratch_dir("test_linkage_walk_") as directory:
        with open_image(write_sparse_image(directory / "w.img", 8 * MIB, blocks)) as img:
            reader = reader_of(img)
            strict = list(walk(reader, parent, expect))
            found = list(walk(reader, parent, expect, "report"))
    assert [v.node.usable for v in strict] == [False]
    assert [(v.node.logical, v.node.valid, v.node.linkage_mismatch) for v in found] == [
        (parent, False, ("parent_generation",)),
        (left, True, ()),
        (right, False, ("owner",)),
    ]
    assert len(list(leaf_items(found))) == 3 and not list(leaf_items(strict))


@pytest.mark.parametrize("name", CORPUS)
def test_on_the_corpus_report_adds_only_flagged_nodes_and_nothing_to_the_current_state(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    with open_image(path) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            for tree in ("root", "fs", "extent", "dev", "csum"):
                try:
                    start = resolve_tree(fs.reader, root_set, tree)
                except RootNotFound:
                    continue
                strict = list(walk(fs.reader, start.bytenr, start.expect()))
                found = list(walk(fs.reader, start.bytenr, start.expect(), "report"))
                usable = {v.node.logical for v in strict if v.node.valid}
                assert usable <= {v.node.logical for v in found if v.node.usable}
                for visit in found:
                    node = visit.node
                    if node.usable and node.logical not in usable:
                        assert node.linkage_mismatch and not node.valid
                        chosen = node.copies[node.chosen]
                        failed = {c.name for c in chosen.checks if c.ok is False}
                        assert failed == set(node.linkage_mismatch) <= set(LINKAGE_CHECKS)
                if root_set.source == "current":
                    assert [v.node for v in strict] == [v.node for v in found]


def test_m2_logtree_has_a_backup_root_whose_address_now_holds_another_trees_block():
    path = SCENARIOS / "m2_logtree.img"
    if not path.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    flagged = []
    with open_image(path) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            if root_set.source == "current":
                continue
            start = resolve_tree(fs.reader, root_set, "root")
            for visit in walk(fs.reader, start.bytenr, start.expect(), "report"):
                if visit.node.linkage_mismatch:
                    flagged.append((root_set.source, visit.node))
    assert flagged  # the oldest backup slot's blocks were reused (EXP-002, README)
    for _, node in flagged:
        # Not the root tree of that slot: a newer block of another tree. Reading its items as
        # the old state would invent a state, which is why recovery never follows it.
        assert "owner" in node.linkage_mismatch or "parent_generation" in node.linkage_mismatch


# ---------------------------------------------------------------------------
# The command, and what a recovery gap says
# ---------------------------------------------------------------------------


def test_walk_linkage_report_is_refused_for_the_current_root(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--linkage", "report"]) == 1
    assert "current state is walked by the kernel's rule" in capsys.readouterr().err
    assert main(["walk", str(sandbox_img), "--root", "backup:13", "--linkage", "report"]) == 0
    captured = capsys.readouterr()
    assert "nodes used although a linkage check failed" in captured.err
    assert all("linkage_mismatch" in json.loads(line)["node"] for line in captured.out.splitlines())


def test_a_recovery_gap_names_the_block_that_lies_there_and_does_not_follow_it():
    path = SCENARIOS / "m2_logtree.img"
    if not path.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    with scratch_dir("test_linkage_gap_") as directory:
        build_catalog(path, directory / "evidence.db")
        conn = db.open_readonly(directory / "evidence.db")
        # a pointer to a scanned block's address, but to a generation that block does not have
        bytenr, generation, level, owner = conn.execute(
            "SELECT bytenr, generation, level, owner FROM nodes WHERE valid AND owner = 5 LIMIT 1"
        ).fetchone()
        root = Root("state:0", None, 5, bytenr, generation + 1000, level)
        leaves, gaps = tree_leaves(conn, root)
        assert not leaves
        (gap,) = gaps
        assert "not among the valid scanned blocks" in gap and "not followed" in gap
        assert f"generation {generation} level {level} owner {owner}" in gap
        assert "linkage mismatch: parent_generation" in gap
        # and nothing at all at an address no block has
        _, (nothing,) = tree_leaves(conn, Root("state:0", None, 5, 12345 * 4096, 7, 0))
        assert nothing.endswith("not among the valid scanned blocks")


def test_no_expectations_means_no_linkage_failure():
    block = make_node(LOGICAL, items=ITEMS, owner=7, generation=3)
    assert all(c.ok is not False for c in check_linkage(block, node_ctx(), NO_EXPECTATIONS))
    assert read(block, NO_EXPECTATIONS, "enforce").valid
