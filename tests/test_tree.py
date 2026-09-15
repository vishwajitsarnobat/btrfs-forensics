"""Tree walking: per-hop validation, cycle protection, inventories and opening a filesystem."""

import json
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe, type_name
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import Expect, Key, NodeReader
from btrfska.substrate.tree import IncompleteTree, fs_tree_inventory, leaf_items, walk
from tests.helpers import DEV_UUID, flip, make_node, node_ctx, scratch_dir, write_sparse_image

GROUND_TRUTH = json.loads((Path(__file__).parent / "ground_truth" / "sandbox.json").read_text())
MIB = 1024**2
BASE = MIB
ROOT, A, B, C = 0x200000, 0x210000, 0x220000, 0x230000
INODE = ondisk.ITEM_KEYS["INODE_ITEM"]
EXPECT_ROOT = Expect(level=1, owner=5, generation=9)


def identity_map() -> ChunkMap:
    """One SINGLE chunk whose physical offsets equal its logical ones."""
    chunk = Chunk(
        BASE, 15 * MIB, ondisk.BLOCK_GROUP_FLAGS["METADATA"], (Stripe(1, BASE, DEV_UUID),)
    )
    return ChunkMap("test", [chunk], {1: DEV_UUID})


@contextmanager
def tree_reader(blocks):
    with scratch_dir("test_tree_") as d:
        path = write_sparse_image(d / "tree.img", 16 * MIB, blocks)
        with open_image(path) as img:
            yield NodeReader(img, identity_map(), node_ctx())


def leaf_a(**kw):
    items = kw.pop("items", [((256, INODE, 0), bytes(160)), ((257, INODE, 0), bytes(160))])
    return make_node(A, items=items, generation=kw.pop("generation", 9), **kw)


def leaf_b(**kw):
    return make_node(
        B, items=[((300, INODE, 0), bytes(160))], generation=kw.pop("generation", 8), **kw
    )


def root(ptrs=None, **kw):
    ptrs = ptrs or [((256, INODE, 0), A, 9), ((300, INODE, 0), B, 8)]
    return make_node(ROOT, level=kw.pop("level", 1), generation=9, ptrs=ptrs, **kw)


def run(overrides=None):
    blocks = {ROOT: root(), A: leaf_a(), B: leaf_b(), **(overrides or {})}
    with tree_reader(blocks) as reader:
        return list(walk(reader, ROOT, EXPECT_ROOT))


def test_walk_is_depth_first_in_key_order_with_hop_provenance():
    visits = run()
    assert [(v.node.logical, v.depth, v.parent, v.slot) for v in visits] == [
        (ROOT, 0, None, None),
        (A, 1, ROOT, 0),
        (B, 1, ROOT, 1),
    ]
    assert all(v.node.valid and v.problems == () for v in visits)
    keys = [item.key for _, item in leaf_items(visits)]
    assert keys == [Key(256, INODE, 0), Key(257, INODE, 0), Key(300, INODE, 0)]
    # Each child was checked against its parent pointer.
    checks = {c.name: c.ok for c in visits[2].node.copies[0].checks}
    assert checks["parent_generation"] is True and checks["first_key"] is True
    assert checks["level"] is True and checks["owner"] is True


def test_the_log_context_reaches_every_child_and_nothing_else_accepts_log_generations():
    log = ondisk.TREE_LOG_OBJECTID
    blocks = {
        ROOT: make_node(
            ROOT, level=1, generation=101, owner=log,
            ptrs=[((256, INODE, 0), A, 101), ((300, INODE, 0), B, 101)],
        ),
        A: leaf_a(generation=101, owner=log),
        B: leaf_b(generation=101, owner=log),
    }  # fmt: skip
    with tree_reader(blocks) as reader:
        in_log = list(walk(reader, ROOT, Expect(level=1, owner=log, generation=101, log=True)))
        outside = list(walk(reader, ROOT, Expect(level=1, owner=log, generation=101)))
    assert [(v.node.logical, v.node.valid) for v in in_log] == [(ROOT, True), (A, True), (B, True)]
    assert [(v.node.logical, v.node.valid) for v in outside] == [(ROOT, False)]


def test_child_newer_than_its_parent_pointer_is_invalid():
    visits = run({B: leaf_b(generation=10)})
    child = visits[2].node
    assert not child.valid
    assert child.problems == (
        "mirror 1: parent_generation: generation 10 != parent pointer generation 8 "
        "(newer: rewritten after the parent)",
    )
    assert [item.key.objectid for _, item in leaf_items(visits)] == [256, 257]


def test_child_level_must_be_one_below_the_parent():
    wrong = make_node(A, level=1, generation=9, ptrs=[((256, INODE, 0), C, 9)])
    visits = run({A: wrong})
    assert not visits[1].node.valid
    assert visits[1].node.problems == ("mirror 1: level: level 1 != expected 0",)
    assert [v.node.logical for v in visits] == [ROOT, A, B]  # not descended


def test_first_key_must_match_the_parent_key():
    visits = run({A: leaf_a(items=[((255, INODE, 0), bytes(160))])})
    assert visits[1].node.problems[0].startswith("mirror 1: first_key: first key (255 1 0)")


def test_keys_at_or_above_the_next_parent_key_are_a_hop_problem():
    items = [((256, INODE, 0), bytes(160)), ((300, INODE, 0), bytes(160))]
    visits = run({A: leaf_a(items=items)})
    assert visits[1].node.valid
    assert visits[1].problems == (
        "last key (300 1 0) is not below the parent's next key (300 1 0)",
    )


def test_cycles_and_repeated_pointers_are_reported_and_not_followed():
    looping = root(
        ptrs=[((256, INODE, 0), A, 9), ((300, INODE, 0), ROOT, 9), ((400, INODE, 0), A, 9)]
    )
    visits = run({ROOT: looping})
    assert [v.node.logical for v in visits] == [ROOT, A]
    assert visits[0].problems == (
        f"slot 1 points to {ROOT}, already reached in this walk; not followed",
        f"slot 2 points to {A}, already reached in this walk; not followed",
    )


def test_an_invalid_internal_node_is_yielded_but_not_descended():
    visits = run({ROOT: flip(root(), 3000)})
    assert len(visits) == 1 and not visits[0].node.valid
    assert list(leaf_items(visits)) == []


def test_an_unmapped_child_is_a_flagged_visit():
    far = 20 * MIB
    visits = run({ROOT: root(ptrs=[((256, INODE, 0), A, 9), ((300, INODE, 0), far, 8)])})
    assert not visits[2].node.valid and visits[2].node.copies == ()
    assert "not in any chunk" in visits[2].node.problems[0]


def test_inventory_refuses_an_incomplete_tree():
    blocks = {ROOT: root(), A: leaf_a(), B: flip(leaf_b(), 4000)}
    with tree_reader(blocks) as reader, pytest.raises(IncompleteTree, match=str(B)):
        fs_tree_inventory(reader, ROOT, EXPECT_ROOT)


# ---------------------------------------------------------------------------
# sandbox.img
# ---------------------------------------------------------------------------
@pytest.mark.sandbox
def test_open_filesystem_builds_the_current_chunk_map(sandbox_img):
    with open_image(sandbox_img) as img:
        fs = open_filesystem(img)
    chunk_map = fs.chunk_map
    assert chunk_map.source == "current" and chunk_map.problems == ()
    assert [
        {
            "logical": c.logical,
            "length": c.length,
            "type": type_name(c.type),
            "stripes": [[s.devid, s.offset] for s in c.stripes],
        }
        for c in chunk_map.chunks
    ] == GROUND_TRUTH["chunks"]
    assert all(c.origin.startswith("chunk tree leaf 22036480 slot ") for c in chunk_map.chunks)
    expected = GROUND_TRUTH["chunk_tree"]
    assert str(uuid.UUID(bytes=fs.reader.ctx.chunk_tree_uuid)) == expected["chunk_tree_uuid"]
    assert fs.chunk_root.valid and fs.chunk_root.logical == expected["root"]
    assert fs.unsupported_format is False


@pytest.mark.sandbox
def test_dup_metadata_copies_are_both_read(sandbox_img):
    with open_image(sandbox_img) as img:
        fs = open_filesystem(img)
        node = fs.reader.read(30720000, Expect(level=0, owner=1, generation=14))
    assert node.valid and node.chosen == 0 and node.problems == ()
    # METADATA|DUP chunk 30408704 has stripes at 38797312 and 72351744.
    assert [(c.mirror, c.physical, c.ok) for c in node.copies] == [
        (1, 38797312 + 30720000 - 30408704, True),
        (2, 72351744 + 30720000 - 30408704, True),
    ]
