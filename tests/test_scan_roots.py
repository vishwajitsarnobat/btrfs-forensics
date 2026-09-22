"""Old-root discovery (scan/roots.py), reuse-versus-damage classes of unreachable blocks, and the
log-tree and raw-tree groups."""

import shutil
import struct
import time
import tracemalloc

import pytest

from btrfska.scan.classify import walk_root_set
from btrfska.scan.kernel_numpy import NodeRecord, iter_candidate_nodes
from btrfska.scan.regions import Region
from btrfska.scan.roots import (
    MAX_LISTED,
    MAX_MISSING,
    MAX_PROBLEMS,
    MAX_STATES,
    ChunkRoot,
    KnownRoot,
    discover,
    discover_image,
    index_records,
    known_roots,
)
from btrfska.substrate import node as node_module
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import CHECK_NAMES, Check, Expect, NodeReader, node_failure
from btrfska.substrate.roots import RootSet, TreeRoot
from tests.helpers import (
    DEV_UUID,
    SCENARIOS,
    flip,
    make_node,
    node_ctx,
    scratch_dir,
    write_sparse_image,
)

MIB, GIB, SECTOR = 1 << 20, 1 << 30, 4096
ROOT_ITEM = ondisk.ITEM_KEYS["ROOT_ITEM"]
CHUNK_ITEM = ondisk.ITEM_KEYS["CHUNK_ITEM"]
INODE_ITEM = ondisk.ITEM_KEYS["INODE_ITEM"]
LOG = ondisk.TREE_LOG_OBJECTID
METADATA = ondisk.BLOCK_GROUP_FLAGS["METADATA"]
CTX = node_ctx()  # superblock generation 100, nodesize 4096
# Logical MIB..16 MIB maps to the same physical range.
IDENTITY = ChunkMap("current", [Chunk(MIB, 15 * MIB, METADATA, (Stripe(1, MIB, DEV_UUID),))],
                    {1: DEV_UUID})  # fmt: skip
EVERYTHING = Region(0, 1 << 40, "unmapped_gap")


def a(i: int) -> int:
    return MIB + i * SECTOR


def inode(objectid: int):
    return ((objectid, INODE_ITEM, 0), bytes(160))


def root_item(bytenr: int, generation: int, level: int = 0) -> bytes:
    data = bytearray(ondisk.ROOT_ITEM.size)
    for name, fmt, value in (
        ("generation", "<Q", generation),
        ("generation_v2", "<Q", generation),
        ("bytenr", "<Q", bytenr),
        ("level", "<B", level),
    ):
        struct.pack_into(fmt, data, ondisk.ROOT_ITEM.offset(name), value)
    return bytes(data)


def chunk_item(physical: int, length: int, type_: int = METADATA) -> bytes:
    """A single-stripe chunk item on devid 1, METADATA unless another type is given."""
    head = struct.pack("<QQQQIIIHH", length, 2, 1 << 16, type_, SECTOR, SECTOR, SECTOR, 1, 1)
    return head + struct.pack("<QQ16s", 1, physical, DEV_UUID)


def records_of(img):
    return iter_candidate_nodes(img, [EVERYTHING], CTX, IDENTITY)


# ---------------------------------------------------------------------------
# Why a referenced block cannot be read: node.node_failure
# ---------------------------------------------------------------------------
def test_node_failure_tells_reuse_from_damage():
    target = make_node(a(0), owner=5, generation=90, items=[inode(256)])
    blocks = {
        a(0): target,
        a(1): b"\x55" * SECTOR,  # no tree block of this filesystem: data or another fs
        a(2): flip(make_node(a(2), owner=5, generation=90, items=[inode(256)]), 300),
        a(3): make_node(a(3), owner=7, generation=95, items=[inode(1)]),  # a newer tree's block
        a(4): make_node(a(4), owner=LOG, generation=101, items=[inode(1)]),  # an uncommitted log
    }
    beyond = Chunk(32 * MIB, MIB, METADATA, (Stripe(1, 64 * MIB, DEV_UUID),))
    chunk_map = ChunkMap("current", [*IDENTITY.chunks, beyond], {1: DEV_UUID})
    want = Expect(level=0, owner=5, generation=90)
    cases = [
        (a(0), want, None),
        (a(0), Expect(level=1, owner=5, generation=90), "mismatch"),
        (a(0), Expect(level=0, owner=5, generation=91), "mismatch"),  # older than the pointer
        (a(1), want, "overwritten"),
        (a(2), want, "corrupt"),
        (a(3), want, "reused"),
        (a(4), want, "reused"),
        (a(5), want, "zeroed"),
        (GIB, want, "unmapped"),
        (32 * MIB, want, "unreadable"),
    ]
    with scratch_dir("test_scan_roots_") as d:
        with open_image(write_sparse_image(d / "f.img", 16 * MIB, blocks)) as img:
            reader = NodeReader(img, chunk_map, CTX)
            got = [
                (bytenr, node_failure(reader.read(bytenr, expect), expect))
                for bytenr, expect, _ in cases
            ]
    assert got == [(bytenr, expected) for bytenr, _, expected in cases]


# ---------------------------------------------------------------------------
# A synthetic history: root-tree states of generations 99 (current), 90 (backup), 85 and 70
# ---------------------------------------------------------------------------
R90, L90A, L90B, O90, R99, CH99, CH60, R70P, E70P = (a(i) for i in range(9))
E, F, C, Z, F1, F2, E2, LOGR = (a(i) for i in range(10, 18))
UNMAPPED = 64 * MIB
R70, E70 = GIB + 7 * SECTOR, GIB + 8 * SECTOR  # logical under the generation-60 chunk tree


def history_blocks() -> dict[int, bytes]:
    def rt(*entries):
        return [((tree, ROOT_ITEM, 0), root_item(*rest)) for tree, *rest in entries]

    return {
        R90: make_node(R90, level=1, owner=1, generation=90,
                       ptrs=[((2, ROOT_ITEM, 0), L90A, 90), ((7, ROOT_ITEM, 0), L90B, 85)]),
        L90A: make_node(L90A, owner=1, generation=90, items=rt((2, E, 90), (5, F, 88, 1))),
        L90B: make_node(L90B, owner=1, generation=85,
                        items=rt((7, C, 85), (9, Z, 80), (10, UNMAPPED, 80), (11, LOGR, 80))),
        O90: make_node(O90, owner=1, generation=90, items=rt((2, E, 90))),  # a fragment
        E: make_node(E, owner=2, generation=90, items=[inode(1)]),
        F: make_node(F, level=1, owner=5, generation=88,
                     ptrs=[((256, INODE_ITEM, 0), F1, 88), ((300, INODE_ITEM, 0), F2, 70)]),
        F1: make_node(F1, owner=5, generation=88, items=[inode(256)]),
        F2: make_node(F2, owner=2, generation=95, items=[inode(300)]),  # reused by a newer tree
        C: flip(make_node(C, owner=7, generation=85, items=[inode(1)]), 200),  # damaged
        LOGR: make_node(LOGR, owner=LOG, generation=101, items=[inode(1)]),  # reused by a log
        R99: make_node(R99, owner=1, generation=99, items=rt((2, E2, 99))),
        E2: make_node(E2, owner=2, generation=99, items=[inode(1)]),
        CH99: make_node(CH99, owner=3, generation=99,
                        items=[((256, CHUNK_ITEM, MIB), chunk_item(MIB, 15 * MIB))]),
        CH60: make_node(CH60, owner=3, generation=60,
                        items=[((256, CHUNK_ITEM, GIB), chunk_item(MIB, 15 * MIB))]),
        R70P: make_node(R70, owner=1, generation=70, items=rt((2, E70, 70))),
        E70P: make_node(E70, owner=2, generation=70, items=[inode(1)]),
    }  # fmt: skip


KNOWN = (
    KnownRoot("current", "root", 1, R99, 99, 0),
    KnownRoot("current", "chunk", 3, CH99, 99, 0),
    KnownRoot("backup:90", "root", 1, R90, 90, 1),
    KnownRoot("backup:90", "chunk", 3, CH60, 60, 0),
    KnownRoot("backup:90", "extent", 2, E, 90, 0),
    KnownRoot("backup:90", "fs", 5, F, 88, 1),
)


@pytest.fixture(scope="module")
def history():
    with scratch_dir("test_scan_roots_history_") as d:
        path = write_sparse_image(d / "history.img", 16 * MIB, history_blocks())
        with open_image(path) as img:
            index = index_records(records_of(img), CTX)
            yield img, index, discover(img, index, ctx=CTX, chunk_map=IDENTITY, known=KNOWN)


def test_candidate_roots_are_the_blocks_no_parent_of_their_generation_or_newer_points_to(history):
    _, _, found = history
    groups = {(g.owner, g.generation, g.level): g for g in found.groups}
    top = groups[(1, 90, 1)]
    assert (top.top, top.blocks, top.copies, top.candidates, top.listed) == (True, 1, 1, 1, (R90,))
    # L90A is referenced by R90. O90 is unreferenced: a candidate below the highest level too.
    below = groups[(1, 90, 0)]
    assert (below.top, below.blocks, below.unreferenced, below.candidates, below.listed) == (
        False, 2, 1, 1, (O90,),
    )  # fmt: skip
    # An unchanged older leaf that a newer parent still points to is part of that newer tree.
    older = groups[(1, 85, 0)]
    assert (older.unreferenced, older.referenced_by_newer, older.candidates, older.listed) == (
        1, 1, 0, (),
    )  # fmt: skip
    assert groups[(5, 88, 0)].unreferenced == 0 and groups[(5, 88, 1)].listed == (F,)
    assert groups[(2, 95, 0)].listed == (F2,)
    assert (7, 85, 0) not in groups  # the damaged block is not indexed
    assert found.root_tree_candidates == 4


def test_a_root_tree_state_lists_its_trees_and_how_complete_it_is(history):
    _, _, found = history
    states = {s.bytenr: s for s in found.states}
    s90 = states[R90]
    assert (s90.generation, s90.level, s90.copies, s90.known_as) == (90, 1, (R90,), ("backup:90",))
    assert [(t.tree_id, t.bytenr, t.status) for t in s90.trees] == [
        (2, E, "found"),
        (5, F, "found"),
        (7, C, "corrupt"),
        (9, Z, "zeroed"),
        (10, UNMAPPED, "unmapped"),
        (11, LOGR, "reused"),
    ]
    fs_tree = s90.trees[1]
    assert (fs_tree.blocks, fs_tree.missing) == (2, 1)  # F2's address holds a newer tree's block
    assert (s90.root_tree_blocks, s90.root_tree_missing) == (3, 0)
    assert (s90.found, s90.referenced) == (6, 11)
    assert s90.missing == {"reused": 2, "corrupt": 1, "zeroed": 1, "unmapped": 1}
    assert s90.completeness == pytest.approx(6 / 11) and s90.level_consistent
    assert s90.chunk_root == ChunkRoot(CH60, 60, 0, "backup:90", differs_from_current=True)
    assert (s90.maps_current, s90.maps_historical, s90.maps_neither) == (6, 0, 0)

    s99 = states[R99]
    assert (s99.known_as, s99.found, s99.referenced, s99.completeness) == (("current",), 2, 2, 1.0)
    assert s99.chunk_root == ChunkRoot(CH99, 99, 0, "current", differs_from_current=False)
    assert (s99.maps_current, s99.maps_historical, s99.maps_neither) == (2, None, 0)


def test_states_beyond_the_superblock_roots_infer_their_chunk_root(history):
    _, _, found = history
    assert [(s.generation, s.bytenr, s.known_as) for s in found.states] == [
        (99, R99, ("current",)), (90, R90, ("backup:90",)), (90, O90, ()), (70, R70, ()),
    ]  # fmt: skip
    s90_fragment, s70 = found.states[2:]
    assert (s90_fragment.found, s90_fragment.referenced) == (2, 2)  # O90 and the extent root E
    assert s70.bytenr == R70 and s70.copies == (R70P,)
    assert (s70.found, s70.referenced, [t.status for t in s70.trees]) == (2, 2, ["found"])
    # The newest chunk-tree root no newer than the state, and it differs from the current one.
    assert s70.chunk_root == ChunkRoot(CH60, 60, 0, "inferred", differs_from_current=True)
    # R70 and E70 claim logical addresses only the generation-60 chunk items map to where they lie.
    assert (s70.maps_current, s70.maps_historical, s70.maps_neither) == (0, 2, 0)
    assert (s90_fragment.chunk_root.source, s90_fragment.chunk_root.bytenr) == ("inferred", CH60)
    maps = (s90_fragment.maps_current, s90_fragment.maps_historical, s90_fragment.maps_neither)
    assert maps == (2, 0, 0)


def test_every_superblock_and_backup_root_is_rediscovered(history):
    img, index, found = history
    assert [(r.root.source, r.root.tree, r.indexed, r.candidate) for r in found.rediscovered] == [
        (root.source, root.tree, True, True) for root in KNOWN
    ]
    gone = KnownRoot("backup:80", "root", 1, Z, 80, 0)
    again = discover(img, index, ctx=CTX, chunk_map=IDENTITY, known=(*KNOWN, gone))
    assert (again.rediscovered[-1].indexed, again.rediscovered[-1].candidate) == (False, False)


def test_known_roots_come_from_the_superblock_and_every_backup_slot(sandbox_img):
    with open_image(sandbox_img) as img:
        fields = open_filesystem(img).fields
    roots = known_roots(fields)
    sources = [r.source for r in roots]
    assert sources.count("current") == 2  # root and chunk; no log_root on the sandbox
    for generation in (11, 12, 13, 14):
        assert [r.tree for r in roots if r.source == f"backup:{generation}"] == [
            "root", "extent", "chunk", "dev", "fs", "csum",
        ]  # fmt: skip
    assert KnownRoot("current", "root", 1, fields["root"], 14, fields["root_level"]) in roots


def test_backup_walks_record_reuse_apart_from_damage(history):
    img, _, _ = history
    backup = RootSet("backup:90", 90, 0, {"root": TreeRoot(1, R90, 1, 90, "backup slot 0")})
    walked = walk_root_set(NodeReader(img, IDENTITY, CTX), backup)
    assert walked.failures == [
        (5, F2, "reused"),
        (7, C, "corrupt"),
        (9, Z, "zeroed"),
        (10, UNMAPPED, "unmapped"),
        (11, LOGR, "reused"),
    ]


def root_items(*entries):
    """ROOT_ITEMs for make_node: (tree id, bytenr, generation[, level]) each."""
    return [((tree, ROOT_ITEM, 0), root_item(*rest)) for tree, *rest in entries]


def discover_blocks(prefix, blocks, **kwargs):
    with scratch_dir(prefix) as d:
        with open_image(write_sparse_image(d / "f.img", 16 * MIB, blocks)) as img:
            index = index_records(records_of(img), CTX)
            return discover(img, index, ctx=CTX, chunk_map=IDENTITY, **kwargs)


def test_a_planted_higher_level_block_does_not_hide_the_root_tree_leaves_of_its_generation():
    leaf, extent, planted = a(0), a(1), a(2)
    blocks = {
        leaf: make_node(leaf, owner=1, generation=90, items=root_items((2, extent, 90))),
        extent: make_node(extent, owner=2, generation=90, items=[inode(1)]),
        # Checksum-valid, owner 1, generation 90, level 7: it points at the real leaf as level 6.
        planted: make_node(planted, level=7, owner=1, generation=90,
                           ptrs=[((2, ROOT_ITEM, 0), leaf, 90)]),
    }  # fmt: skip
    found = discover_blocks("test_scan_roots_planted_", blocks)
    assert found.root_tree_candidates == 2
    states = {s.bytenr: s for s in found.states}
    real, forged = states[leaf], states[planted]
    assert (real.found, real.referenced, real.completeness, real.level_consistent) == (
        2, 2, 1.0, True,
    )  # fmt: skip
    assert (forged.found, forged.referenced, forged.missing) == (1, 2, {"mismatch": 1})
    assert forged.level_consistent is False
    assert any("level 7" in p and "1 pointer" in p for p in forged.problems)
    groups = {(g.owner, g.generation, g.level): g for g in found.groups}
    assert (groups[(1, 90, 0)].top, groups[(1, 90, 0)].candidates) == (False, 1)


def test_forged_chunk_roots_claiming_one_address_at_two_levels_get_maps_with_distinct_names():
    real, planted, leaf = a(0), a(1), a(2)
    chunk = [((256, CHUNK_ITEM, MIB), chunk_item(MIB, 15 * MIB))]
    blocks = {
        real: make_node(real, owner=3, generation=90, items=chunk),
        # at another offset, claiming the same address and generation one level up
        planted: make_node(real, level=1, owner=3, generation=90,
                           ptrs=[((256, CHUNK_ITEM, MIB), leaf, 90)]),
        leaf: make_node(leaf, owner=3, generation=90, items=chunk),
    }  # fmt: skip
    found = discover_blocks("test_scan_roots_chunk_twins_", blocks)
    names = [m.name for m in found.chunk_maps]
    assert len(names) == len(set(names))
    assert {f"historical:90@{real}/level0", f"historical:90@{real}/level1"} <= set(names)


def test_a_historical_map_accepts_a_mixed_chunk_only_under_the_mixed_groups_feature():
    """The current map is built with the superblock's flags (substrate/fs.py); a historical
    map must be too, or every chunk of a mixed filesystem is rejected there."""
    mixed = METADATA | ondisk.BLOCK_GROUP_FLAGS["DATA"]
    root = a(0)
    blocks = {
        root: make_node(
            root,
            owner=3,
            generation=90,
            items=[((256, CHUNK_ITEM, MIB), chunk_item(MIB, 15 * MIB, mixed))],
        )
    }
    strict = discover_blocks("test_scan_roots_mixed_", blocks)
    (found,) = [m for m in strict.chunk_maps if m.kind == "historical"]
    assert not found.chunk_map.chunks and len(found.chunk_map.rejected) == 1
    lenient = discover_blocks("test_scan_roots_mixed_", blocks,
                              incompat=ondisk.INCOMPAT["MIXED_GROUPS"])  # fmt: skip
    (found,) = [m for m in lenient.chunk_maps if m.kind == "historical"]
    assert [c.logical for c in found.chunk_map.chunks] == [MIB]


def test_old_leaves_of_a_multi_leaf_root_tree_that_newer_parents_still_use_are_not_states():
    # Generation 40 had a root node over two leaves; only its leaf B40 survives. Generation 50
    # rewrote the other leaf and still points to B40; generation 60 rewrote B40 and kept A50.
    n50, a50, b40, n60, b60, extent, tree7 = (a(i) for i in range(7))
    blocks = {
        n50: make_node(n50, level=1, owner=1, generation=50,
                       ptrs=[((2, ROOT_ITEM, 0), a50, 50), ((7, ROOT_ITEM, 0), b40, 40)]),
        a50: make_node(a50, owner=1, generation=50, items=root_items((2, extent, 50))),
        b40: make_node(b40, owner=1, generation=40, items=root_items((7, tree7, 40))),
        n60: make_node(n60, level=1, owner=1, generation=60,
                       ptrs=[((2, ROOT_ITEM, 0), a50, 50), ((7, ROOT_ITEM, 0), b60, 60)]),
        b60: make_node(b60, owner=1, generation=60, items=root_items((7, tree7, 40))),
        extent: make_node(extent, owner=2, generation=50, items=[inode(1)]),
        tree7: make_node(tree7, owner=7, generation=40, items=[inode(1)]),
    }  # fmt: skip
    found = discover_blocks("test_scan_roots_multileaf_", blocks)
    assert found.root_tree_candidates == 2
    assert [(s.generation, s.bytenr) for s in found.states] == [(60, n60), (50, n50)]
    assert all((s.found, s.referenced, s.level_consistent) == (5, 5, True) for s in found.states)
    groups = {(g.owner, g.generation, g.level): g for g in found.groups}
    b40_group = groups[(1, 40, 0)]
    assert (b40_group.unreferenced, b40_group.referenced_by_newer, b40_group.candidates) == (
        1, 1, 0,
    )  # fmt: skip
    a50_group = groups[(1, 50, 0)]  # referenced by N50 of its own generation (and by N60)
    assert (a50_group.unreferenced, a50_group.referenced_by_newer, a50_group.candidates) == (
        0, 0, 0,
    )  # fmt: skip


def test_missing_blocks_outside_the_current_map_use_the_state_chunk_items_and_invalid_copies():
    # A generation-70 state whose chunk tree (generation 60) maps logical GIB.. to physical MIB..,
    # a range the current map covers only under other logical addresses.
    chunk, far, nowhere = a(0), 5 * GIB, 6 * GIB
    leaf, extent, zeroed, damaged = (GIB + i * SECTOR for i in range(1, 5))
    blocks = {
        chunk: make_node(chunk, owner=3, generation=60,
                         items=[((256, CHUNK_ITEM, GIB), chunk_item(MIB, 15 * MIB))]),
        a(1): make_node(leaf, owner=1, generation=70, items=root_items(
            (2, extent, 70), (7, zeroed, 70), (9, damaged, 70), (10, far, 70), (11, nowhere, 70),
        )),
        a(2): make_node(extent, owner=2, generation=70, items=[inode(1)]),
        # a(3), logical `zeroed`, holds nothing.
        a(4): flip(make_node(damaged, owner=9, generation=70, items=[inode(1)]), 300),
        # Scanned, but no chunk map places logical 5 GiB: only the invalid copy tells.
        a(5): flip(make_node(far, owner=10, generation=70, items=[inode(1)]), 300),
    }  # fmt: skip
    found = discover_blocks("test_scan_roots_outside_", blocks)
    assert found.stats["invalid_copies"] == 2
    (state,) = found.states
    assert state.chunk_root == ChunkRoot(chunk, 60, 0, "inferred", differs_from_current=True)
    assert [(t.tree_id, t.status) for t in state.trees] == [
        (2, "found"), (7, "zeroed"), (9, "corrupt"), (10, "corrupt"), (11, "unmapped"),
    ]  # fmt: skip
    assert state.missing == {"zeroed": 1, "corrupt": 2, "unmapped": 1}


GEN3_CSUM_LEAF = 1130496  # sandbox.img: logical = physical, generation 1, owner 7, an empty leaf


@pytest.mark.sandbox
def test_a_present_but_invalid_block_of_an_old_state_is_not_reported_unmapped(sandbox_img):
    """The generation-3 state's csum tree root lies in an mkfs chunk that the current chunk map no
    longer covers. Damaged in a copy of sandbox.img, it must read as corrupt, not unmapped."""
    with scratch_dir("test_scan_roots_gen3_") as d:
        path = d / "gen3.img"
        shutil.copyfile(sandbox_img, path)
        with open(path, "r+b") as f:
            f.seek(GEN3_CSUM_LEAF + 200)
            byte = f.read(1)[0]
            f.seek(GEN3_CSUM_LEAF + 200)
            f.write(bytes([byte ^ 0xFF]))
        with open_image(path) as img:
            run = discover_image(img, open_filesystem(img))
    state = {s.generation: s for s in run.discovery.states}[3]
    tree = {t.tree_id: t for t in state.trees}[7]
    assert (tree.bytenr, tree.generation, tree.status) == (GEN3_CSUM_LEAF, 1, "corrupt")
    assert (state.found, state.referenced, state.missing) == (6, 7, {"corrupt": 1})
    assert state.maps_current == 0 and state.chunk_root.source == "inferred"


# ---------------------------------------------------------------------------
# The index: log context, raw trees, rejected log candidates
# ---------------------------------------------------------------------------
def rec(physical, *, bytenr=None, owner=1, generation=50, level=0, failed=(), truncated=False):
    checks = (
        ()
        if truncated
        else tuple(Check(n, n not in failed, "x" if n in failed else "") for n in CHECK_NAMES)
    )
    return NodeRecord(
        physical=physical,
        bytenr=physical if bytenr is None else bytenr,
        generation=generation,
        owner=owner,
        level=level,
        nritems=1,
        checks=checks,
        valid=not failed and not truncated,
        bytenr_mapped=True,
        maps_here=True,
        region=EVERYTHING,
        problems=("truncated",) if truncated else (),
    )


def test_log_blocks_one_generation_ahead_are_indexed_and_other_log_candidates_rejected():
    records = [
        rec(a(0), owner=LOG, generation=101, failed=("generation",)),  # live log (below)
        rec(a(8), owner=LOG, generation=101, failed=("generation",)),  # superseded log commit
        rec(a(1), owner=LOG, generation=102, failed=("generation",)),  # too new: rejected
        rec(a(2), owner=LOG, generation=101, failed=("generation", "csum")),  # damaged: rejected
        rec(a(3), owner=LOG, generation=40),  # a log of a committed transaction: valid as it is
        rec(a(4), owner=5, generation=101, failed=("generation",)),  # not a log: never accepted
        rec(a(5), owner=LOG, generation=101, truncated=True),  # cut by the image end: rejected
        rec(a(6), owner=ondisk.RAID_STRIPE_TREE_OBJECTID),
        rec(a(7), owner=ondisk.REMAP_TREE_OBJECTID, failed=("csum",)),
    ]
    index = index_records(records, CTX)
    assert index.stats == {
        "candidates": 9,
        "indexed_copies": 4,
        "log_accepted": 2,
        "log_rejected": 3,
        "raid_stripe_blocks": 1,
        "remap_blocks": 1,
        "invalid_copies": 5,  # a(1), a(2), a(4), a(5) and a(7): kept to classify missing blocks
    }
    assert [(r["owner"], r["physical"], r["valid"]) for r in index.raw] == [
        (ondisk.RAID_STRIPE_TREE_OBJECTID, a(6), True),
        (ondisk.REMAP_TREE_OBJECTID, a(7), False),
    ]
    with scratch_dir("test_scan_roots_log_") as d:
        with open_image(write_sparse_image(d / "log.img", 16 * MIB, {})) as img:
            found = discover(img, index, ctx=CTX, chunk_map=IDENTITY, log_live=frozenset({a(0)}))
    logs = {log.generation: log for log in found.logs}
    assert set(logs) == {40, 101}
    new = logs[101]
    assert (new.blocks, new.copies, new.live, new.superseded, new.committed) == (2, 2, 1, 1, False)
    assert (logs[40].live, logs[40].superseded, logs[40].committed) == (0, 0, True)
    assert found.raw == index.raw


# ---------------------------------------------------------------------------
# Adversarial input
# ---------------------------------------------------------------------------
def test_forged_root_trees_with_inconsistent_root_items_and_repeated_pointers_stay_bounded():
    root, node, leaf, newer, wrong_level = a(0), a(1), a(2), a(3), a(4)
    fan = 100  # pointers per node, all to one child: 10 000 leaf visits without de-duplication
    blocks = {
        root: make_node(root, level=2, owner=1, generation=90,
                        ptrs=[((i, ROOT_ITEM, 0), node, 90) for i in range(1, fan + 1)]),
        # The last pointer points back at the node itself, one level too low.
        node: make_node(node, level=1, owner=1, generation=90,
                        ptrs=[((i, ROOT_ITEM, 0), leaf, 90) for i in range(1, fan)]
                        + [((10**6, ROOT_ITEM, 0), node, 90)]),
        leaf: make_node(leaf, owner=1, generation=90, items=[
            ((1, ROOT_ITEM, 0), root_item(root, 90, level=2)),  # names the root tree itself
            ((2, ROOT_ITEM, 0), root_item(newer, 95)),  # newer than the state
            ((5, ROOT_ITEM, 0), root_item(wrong_level, 90, level=1)),  # the block is a leaf
            ((7, ROOT_ITEM, 0), bytes(10)),  # malformed
        ]),
        newer: make_node(newer, owner=2, generation=95, items=[inode(1)]),
        wrong_level: make_node(wrong_level, owner=5, generation=90, items=[inode(256)]),
    }  # fmt: skip
    with scratch_dir("test_scan_roots_forged_") as d:
        with open_image(write_sparse_image(d / "forged.img", 16 * MIB, blocks)) as img:
            found = discover(img, index_records(records_of(img), CTX), ctx=CTX, chunk_map=IDENTITY)
    assert found.root_tree_candidates == 1
    (state,) = found.states
    assert [(t.tree_id, t.status) for t in state.trees] == [
        (1, "skipped"), (2, "found"), (5, "mismatch"),
    ]  # fmt: skip
    # root, node, leaf and the newer tree are found; the self-pointer and the wrong level are not.
    assert (state.found, state.referenced, state.missing) == (4, 6, {"mismatch": 2})
    problems = state.problems
    assert len(problems) == MAX_PROBLEMS + 1 and problems[-1].startswith("and ")
    assert any("names the root tree" in p for p in problems)
    assert any("generation 95 is newer than the root tree state (90)" in p for p in problems)
    assert any("(7 132 0)" in p and "btrfs_root_item" in p for p in problems)
    assert any("already reached" in p for p in problems)


def test_shared_subtrees_with_dangling_pointers_cost_one_walk_not_one_per_root(monkeypatch):
    """The review's forged image, scaled down with its shape kept: owner-1 level-2 roots that all
    point to the same level-1 nodes, each full of pointers to blocks that are not there. Before
    subtree memoisation this cost roots x nodes x pointers full reads (317 s and 137 MB of heap at
    64 x 121 x 121 on a 1.5 MB image)."""
    roots, shared, dangling = MAX_STATES, 40, 40
    first_shared, first_dangling = roots, roots + shared
    node_ptrs = [
        [
            ((i * dangling + j, ROOT_ITEM, 0), a(first_dangling + i * dangling + j), 90)
            for j in range(dangling)
        ]  # fmt: skip
        for i in range(shared)
    ]
    blocks = {
        a(first_shared + i): make_node(a(first_shared + i), level=1, owner=1, generation=90,
                                       ptrs=node_ptrs[i])
        for i in range(shared)
    }  # fmt: skip
    for r in range(roots):
        ptrs = [((i * dangling, ROOT_ITEM, 0), a(first_shared + i), 90) for i in range(shared)]
        blocks[a(r)] = make_node(a(r), level=2, owner=1, generation=90, ptrs=ptrs)
    assert first_dangling + shared * dangling < 15 * MIB // SECTOR  # every pointer is mapped
    reads = 0
    real_read_node = node_module.read_node

    def counting_read_node(*args, **kwargs):
        nonlocal reads
        reads += 1
        return real_read_node(*args, **kwargs)

    monkeypatch.setattr(node_module, "read_node", counting_read_node)
    with scratch_dir("test_scan_roots_shared_") as d:
        with open_image(write_sparse_image(d / "shared.img", 16 * MIB, blocks)) as img:
            index = index_records(records_of(img), CTX)
            started = time.perf_counter()
            found = discover(img, index, ctx=CTX, chunk_map=IDENTITY)
            elapsed = time.perf_counter() - started
            tracemalloc.start()
            try:
                discover(img, index, ctx=CTX, chunk_map=IDENTITY)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
    assert found.root_tree_candidates == roots and len(found.states) == roots
    # Every state reaches its root and the shared level-1 nodes; 1 600 blocks are referenced but
    # absent. At most MAX_MISSING of them are read and classified, the rest count as unchecked.
    total = shared * dangling
    for state in found.states:
        assert (state.found, state.referenced) == (1 + shared, 1 + shared + total)
        assert state.missing == {"zeroed": MAX_MISSING, "unchecked": total - MAX_MISSING}
        assert (state.root_tree_blocks, state.root_tree_missing) == (1 + shared, total)
    # Classification is cached across states: the shared blocks are read once per discovery run.
    assert reads <= 2 * MAX_MISSING, f"{reads} reads"
    assert elapsed < 5, f"{elapsed:.1f} s"
    assert peak < 8 << 20, f"peak {peak} bytes"


def test_discovery_memory_is_bounded_on_a_flood_of_same_generation_fragments():
    count, budget = 50_000, 16 << 20
    # Every record claims a distinct root-tree leaf of generation 50; the image holds zeros.
    records = (rec(0, bytenr=SECTOR * (i + 1)) for i in range(count))
    with scratch_dir("test_scan_roots_flood_") as d:
        with open_image(write_sparse_image(d / "flood.img", 64 * SECTOR, {})) as img:
            tracemalloc.start()
            try:
                index = index_records(records, CTX)
                found = discover(img, index, ctx=CTX, chunk_map=IDENTITY)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
    assert found.root_tree_candidates == count
    assert len(found.states) == MAX_STATES
    assert all(s.trees == () and s.missing == {"changed": 1} for s in found.states)
    (group,) = found.groups
    assert (group.blocks, group.candidates, len(group.listed)) == (count, count, MAX_LISTED)
    assert peak < budget, f"peak {peak} bytes"


# ---------------------------------------------------------------------------
# Ground truth: sandbox.img and the M1 images
# ---------------------------------------------------------------------------
def rediscovery_holds(path, damaged=None):
    """Every superblock and backup root is a candidate root; every tree the current root tree
    names is found, except `damaged` ({tree id: failure class})."""
    damaged = damaged or {}
    with open_image(path) as img:
        fs = open_filesystem(img)
        run = discover_image(img, fs, full_sweep=True)
        current_trees = [
            t for s in run.discovery.states if "current" in s.known_as for t in s.trees
        ]
        candidates = [
            run.discovery.candidate(t.bytenr, t.generation, t.level, t.tree_id)
            for t in current_trees
        ]
    found = run.discovery
    assert found.rediscovered and all(r.indexed and r.candidate for r in found.rediscovered)
    sources = {r.root.source for r in found.rediscovered}
    assert sources == {"current"} | {f"backup:{g}" for g in backup_generations(fs.fields)}
    assert current_trees
    assert {t.tree_id: t.status for t in current_trees if t.status != "found"} == damaged
    assert all(ok for t, ok in zip(current_trees, candidates, strict=True) if t.status == "found")
    return run


def backup_generations(fields):
    raw = fields["super_roots"]
    size = ondisk.ROOT_BACKUP.size
    return {
        ondisk.ROOT_BACKUP.unpack_from(raw, slot * size)["tree_root_gen"]
        for slot in range(ondisk.NUM_BACKUP_ROOTS)
        if ondisk.ROOT_BACKUP.unpack_from(raw, slot * size)["tree_root"]
    }


@pytest.mark.sandbox
def test_sandbox_discovery_rediscovers_every_superblock_and_backup_root(sandbox_img):
    run = rediscovery_holds(sandbox_img)
    states = {s.generation: s for s in run.discovery.states if s.known_as}
    assert sorted(states) == [11, 12, 13, 14]
    # Every backup state of the sandbox walks completely (research.md §10.8).
    assert all(s.completeness == 1.0 for s in states.values())


@pytest.mark.vm
@pytest.mark.parametrize(
    "name",
    ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m1_badnode",
     "m1_badnode_both", "m1_mirror_damage", "m1_foreign_mirror"],
)  # fmt: skip
def test_m1_discovery_rediscovers_every_superblock_and_backup_root(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent")
    # m1_badnode_both: the sv1 leaf (tree 256) is damaged on both copies (corpus/manifest.tsv).
    rediscovery_holds(path, {256: "corrupt"} if name == "m1_badnode_both" else None)


@pytest.mark.vm
def test_m2_logtree_superseded_logs_and_reused_backup_blocks():
    path = SCENARIOS / "m2_logtree.img"
    if not path.exists():
        pytest.skip("m2_logtree.img absent")
    with open_image(path) as img:
        found = discover_image(img, open_filesystem(img)).discovery
    # Generation 9 = superblock + 1: the live log (log root tree leaf 30982144, sv1 log leaf
    # 30965760) and the first fsync's superseded log commit (30932992, 30949376), 2 copies each.
    (log,) = found.logs
    assert (log.generation, log.blocks, log.copies, log.live, log.superseded) == (9, 4, 8, 2, 2)
    assert found.stats["log_accepted"] == 8 and found.stats["log_rejected"] == 0
    # The oldest backup root's root, extent and dev tree blocks now hold generation-7 blocks.
    reused = [(30441472, 1), (30474240, 2), (30457856, 4)]
    assert found.walk_failures == tuple(
        ("backup:5", tree, bytenr, "reused") for bytenr, tree in reused
    )
    assert [(r.root.bytenr, r.indexed) for r in found.rediscovered if not r.candidate] == [
        (bytenr, False) for bytenr, _ in reused
    ]
