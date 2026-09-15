"""Old-root discovery (scan/roots.py), reuse-versus-damage classes of unreachable blocks, and the
log-tree and raw-tree groups."""

import struct
import tracemalloc

import pytest

from btrfska.scan.classify import walk_root_set
from btrfska.scan.kernel_numpy import NodeRecord, iter_candidate_nodes
from btrfska.scan.regions import Region
from btrfska.scan.roots import (
    MAX_LISTED,
    MAX_PROBLEMS,
    MAX_STATES,
    ChunkRoot,
    KnownRoot,
    discover,
    discover_image,
    index_records,
    known_roots,
)
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


def chunk_item(physical: int, length: int) -> bytes:
    """A single-stripe METADATA chunk item on devid 1."""
    head = struct.pack("<QQQQIIIHH", length, 2, 1 << 16, METADATA, SECTOR, SECTOR, SECTOR, 1, 1)
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


def test_candidate_roots_are_the_unreferenced_highest_level_blocks_of_each_generation(history):
    _, _, found = history
    groups = {(g.owner, g.generation, g.level): g for g in found.groups}
    top = groups[(1, 90, 1)]
    assert (top.top, top.blocks, top.copies, top.candidates, top.listed) == (True, 1, 1, 1, (R90,))
    below = groups[(1, 90, 0)]  # L90A is referenced by R90; O90 is an unreferenced fragment
    assert (below.top, below.blocks, below.unreferenced, below.candidates) == (False, 2, 1, 0)
    # An unchanged older leaf is referenced by a newer parent only: a candidate of its generation.
    assert groups[(1, 85, 0)].listed == (L90B,)
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
    assert s90.completeness == pytest.approx(6 / 11)
    assert s90.chunk_root == ChunkRoot(CH60, 60, 0, "backup:90", differs_from_current=True)
    assert (s90.maps_current, s90.maps_historical, s90.maps_neither) == (6, 0, 0)

    s99 = states[R99]
    assert (s99.known_as, s99.found, s99.referenced, s99.completeness) == (("current",), 2, 2, 1.0)
    assert s99.chunk_root == ChunkRoot(CH99, 99, 0, "current", differs_from_current=False)
    assert (s99.maps_current, s99.maps_historical, s99.maps_neither) == (2, None, 0)


def test_states_beyond_the_superblock_roots_infer_their_chunk_root(history):
    _, _, found = history
    assert [(s.generation, s.known_as) for s in found.states] == [
        (99, ("current",)), (90, ("backup:90",)), (85, ()), (70, ()),
    ]  # fmt: skip
    s85, s70 = found.states[2:]
    assert (s85.found, s85.referenced) == (1, 5)
    assert s70.bytenr == R70 and s70.copies == (R70P,)
    assert (s70.found, s70.referenced, [t.status for t in s70.trees]) == (2, 2, ["found"])
    # The newest chunk-tree root no newer than the state, and it differs from the current one.
    assert s70.chunk_root == ChunkRoot(CH60, 60, 0, "inferred", differs_from_current=True)
    # R70 and E70 claim logical addresses only the generation-60 chunk items map to where they lie.
    assert (s70.maps_current, s70.maps_historical, s70.maps_neither) == (0, 2, 0)
    assert (s85.maps_current, s85.maps_historical, s85.maps_neither) == (1, 0, 0)


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
