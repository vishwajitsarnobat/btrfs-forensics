"""The orphan graph (plan.md M5c): fragments by key pointer, sibling and parent-path joins, the
refusal of what cannot be justified, and the rule that a file whose extent is newer than its
INODE_ITEM is not complete.

A wrong join makes a file that never existed. The rules are tested on forged leaves, one refusal
each; the claims on `m4_deep`, against what its scenario can have written.
"""

import json
import re
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.dbtree import fragment_roots, orphan_leaves
from btrfska.recover.engine import recover
from btrfska.recover.inodes import Name, paths
from btrfska.substrate import ondisk
from experiments.exp008 import EMPTY, TRUTH, padding_contents
from tests.helpers import SCENARIOS, scratch_dir
from tests.test_recover import (
    DATA_LOGICAL,
    DATA_PHYS,
    META_LOGICAL,
    NODESIZE,
    ROOT_DIR_ITEMS,
    by_source,
    dir_items_,
    file_items,
    files_under,
    inode_item,
    inode_ref,
    run,
    synthetic,
)

K = ondisk.ITEM_KEYS
SECTOR = 4096
DEEP = SCENARIOS / "m4_deep.img"


def regular(file_offset_sector: int, sectors: int = 1, generation: int = 7) -> bytes:
    """A regular extent of `sectors` sectors whose data lies `file_offset_sector` sectors into
    the synthetic data chunk."""
    length = sectors * SECTOR
    return struct.pack(
        ondisk.FILE_EXTENT_ITEM.format, generation, length, 0, 0, 0, ondisk.FILE_EXTENT_REG,
        DATA_LOGICAL + file_offset_sector * SECTOR, length, 0, length,
    )  # fmt: skip


DATA = {DATA_PHYS + n * SECTOR: bytes([65 + n]) * SECTOR for n in range(8)}
HEAD = [
    *ROOT_DIR_ITEMS,
    *file_items(257, b"whole", b"fits"),
    ((258, K["INODE_ITEM"], 0), inode_item(3 * SECTOR)),
    ((258, K["INODE_REF"], 256), inode_ref(b"cut")),
    ((258, K["EXTENT_DATA"], 0), regular(0)),
]


def tail(*extents, more=()) -> list:
    """A leaf that begins inside inode 258: (file offset in sectors, data sector, generation)."""
    items = [
        ((258, K["EXTENT_DATA"], offset * SECTOR), regular(sector, 1, generation))
        for offset, sector, generation in extents
    ]
    return [*items, *more]


def graph_run(loose, trees=None, **options):
    trees = trees or {"current": list(ROOT_DIR_ITEMS)}
    context = synthetic(trees, DATA, loose=tuple(loose))
    conn, reader, out = context.__enter__()
    try:
        notes: list[str] = []
        run(conn, reader, out, orphans=True, graph=True, notes=notes, **options)
        # a tail read on its own is an artifact too (`unknown`, no INODE_ITEM): leave it out
        rows = conn.execute("SELECT * FROM artifacts WHERE kind != 'unknown'")
        return {(r["source_kind"], r["objectid"]): r for r in rows}, files_under(out), notes
    finally:
        context.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Sibling joins
# ---------------------------------------------------------------------------


def test_a_cut_file_is_continued_in_the_leaf_that_fits_exactly_and_the_artifact_says_so():
    rows, written, _ = graph_run(
        [HEAD, tail((1, 1, 7), (2, 2, 7), more=file_items(259, b"n", b"x"))]
    )
    row = rows["orphan_graph", 258]
    assert (row["status"], row["path"]) == ("complete", "cut")
    (join,) = json.loads(row["joined"])
    assert join["kind"] == "sibling" and len(join["leaves"]) == 2 and "exactly" in join["evidence"]
    (content,) = [data for name, data in written.items() if name.endswith("/cut")]
    assert content == b"A" * SECTOR + b"B" * SECTOR + b"C" * SECTOR
    # what needed no join is not called a join
    assert rows["orphan_node", 257]["joined"] == "[]"


def test_without_graph_nothing_is_joined_as_in_m4():
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, DATA,
                   loose=(HEAD, tail((1, 1, 7), (2, 2, 7)))) as (conn, reader, out):  # fmt: skip
        run(conn, reader, out, orphans=True)
        row = by_source(conn)["orphan_node", 258]
        assert row["status"] == "partial" and "continues_elsewhere" in row["missing"]


def test_a_file_over_three_leaves_is_followed_through_the_middle_one():
    rows, written, _ = graph_run([HEAD, tail((1, 1, 7)), tail((2, 2, 7))])
    row = rows["orphan_graph", 258]
    assert row["status"] == "complete"
    assert len(json.loads(row["joined"])[0]["leaves"]) == 3


@pytest.mark.parametrize(
    ("tails", "reason"),
    [
        ([tail((1, 1, 7), (2, 2, 7)), tail((1, 3, 7), (2, 4, 7))], "ambiguous continuation"),
        ([tail((1, 1, 7))], "the file has"),  # too short, and nothing continues it
        ([tail((2, 2, 7))], "gap"),
        ([tail((1, 1, 7), (2, 2, 7), (3, 3, 7))], "past the file"),
        ([tail((1, 1, 9), (2, 2, 9))], "newer than the INODE_ITEM"),
        # a leaf written before the inode's last change (generation 5, transid 7)
        ([{"items": tail((1, 1, 5), (2, 2, 5)), "generation": 5}], "cannot be excluded"),
        ([], "no scanned leaf of this tree continues"),
    ],
)
def test_a_continuation_that_cannot_be_justified_is_refused_with_the_reason(tails, reason):
    rows, _, _ = graph_run([HEAD, *tails])
    row = rows["orphan_node", 258]  # no join: it stays what M4 made it
    assert row["status"] == "partial" and row["joined"] == "[]"
    assert any("not joined with another leaf" in p and reason in p
               for p in json.loads(row["problems"]))  # fmt: skip


def test_two_tails_with_identical_items_are_one_candidate():
    same = tail((1, 1, 7), (2, 2, 7))
    rows, _, _ = graph_run([HEAD, same, list(same)])
    assert rows["orphan_graph", 258]["status"] == "complete"


def test_a_tail_in_another_tree_is_not_a_candidate():
    other = {"items": tail((1, 1, 7), (2, 2, 7)), "owner": 300}
    rows, _, _ = graph_run([HEAD, other])
    assert rows["orphan_node", 258]["status"] == "partial"


# ---------------------------------------------------------------------------
# Parent paths
# ---------------------------------------------------------------------------

IN_DOCS = [*file_items(400, b"report.txt", b"body", parent=300)]


def test_a_missing_parent_is_named_when_its_number_has_one_name_in_the_tree():
    elsewhere = [
        *dir_items_(300, b"docs"),
        ((300, K["DIR_INDEX"], 2), _dir_index(400, b"report.txt")),
    ]
    rows, written, _ = graph_run([IN_DOCS, elsewhere])
    row = rows["orphan_graph", 400]
    assert (row["path"], row["attached"], row["status"]) == ("docs/report.txt", 1, "complete")
    (join,) = json.loads(row["joined"])
    assert join["kind"] == "parent_path" and join["objectid"] == 300
    assert join["dir_index_names_this_file"] is True and "only name" in join["evidence"]
    assert any(name.endswith("/docs/report.txt") for name in written)


def _dir_index(child: int, name: bytes) -> bytes:
    head = struct.pack(ondisk.DIR_ITEM.format, child, K["INODE_ITEM"], 0, 7, 0, len(name), 1)
    return head + name


def test_a_parent_number_with_two_names_gives_no_path_and_says_why():
    rows, _, _ = graph_run([IN_DOCS, dir_items_(300, b"docs"), dir_items_(300, b"renamed")])
    row = rows["orphan_node", 400]
    assert row["attached"] == 0 and row["path"].startswith(".btrfska-unattached/")
    assert any("no path" in p and "ambiguous" in p for p in json.loads(row["problems"]))


def test_a_parent_number_used_by_two_inodes_gives_no_path():
    first = [((300, K["INODE_ITEM"], 0), inode_item(0, mode=0o040755, generation=3)),
             ((300, K["INODE_REF"], 256), inode_ref(b"docs"))]  # fmt: skip
    second = [((300, K["INODE_ITEM"], 0), inode_item(0, mode=0o040755, generation=9)),
              ((300, K["INODE_REF"], 256), inode_ref(b"docs"))]  # fmt: skip
    rows, _, _ = graph_run([IN_DOCS, first, second])
    assert rows["orphan_node", 400]["attached"] == 0


def test_a_cycle_of_parents_ends_unattached_without_a_crash():
    loop = [*dir_items_(300, b"a", parent=301)]
    back = [*dir_items_(301, b"b", parent=300)]
    rows, _, _ = graph_run([IN_DOCS, loop, back])
    row = rows["orphan_node", 400]  # a chain that leads nowhere is no join
    assert row["attached"] == 0 and row["joined"] == "[]"


def test_paths_take_ancestors_only_for_directories_the_leaves_do_not_hold():
    from btrfska.recover.inodes import InodeRecord

    inodes = {400: InodeRecord(400, names=[Name(300, b"f", 2, False)])}
    located = paths(inodes, {300: Name(256, b"docs", 2, False)})
    assert located == {400: ((b"docs", b"f"), True)}
    assert paths(inodes) == {400: ((b".btrfska-unattached", b"300", b"f"), False)}


# ---------------------------------------------------------------------------
# Fragments
# ---------------------------------------------------------------------------


def fragment(children, **extra) -> dict:
    return {"ptrs": children, "bytenr": META_LOGICAL + 200 * NODESIZE, "generation": 30} | extra


def leaf_at(number: int, items: list, generation: int = 30, owner: int = 5) -> dict:
    return {"items": items, "bytenr": META_LOGICAL + number * NODESIZE,
            "generation": generation, "owner": owner}  # fmt: skip


def test_a_tree_version_nothing_names_is_walked_from_its_top_and_says_what_it_is():
    left = leaf_at(100, [*ROOT_DIR_ITEMS, *dir_items_(300, b"docs")])
    right = leaf_at(101, IN_DOCS)
    top = fragment([((256, K["INODE_ITEM"], 0), left["bytenr"], 30),
                    ((400, K["INODE_ITEM"], 0), right["bytenr"], 30)])  # fmt: skip
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, DATA, loose=(left, right, top)) as (
        conn, reader, out,
    ):  # fmt: skip
        total, tops = fragment_roots(conn, 10)
        assert total == 1 and tops[0].source == f"fragment:{top['bytenr']}@30"
        run(conn, reader, out, orphans=True, graph=True, fragments=tuple(tops))
        rows = by_source(conn)
        row = rows["orphan_graph", 400]
        assert (row["path"], row["attached"], row["source"]) == (
            "docs/report.txt", 1, tops[0].source,
        )  # fmt: skip
        (join,) = json.loads(row["joined"])
        assert join["kind"] == "pointer" and join["leaves"] == 2 and join["gaps"] == 0
        assert "never a committed state" in join["evidence"]
        # the leaves under the fragment are not read again on their own
        assert not [key for key in rows if key[0] == "orphan_node"]
        assert any("orphan_graph/tree_5/fragment_" in name for name in files_under(out))


def test_a_pointer_to_a_block_of_another_tree_or_first_key_is_a_gap_not_a_join():
    foreign = leaf_at(100, IN_DOCS, owner=2)  # an extent-tree block at that address
    shifted = leaf_at(101, file_items(500, b"x", b"y"))
    top = fragment([((400, K["INODE_ITEM"], 0), foreign["bytenr"], 30),
                    ((450, K["INODE_ITEM"], 0), shifted["bytenr"], 30)])  # fmt: skip
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, DATA, loose=(foreign, shifted, top)) as (
        conn, reader, out,
    ):  # fmt: skip
        _, tops = fragment_roots(conn, 10)
        _, gaps = run(conn, reader, out, graph=True, fragments=tuple(tops))
        lines = gaps[f"{tops[0].source} tree 5"]
        assert any("linkage mismatch: owner" in line for line in lines)
        assert any("linkage mismatch: first_key" in line for line in lines)
        assert not conn.execute("SELECT 1 FROM artifacts WHERE source LIKE 'fragment:%'").fetchall()


def test_a_node_some_pointer_or_root_item_names_is_not_a_fragment():
    child = fragment([((256, K["INODE_ITEM"], 0), META_LOGICAL + 100 * NODESIZE, 30)])
    parent = {"ptrs": [((256, K["INODE_ITEM"], 0), child["bytenr"], 30)],
              "bytenr": META_LOGICAL + 300 * NODESIZE, "generation": 30}  # fmt: skip
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, DATA, loose=(child, parent)) as (conn, _, _):
        total, tops = fragment_roots(conn, 10)
        assert total == 1 and tops[0].bytenr == parent["bytenr"]
        assert fragment_roots(conn, 0) == (1, [])  # the bound keeps the count


# ---------------------------------------------------------------------------
# An extent newer than the inode item
# ---------------------------------------------------------------------------


def test_a_file_whose_extent_is_newer_than_its_inode_item_is_not_complete():
    stale = [
        ((257, K["INODE_ITEM"], 0), inode_item(SECTOR, generation=7)),
        ((257, K["INODE_REF"], 256), inode_ref(b"rewritten")),
        ((257, K["EXTENT_DATA"], 0), regular(0, 1, generation=9)),
    ]
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, DATA, loose=(stale,)) as (conn, reader, out):
        run(conn, reader, out, orphans=True)
        row = by_source(conn)["orphan_node", 257]
        assert row["status"] == "partial" and row["sha256"] is None
        assert json.loads(row["missing"]) == [[0, SECTOR, "inode_item_older_than_extent"]]
        assert any("newer than the INODE_ITEM" in p for p in json.loads(row["problems"]))


def test_in_an_uncommitted_block_data_past_the_end_of_the_file_means_the_same():
    """Created at size 0, written a moment later, both in one transaction: the generations
    agree, the sizes do not. In a committed tree the same items are what the kernel shows."""
    early = [
        ((257, K["INODE_ITEM"], 0), inode_item(0, generation=7)),
        ((257, K["INODE_REF"], 256), inode_ref(b"just-created")),
        ((257, K["EXTENT_DATA"], 0), regular(0, 2, generation=7)),
    ]
    with synthetic({"current": [*ROOT_DIR_ITEMS, *early]}, DATA, loose=([*early],)) as (
        conn, reader, out,
    ):  # fmt: skip
        run(conn, reader, out, orphans=True, dedup=False)
        rows = by_source(conn)
        assert rows["anchored_root", 257]["status"] == "complete"
        lone = rows["orphan_node", 257]
        assert lone["status"] == "partial"
        assert json.loads(lone["missing"]) == [[0, 0, "inode_item_older_than_extent"]]
        assert any("earlier moment" in p for p in json.loads(lone["problems"]))


# ---------------------------------------------------------------------------
# m4_deep: against what its scenario can have written
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deep():
    if not DEEP.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    with scratch_dir("test_graph_deep_") as directory:
        build_catalog(DEEP, directory / "evidence.db", full_sweep=True)
        done = recover(DEEP, directory / "evidence.db", directory / "out", roots=("all",),
                       tree_id=None, graph=True)  # fmt: skip
        conn = db.open_readonly(directory / "evidence.db")
        yield conn, done
        conn.close()


def whole(conn, row):
    if row["status"] != "duplicate":
        return row
    return conn.execute(
        "SELECT * FROM artifacts WHERE artifact_id = ?", (row["duplicate_of"],)
    ).fetchone()


def test_every_joined_artifact_says_what_was_joined_and_every_leaf_is_read_once(deep):
    conn, done = deep
    rows = conn.execute("SELECT * FROM artifacts WHERE source_kind = 'orphan_graph'").fetchall()
    assert rows and all(json.loads(row["joined"]) for row in rows)
    others = conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE source_kind != 'orphan_graph' AND joined != '[]'"
    ).fetchone()[0]
    assert others == 0
    orphan = {leaf.bytenr for _, leaf in orphan_leaves(conn)}
    assert done.fragments and done.fragments == done.fragments_found
    under = {r[0] for r in conn.execute(
        "SELECT DISTINCT p.bytenr FROM provenance p JOIN artifacts a USING (artifact_id)"
        " WHERE a.source LIKE 'fragment:%'")}  # fmt: skip
    alone = {
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT a.root_bytenr FROM artifacts a WHERE a.source LIKE 'orphan_node:%'"
        )
    }
    assert orphan & under and not under & alone  # most orphan leaves hang under a fragment
    assert orphan <= under | alone | _empty_leaves(conn, orphan)


def _empty_leaves(conn, leaves) -> set[int]:
    """Orphan leaves that hold no inode (only directory index items, say) give no artifact."""
    found = set()
    for bytenr in leaves:
        count = conn.execute(
            "SELECT COUNT(*) FROM items i JOIN content_blocks b USING (content_id)"
            " WHERE b.bytenr = ? AND i.key_type IN (1, 12, 13, 24, 108)", (bytenr,)
        ).fetchone()[0]  # fmt: skip
        if not count:
            found.add(bytenr)
    return found


def test_no_joined_file_of_the_deep_image_has_a_content_its_scenario_cannot_have_written(deep):
    conn, _ = deep
    truth = dict(TRUTH.findall(DEEP.with_suffix(".log").read_text()))
    checked = 0
    for row in conn.execute("SELECT * FROM artifacts WHERE source_kind = 'orphan_graph'"):
        content = whole(conn, row)
        if row["kind"] != "file" or content["status"] != "complete":
            continue
        if content["size"] == 0 and content["sha256"] == EMPTY:
            continue  # a version between truncation and rewrite: a true one
        name = row["path"].rsplit("/", 1)[-1]
        if name in truth:
            checked += 1
            assert content["sha256"] == truth[name], row["path"]
        elif re.fullmatch(r"pad/p\d+", row["path"]):
            checked += 1
            assert content["sha256"] in padding_contents(int(name[1:])), row["path"]
    assert checked


def test_no_committed_tree_holds_an_extent_newer_than_its_inode_item(deep):
    conn, _ = deep
    kinds = {
        row[0] for row in conn.execute(
            "SELECT DISTINCT source_kind FROM artifacts"
            " WHERE missing LIKE '%inode_item_older_than_extent%'"
        )
    }  # fmt: skip
    assert kinds and kinds <= {"orphan_graph", "orphan_node"}
