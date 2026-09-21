"""The evidence database, second half (plan.md M3b): contents, items, edges, reverse queries.

The definition of done: the four reverse queries are answered from the database alone, with the
image file deleted, and agree with anchored walks of the current and backup roots.
"""

import hashlib
import random
import re
import shutil
import subprocess
from collections import Counter, deque

import pytest

from btrfska.catalog import build, db, query
from btrfska.catalog.content import ContentWriter, _text
from btrfska.catalog.schema import DDL, key_from_sort, key_sort, u64
from btrfska.cli import main
from btrfska.substrate import items, ondisk
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import Key
from btrfska.substrate.roots import TreeRoot, root_sets
from btrfska.substrate.tree import walk
from tests.helpers import NODESIZE, REPO_ROOT, SCENARIOS, make_node, scratch_dir

K = ondisk.ITEM_KEYS
SANDBOX = REPO_ROOT / "sandbox.img"
NAMES = {
    "ROOT_TREE": 1, "EXTENT_TREE": 2, "CHUNK_TREE": 3, "DEV_TREE": 4, "FS_TREE": 5,
    "CSUM_TREE": 7, "UUID_TREE": 9, "FREE_SPACE_TREE": 10, "BLOCK_GROUP_TREE": 11,
    "DATA_RELOC_TREE": (1 << 64) - 9,
}  # fmt: skip


# ---------------------------------------------------------------------------
# key_sort: the btrfs key order, which signed storage alone would lose
# ---------------------------------------------------------------------------
def test_key_sort_orders_keys_as_btrfs_does_including_high_objectids():
    rng = random.Random(17)
    edges = [0, 1, 255, 256, (1 << 63) - 1, 1 << 63, (1 << 64) - 9, (1 << 64) - 6, (1 << 64) - 1]
    keys = [
        Key(rng.choice(edges), rng.randrange(256), rng.choice(edges + [rng.randrange(1 << 64)]))
        for _ in range(2000)
    ]
    assert sorted(keys) == [Key(*key_from_sort(b)) for b in sorted(key_sort(*k) for k in keys)]
    assert all(len(key_sort(*k)) == 17 for k in keys)


def test_sqlite_compares_key_sort_blobs_in_that_order():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (k BLOB)")
    keys = [Key((1 << 64) - 6, 132, 5), Key(5, 1, 0), Key(256, 84, (1 << 64) - 1), Key(256, 84, 3)]
    conn.executemany("INSERT INTO t VALUES (?)", [(key_sort(*k),) for k in keys])
    stored = [Key(*key_from_sort(r[0])) for r in conn.execute("SELECT k FROM t ORDER BY k")]
    assert stored == sorted(keys)
    assert stored[-1].objectid == (1 << 64) - 6  # the log tree sorts last, not first


# ---------------------------------------------------------------------------
# ContentWriter on synthetic blocks
# ---------------------------------------------------------------------------
def _memory_db():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.executescript(DDL)
    return conn


def test_identical_copies_share_one_content_and_a_differing_copy_gets_its_own():
    conn = _memory_db()
    writer = ContentWriter(conn, NODESIZE)
    inode = bytes(ondisk.INODE_ITEM.size)
    block = make_node(30720000, items=[((256, K["INODE_ITEM"], 0), inode)])
    other = make_node(30720000, items=[((257, K["INODE_ITEM"], 0), inode)])
    first, again, different = (
        writer.add(block, True),
        writer.add(block, True),
        writer.add(other, True),
    )
    writer.flush()
    assert first == again != different
    assert conn.execute("SELECT COUNT(*) FROM contents").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 2
    row = conn.execute("SELECT sha256, parsed FROM contents WHERE content_id = ?", (first,))
    assert tuple(row.fetchone()) == (hashlib.sha256(block).hexdigest(), 1)


def test_a_content_is_parsed_only_once_some_copy_is_valid():
    conn = _memory_db()
    writer = ContentWriter(conn, NODESIZE)
    block = make_node(4096, items=[((256, K["INODE_ITEM"], 0), bytes(ondisk.INODE_ITEM.size))])
    content = writer.add(block, False)
    writer.flush()
    assert conn.execute("SELECT parsed FROM contents").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
    assert writer.add(block, True) == content
    writer.flush()
    assert conn.execute("SELECT parsed FROM contents").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1


def test_a_payload_that_does_not_parse_is_kept_raw_and_reported():
    conn = _memory_db()
    writer = ContentWriter(conn, NODESIZE)
    good = bytes(ondisk.INODE_ITEM.size)
    block = make_node(
        4096,
        items=[((256, K["INODE_ITEM"], 0), good), ((257, K["INODE_ITEM"], 0), b"short")],
    )
    writer.add(block, True)
    writer.flush()
    assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 2
    assert conn.execute("SELECT data FROM items WHERE slot = 1").fetchone()[0] == b"short"
    assert conn.execute("SELECT COUNT(*) FROM inodes").fetchone()[0] == 1
    problem = conn.execute("SELECT slot, detail FROM item_problems").fetchone()
    assert problem[0] == 1 and "INODE_ITEM" in problem[1]


def test_internal_nodes_give_key_pointers_and_a_key_range():
    conn = _memory_db()
    writer = ContentWriter(conn, NODESIZE)
    high = (1 << 64) - 6
    ptrs = [((256, 1, 0), 30408704, 7), ((high, 132, 5), 30425088, 9)]
    writer.add(make_node(30720000, level=1, ptrs=ptrs), True)
    writer.flush()
    rows = conn.execute("SELECT key_objectid, blockptr, ptr_generation FROM key_ptrs ORDER BY slot")
    assert [tuple(r) for r in rows] == [(256, 30408704, 7), (-6, 30425088, 9)]
    first, last = conn.execute("SELECT first_key, last_key FROM contents").fetchone()
    assert key_from_sort(first) == (256, 1, 0) and key_from_sort(last) == (high, 132, 5)


def test_names_are_stored_as_text_and_as_the_exact_bytes():
    assert _text("plain.txt") == ("plain.txt", b"plain.txt")
    text, raw = _text(b"bad\xff\xfename".decode("utf-8", "surrogateescape"))
    assert raw == b"bad\xff\xfename" and "bad" in text and "�" in text


# ---------------------------------------------------------------------------
# The definition of done: reverse queries with the image gone, against anchored walks
# ---------------------------------------------------------------------------
def _anchored_visits(path):
    """Every valid node that a walk of the current or a backup root reaches, tree by tree."""
    found = {}  # (bytenr, generation) -> (owner tree of the walk, node, parent logical)
    with open_image(path) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            queue = deque((tree, tree.tree_id == ondisk.ROOT_TREE_OBJECTID)
                          for tree in root_set.trees.values())  # fmt: skip
            seen = set()
            while queue:
                tree, names_trees = queue.popleft()
                if tree.bytenr in seen:
                    continue
                seen.add(tree.bytenr)
                for visit in walk(fs.reader, tree.bytenr, tree.expect()):
                    node = visit.node
                    if not node.valid:
                        continue
                    found.setdefault((node.logical, node.generation), (node, visit.parent))
                    if node.level or not names_trees:
                        continue
                    for item in node.items:
                        if item.key.type == K["ROOT_ITEM"]:
                            parsed = items.root_item(item.data)
                            queue.append((TreeRoot(item.key.objectid, parsed["bytenr"],
                                                   parsed["level"], parsed["generation"], ""),
                                          False))  # fmt: skip
    return found


def _build_then_delete_the_image(source, directory, full_sweep):
    copy = directory / "evidence.img"
    subprocess.run(["cp", "--sparse=always", str(source), str(copy)], check=True)
    database = directory / "evidence.db"
    built = build.build_catalog(copy, database, full_sweep=full_sweep)
    assert built.image_unchanged is True
    copy.unlink()
    assert not copy.exists()
    return db.open_readonly(database)


def _assert_queries_agree_with_walks(source, conn):
    visits = _anchored_visits(source)
    assert visits
    by_generation = Counter()
    for (bytenr, generation), (node, parent) in visits.items():
        block = conn.execute(
            "SELECT content_id, level, owner FROM content_blocks"
            " WHERE bytenr = ? AND generation = ?",
            (bytenr, generation),
        ).fetchone()
        assert block is not None, f"walked block {bytenr} gen {generation} is not in the database"
        assert (block["level"], u64(block["owner"])) == (node.level, node.owner)
        if node.level == 0:
            stored = conn.execute(
                "SELECT slot, key_sort, data_offset, data_size, data FROM items"
                " WHERE content_id = ? ORDER BY slot",
                (block["content_id"],),
            ).fetchall()
            assert [(r[0], key_from_sort(r[1]), r[2], r[3], r[4]) for r in stored] == [
                (i.slot, tuple(i.key), i.offset, i.size, i.data) for i in node.items
            ]
            by_generation[generation] += len(node.items)
            # trees-covering: every item key of this leaf is covered by this leaf, exactly
            for item in (node.items[0], node.items[-1]) if node.items else ():
                hits = query.trees_covering(conn, *item.key)
                assert any(h["bytenr"] == bytenr and h["generation"] == generation and h["exact"]
                           for h in hits)  # fmt: skip
        else:
            stored = conn.execute(
                "SELECT slot, key_sort, blockptr, ptr_generation FROM key_ptrs"
                " WHERE content_id = ? ORDER BY slot",
                (block["content_id"],),
            ).fetchall()
            assert [(r[0], key_from_sort(r[1]), u64(r[2]), u64(r[3])) for r in stored] == [
                (p.slot, tuple(p.key), p.blockptr, p.generation) for p in node.key_ptrs
            ]
        # parents-of: the walk's parent is among the referrers; a tree root has a ROOT_ITEM or a
        # superblock slot naming it instead
        referrers = query.parents_of(conn, bytenr, generation)
        if parent is not None:
            assert any(r["referrer"] == "node" and r["bytenr"] == parent for r in referrers)
        else:
            assert any(r["referrer"] in ("root_item", "superblock") for r in referrers)
    # items-in-generation: at least the items of the walked leaves of that generation
    for generation, count in by_generation.items():
        rows = query.items_in_generation(conn, generation)
        assert len(rows) >= count
        walked = {(b, i.slot) for (b, g), (n, _) in visits.items() if g == generation
                  and n.level == 0 for i in n.items}  # fmt: skip
        assert walked <= {(r["bytenr"], r["slot"]) for r in rows}
    return visits


@pytest.mark.sandbox
def test_sandbox_reverse_queries_agree_with_walks_with_the_image_deleted():
    with scratch_dir("catalog-") as directory:
        conn = _build_then_delete_the_image(SANDBOX, directory, full_sweep=False)
        visits = _assert_queries_agree_with_walks(SANDBOX, conn)
        assert {g for _, g in visits} >= {11, 12, 13, 14}  # the four backup generations
        assert conn.execute("SELECT COUNT(*) FROM item_problems").fetchone()[0] == 0
        # the sandbox's known history is now a query: both deleted files, by name and generation
        names = {r[0] for r in conn.execute("SELECT DISTINCT name FROM inode_refs")}
        assert {"target_file.txt", "large_target.txt"} <= names
        conn.close()


@pytest.mark.sandbox
def test_cli_query_prints_json_lines(capsys):
    import json

    with scratch_dir("catalog-") as directory:
        database = directory / "s.db"
        build.build_catalog(SANDBOX, database, rehash=False)
        conn = db.open_readonly(database)
        bytenr, generation = conn.execute(
            "SELECT bytenr, generation FROM known_roots WHERE source = 'current' AND tree = 'root'"
        ).fetchone()
        conn.close()
        assert main(["catalog", "query", str(database), "parents-of", str(bytenr)]) == 0
        captured = capsys.readouterr()
        rows = [json.loads(line) for line in captured.out.splitlines()]
        assert {"superblock"} == {r["referrer"] for r in rows}
        assert "parents-of: 2 rows" in captured.err
        args = ["catalog", "query", str(database), "items-in-generation", str(generation)]
        assert main([*args, "--type", "1", "--limit", "3"]) == 0
        rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert len(rows) == 3 and {r["type_name"] for r in rows} == {"INODE_ITEM"}
        assert main(["catalog", "query", str(database), "trees-covering", "256", "1", "0"]) == 0
        assert main(["catalog", "query", str(database), "owners-of", "0x0"]) == 0
        assert main(["catalog", "query", str(directory / "absent.db"), "owners-of", "1"]) == 1


# ---------------------------------------------------------------------------
# Corpus images (vm)
# ---------------------------------------------------------------------------
def _corpus_image(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    return path


@pytest.mark.vm
@pytest.mark.parametrize("name", ["m3_wide", "s01_discard_none_r1", "m2_logtree", "m1_sha256_bgt"])
def test_corpus_reverse_queries_agree_with_walks_with_the_image_deleted(name):
    source = _corpus_image(name)
    with scratch_dir("catalog-") as directory:
        conn = _build_then_delete_the_image(source, directory, full_sweep=True)
        visits = _assert_queries_agree_with_walks(source, conn)
        if name == "m3_wide":
            # the scenario exists to grow internal nodes: parents-of was checked on real edges
            assert any(parent is not None for _, parent in visits.values())
            levels = dict(conn.execute("SELECT owner, MAX(level) FROM blocks GROUP BY owner"))
            assert levels[1] >= 1 and levels[5] >= 1
            edges = conn.execute("SELECT COUNT(*), SUM(child_found) FROM tree_edges").fetchone()
            assert edges[0] > 500
        conn.close()


@pytest.mark.vm
def test_owners_of_a_data_extent_joins_file_extents_and_the_extent_tree():
    source = _corpus_image("m3_wide")
    with scratch_dir("catalog-") as directory:
        conn = _build_then_delete_the_image(source, directory, full_sweep=True)
        extent = conn.execute(
            "SELECT disk_bytenr FROM file_extents f JOIN content_blocks b USING (content_id)"
            " WHERE disk_bytenr > 0 AND b.live ORDER BY disk_bytenr LIMIT 1"
        ).fetchone()[0]
        rows = query.owners_of(conn, extent)
        files = [r for r in rows if r["referrer"] == "file_extent"]
        refs = [r for r in rows if r["referrer"] == "extent_backref"]
        assert files and refs
        assert any(r["reach"] == "live" for r in files) and any(r["reach"] == "live" for r in refs)
        named = {r["inode"] for r in refs if r["ref_type_name"] == "EXTENT_DATA_REF"}
        assert named and named <= {r["inode"] for r in files}
        assert len({r["generation"] for r in files}) > 1  # the extent's history, not one state
        conn.close()


@pytest.mark.vm
@pytest.mark.parametrize("name", ["m3_wide", "s01_discard_none_r1"])
def test_extent_back_references_equal_btrfs_dump_tree(name):
    """An independent oracle for the new extent parser. The tool only ever sees a scratch copy."""
    if shutil.which("btrfs") is None:
        pytest.skip("btrfs-progs is not installed")
    source = _corpus_image(name)
    with scratch_dir("catalog-") as directory:
        copy = directory / "copy.img"
        subprocess.run(["cp", "--sparse=always", str(source), str(copy)], check=True)
        dumped = subprocess.run(
            ["btrfs", "inspect-internal", "dump-tree", "-t", "extent", str(copy)],
            capture_output=True, text=True, check=True,
        ).stdout  # fmt: skip
        conn = db.open_readonly(_database(copy, directory))
        ours = Counter(
            (u64(r["extent_bytenr"]), r["ref_type_name"], u64(r["root"]), u64(r["parent"]),
             u64(r["objectid"]), u64(r["file_offset"]), r["ref_count"])
            for r in conn.execute(
                "SELECT r.* FROM extent_backrefs r JOIN content_blocks b USING (content_id)"
                " WHERE b.live AND b.owner = 2"
            )
        )  # fmt: skip
        conn.close()
    theirs, current = Counter(), None

    def root_id(text):
        return NAMES[text] if text in NAMES else int(text)

    for line in dumped.splitlines():
        if m := re.search(r"item \d+ key \((\d+) \w+ ", line):
            current = int(m.group(1))
        if m := re.search(r"tree block backref root (\S+)", line):
            theirs[(current, "TREE_BLOCK_REF", root_id(m.group(1)), None, None, None, None)] += 1
        if m := re.search(r"shared block backref parent (\d+)", line):
            theirs[(current, "SHARED_BLOCK_REF", None, int(m.group(1)), None, None, None)] += 1
        if m := re.search(r"extent data backref root (\S+) objectid (\d+) offset (\d+) count (\d+)",
                          line):  # fmt: skip
            theirs[(current, "EXTENT_DATA_REF", root_id(m.group(1)), None, int(m.group(2)),
                    int(m.group(3)), int(m.group(4)))] += 1  # fmt: skip
        if m := re.search(r"shared data backref parent (\d+) count (\d+)", line):
            theirs[(current, "SHARED_DATA_REF", None, int(m.group(1)), None, None,
                    int(m.group(2)))] += 1  # fmt: skip
    assert theirs and ours == theirs


def _database(image, directory):
    database = directory / "oracle.db"
    build.build_catalog(image, database, full_sweep=True, rehash=False)
    return database
