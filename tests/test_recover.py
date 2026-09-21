"""`btrfska recover`: the output writer, the append-only database, and recovery itself.

Three layers, each against what it can be checked against:
- the writer and the authorizer on their own;
- the engine on synthetic trees, where names, parents and extents are hostile on purpose;
- the whole command on `sandbox.img` and corpus images, against `read_file` (the path `btrfska
  cat` and the oracle tests use), walking the same roots through the image.
"""

import hashlib
import json
import os
import random
import sqlite3
import stat
import struct
import tracemalloc
from contextlib import contextmanager
from pathlib import Path

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.content import ContentWriter
from btrfska.catalog.schema import RECOVERY_TABLES, SCHEMA_VERSION
from btrfska.cli import main
from btrfska.recover.dbtree import Root, RootNotCataloged, resolve_roots, tree_leaves
from btrfska.recover.engine import RecoveryError, recover, recover_roots
from btrfska.recover.inodes import UNATTACHED, paths, safe_component
from btrfska.recover.output import PARTIAL, OutputError, OutputTree
from btrfska.substrate import items as parsers
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import Chunk, ChunkMap, Stripe
from btrfska.substrate.extents import read_file, stream_extent
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import Item, Key, NodeReader
from btrfska.substrate.roots import root_sets, subvolumes
from btrfska.substrate.tree import walk
from tests.helpers import (
    DEV_UUID,
    NODESIZE,
    REPO_ROOT,
    SCENARIOS,
    make_node,
    node_ctx,
    scratch_dir,
    write_sparse_image,
)

BG = ondisk.BLOCK_GROUP_FLAGS
K = ondisk.ITEM_KEYS
MIB = 1 << 20
META_LOGICAL, META_PHYS = 1 << 30, 1 * MIB
DATA_LOGICAL, DATA_PHYS = 2 << 30, 4 * MIB
SANDBOX = REPO_ROOT / "sandbox.img"


# ---------------------------------------------------------------------------
# The output writer
# ---------------------------------------------------------------------------
def test_the_output_directory_must_not_exist():
    with scratch_dir("test_recover_") as d:
        (d / "taken").mkdir()
        (d / "file").write_bytes(b"evidence")
        for path in (d / "taken", d / "file", d / "missing" / "below"):
            with pytest.raises(OutputError):
                OutputTree(path)
        assert (d / "file").read_bytes() == b"evidence"


@pytest.mark.parametrize("name", [b"", b".", b"..", b"a/b", b"a\0b", b"x" * 256])
def test_unusable_components_are_refused_by_the_writer_itself(name):
    with scratch_dir("test_recover_") as d, OutputTree(d / "out") as out:
        with pytest.raises(OutputError):
            out.create((b"dir", name))
        with pytest.raises(OutputError):
            out.make_dir((name,), None, None)


def test_a_file_is_partial_until_promoted_and_nothing_is_ever_replaced():
    with scratch_dir("test_recover_") as d, OutputTree(d / "out") as out:
        sink = out.create((b"a", b"f.txt"))
        sink.write(b"one")
        digest = sink.close(0o640, (1_000_000_000, 2_000_000_000))
        assert digest == hashlib.sha256(b"one").hexdigest()
        assert (d / "out/a/f.txt.partial").read_bytes() == b"one"
        assert not (d / "out/a/f.txt").exists()
        out.promote((b"a", b"f.txt"))
        target = d / "out/a/f.txt"
        assert target.read_bytes() == b"one" and not (d / "out/a/f.txt.partial").exists()
        assert target.stat().st_mode & 0o7777 == 0o640 and target.stat().st_mtime == 2
        again = out.create((b"a", b"f.txt"))
        again.write(b"two")
        again.close(None, None)
        with pytest.raises(FileExistsError):  # the promoted name is taken now
            out.promote((b"a", b"f.txt"))
        assert target.read_bytes() == b"one"
        assert (d / "out/a/f.txt.partial").read_bytes() == b"two"


def test_setuid_setgid_and_sticky_bits_are_never_applied():
    with scratch_dir("test_recover_") as d, OutputTree(d / "out") as out:
        out.create((b"f",)).close(0o106755, None)
        assert (d / "out/f.partial").stat().st_mode & 0o7777 == 0o755


def test_zero_runs_become_holes_and_count_towards_length_and_hash():
    with scratch_dir("test_recover_") as d, OutputTree(d / "out") as out:
        sink = out.create((b"sparse",))
        sink.write(b"ab")
        sink.zeros(3 * MIB)
        sink.write(b"cd")
        sink.zeros(MIB)  # a file ending in a hole still has its full length
        digest = sink.close(None, None)
        data = (d / "out/sparse.partial").read_bytes()
        assert data == b"ab" + bytes(3 * MIB) + b"cd" + bytes(MIB)
        assert digest == hashlib.sha256(data).hexdigest() and sink.written == len(data)


def test_a_planted_symlink_is_not_followed():
    with scratch_dir("test_recover_") as d:
        outside = d / "outside"
        outside.mkdir()
        with OutputTree(d / "out") as out:
            os.symlink(outside, d / "out" / "link")
            with pytest.raises(OutputError):
                out.create((b"link", b"escaped"))
            os.symlink(outside / "target", d / "out" / ("f" + PARTIAL.decode()))
            with pytest.raises(OSError):
                out.create((b"f",))
        assert list(outside.iterdir()) == []


def test_directory_metadata_is_applied_at_close_and_never_locks_the_owner_out():
    with scratch_dir("test_recover_") as d:
        with OutputTree(d / "out") as out:
            out.make_dir((b"top",), 0o040000, (5_000_000_000, 6_000_000_000))
            out.create((b"top", b"child")).close(None, None)
        top = d / "out/top"
        assert top.stat().st_mode & 0o777 == 0o700 and top.stat().st_mtime == 6
        assert (top / "child.partial").exists()


# ---------------------------------------------------------------------------
# The database accepts a recovery's rows and nothing else
# ---------------------------------------------------------------------------
def _sandbox_db(directory: Path) -> Path:
    path = directory / "sandbox.db"
    build_catalog(SANDBOX, path, full_sweep=True)
    return path


def test_the_recovery_connection_cannot_change_what_the_scan_wrote():
    with scratch_dir("test_recover_") as d:
        conn = db.open_for_recovery(_sandbox_db(d))
        conn.execute(
            "INSERT INTO recovery_runs (tool_version, started_utc, image_path, image_checked,"
            " output_dir, options) VALUES ('t', 'now', 'i', 1, 'o', '{}')"
        )
        conn.execute("UPDATE recovery_runs SET finished_utc = 'later'")
        for statement in (
            "UPDATE scan_runs SET image_path = 'elsewhere'",
            "UPDATE nodes SET status = 'live'",
            "DELETE FROM items",
            "DELETE FROM recovery_runs",
            "INSERT INTO problems (source, detail) VALUES ('x', 'y')",
            "DROP TABLE nodes",
            "CREATE TABLE extra (a)",
            "PRAGMA user_version = 9",
            "ATTACH DATABASE ':memory:' AS other",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                conn.execute(statement)
        conn.close()


def test_a_version_2_database_is_refused():
    with scratch_dir("test_recover_") as d:
        path = _sandbox_db(d)
        raw = sqlite3.connect(path)
        raw.execute("PRAGMA user_version = 2")
        raw.commit()
        raw.close()
        with pytest.raises(db.CatalogError, match="schema version 2"):
            db.open_for_recovery(path)
    assert SCHEMA_VERSION == 3 and set(RECOVERY_TABLES) == {
        "recovery_runs", "artifacts", "provenance"
    }  # fmt: skip


# ---------------------------------------------------------------------------
# Synthetic trees: hostile names, parents and extents
# ---------------------------------------------------------------------------
def inode_item(size: int, mode: int = 0o100644, generation: int = 7, **fields) -> bytes:
    values = dict.fromkeys(ondisk.INODE_ITEM.fields, 0)
    values |= {"size": size, "mode": mode, "generation": generation, "transid": generation}
    values |= fields
    return struct.pack(ondisk.INODE_ITEM.format, *(values[f] for f in ondisk.INODE_ITEM.fields))


def inode_ref(name: bytes, index: int = 2) -> bytes:
    return struct.pack(ondisk.INODE_REF.format, index, len(name)) + name


def inode_extref(parent: int, name: bytes, index: int = 3) -> bytes:
    return struct.pack(ondisk.INODE_EXTREF.format, parent, index, len(name)) + name


def dir_item(child: int, name: bytes, file_type: int, value: bytes = b"") -> bytes:
    head = struct.pack(
        ondisk.DIR_ITEM.format, child, K["INODE_ITEM"], 0, 7, len(value), len(name), file_type
    )
    return head + name + value


def inline(data: bytes) -> bytes:
    return struct.pack("<QQBBHB", 7, len(data), 0, 0, 0, ondisk.FILE_EXTENT_INLINE) + data


def regular(disk_bytenr, length, encryption=0) -> bytes:
    return struct.pack(
        ondisk.FILE_EXTENT_ITEM.format, 7, length, 0, encryption, 0, ondisk.FILE_EXTENT_REG,
        disk_bytenr, length, 0, length,
    )  # fmt: skip


def file_items(objectid: int, name: bytes, data: bytes, parent: int = 256, **inode) -> list:
    return [
        ((objectid, K["INODE_ITEM"], 0), inode_item(len(data), **inode)),
        ((objectid, K["INODE_REF"], parent), inode_ref(name)),
        ((objectid, K["EXTENT_DATA"], 0), inline(data)),
    ]


def dir_items_(objectid: int, name: bytes, parent: int = 256) -> list:
    return [
        ((objectid, K["INODE_ITEM"], 0), inode_item(0, mode=0o040755)),
        ((objectid, K["INODE_REF"], parent), inode_ref(name)),
    ]


ROOT_DIR_ITEMS = [((256, K["INODE_ITEM"], 0), inode_item(0, mode=0o040755))]


def _catalog(conn, trees: dict[str, list]) -> None:
    """One single-leaf fs tree per source, cataloged as the scan would have."""
    conn.execute("INSERT INTO regions (region_id, scanned, kind, start_offset, end_offset)"
                 " VALUES (1, 1, 'METADATA', 0, 1)")  # fmt: skip
    writer = ContentWriter(conn, NODESIZE)
    for number, (source, items) in enumerate(trees.items(), start=1):
        bytenr, generation = META_LOGICAL + number * NODESIZE, 7 + number
        items = sorted(items, key=lambda entry: entry[0])
        leaf = make_node(bytenr, items=items, owner=5, generation=generation)
        content_id = writer.add(leaf, True)
        conn.execute(
            "INSERT INTO nodes (physical, region_id, bytenr, generation, owner, level, nritems,"
            " valid, status, orphan, outside_map, legacy_orphan, log_tree, bytenr_mapped,"
            " maps_here, problems, content_id)"
            " VALUES (?, 1, ?, ?, 5, 0, ?, 1, 'live', 0, 0, 0, 0, 1, 1, '[]', ?)",
            (META_PHYS + number * NODESIZE, bytenr, generation, len(items), content_id),
        )
        conn.execute(
            "INSERT INTO states (state_id, bytenr, generation, level, known_as, root_tree_blocks,"
            " root_tree_missing, found, referenced, completeness, missing, maps_current,"
            " maps_neither, level_consistent, problems)"
            " VALUES (?, ?, ?, 0, ?, 1, 0, 1, 1, 1.0, '{}', 1, 0, 1, '[]')",
            (number, 9000 + number, generation, json.dumps([source])),
        )
        conn.execute(
            "INSERT INTO state_trees VALUES (?, 0, 5, 0, ?, ?, 0, ?, 0, 'found', 1, 0)",
            (number, bytenr, generation, 9000 + number),
        )
    writer.flush()
    conn.execute(
        "INSERT INTO recovery_runs (recovery_id, tool_version, started_utc, image_path,"
        " image_checked, output_dir, options) VALUES (1, 't', 'now', 'i', 1, 'o', '{}')"
    )


@contextmanager
def synthetic(trees: dict[str, list], data: dict[int, bytes] | None = None, size=16 * MIB):
    """(conn, reader, output directory path) over synthetic fs trees and a sparse image."""
    chunks = [Chunk(DATA_LOGICAL, 512 * MIB, BG["DATA"], (Stripe(1, DATA_PHYS, DEV_UUID),))]
    with scratch_dir("test_recover_") as d:
        conn = db.create(d / "synthetic.db")
        conn.row_factory = sqlite3.Row
        _catalog(conn, trees)
        path = write_sparse_image(d / "fs.img", size, data or {})
        with open_image(path) as img:
            reader = NodeReader(img, ChunkMap("test", chunks, {1: DEV_UUID}), node_ctx())
            yield conn, reader, d / "out"
        conn.close()


def run(conn, reader, out_dir, sources=("current",), notes=None, **options):
    roots = tuple(root for s in sources for root in resolve_roots(conn, s, 5))
    with OutputTree(out_dir) as out:
        note = (notes if notes is not None else []).append
        return recover_roots(conn, reader, out, 1, roots, no_holes=True, note=note, **options)


def artifacts(conn) -> dict[int, sqlite3.Row]:
    return {row["objectid"]: row for row in conn.execute("SELECT * FROM artifacts")}


def files_under(path: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(path)): p.read_bytes()
        for p in sorted(path.rglob("*"))
        if p.is_file() and p.name != "manifest.jsonl"
    }


def test_files_directories_names_xattrs_and_hard_links():
    items = [
        *ROOT_DIR_ITEMS,
        *dir_items_(257, b"docs"),
        *file_items(258, b"a.txt", b"alpha", parent=257, mtime_sec=1_700_000_000),
        ((258, K["INODE_EXTREF"], 99), inode_extref(256, b"second-name")),
        ((258, K["XATTR_ITEM"], 12345), dir_item(0, b"user.note", ondisk.FT_XATTR, b"\x00\xffhi")),
        *file_items(259, b"caf\xe9", b"latin-1 name"),
    ]
    with synthetic({"current": items}) as (conn, reader, out):
        done, gaps = run(conn, reader, out)
        assert gaps == {"current tree 5": ()} and dict(done.counts) == {"complete": 3}
        assert files_under(out) == {
            "current/tree_5/docs/a.txt": b"alpha",
            "current/tree_5/caf\udce9": b"latin-1 name",
        }
        assert (out / "current/tree_5/docs/a.txt").stat().st_mtime == 1_700_000_000
        row = artifacts(conn)[258]
        assert (row["kind"], row["status"], row["path"], row["attached"]) == (
            "file", "complete", "docs/a.txt", 1,
        )  # fmt: skip
        assert row["sha256"] == hashlib.sha256(b"alpha").hexdigest()
        assert [(n["parent"], n["name"], n["extended"]) for n in json.loads(row["names"])] == [
            (257, "a.txt", False),
            (256, "second-name", True),
        ]
        assert json.loads(row["xattrs"]) == [{"name": "user.note", "value_hex": "00ff6869"}]
        assert artifacts(conn)[259]["path_raw"] == b"caf\xe9"
        roles = [
            r["role"]
            for r in conn.execute(
                "SELECT role FROM provenance WHERE artifact_id = ? ORDER BY seq",
                (row["artifact_id"],),
            )
        ]
        assert roles == ["inode_item", "inode_ref", "inode_extref", "xattr", "extent_data"]
        # every provenance row names an item that exists, of the type its role says
        mismatched = conn.execute(
            "SELECT COUNT(*) FROM provenance p JOIN items i USING (content_id, slot)"
            " WHERE (p.role = 'extent_data') != (i.type_name = 'EXTENT_DATA')"
        ).fetchone()[0]
        assert mismatched == 0
        manifest = [json.loads(line) for line in (out / "manifest.jsonl").read_text().splitlines()]
        assert {m["objectid"] for m in manifest} == {257, 258, 259}
        assert next(m for m in manifest if m["objectid"] == 258)["inode"]["size"] == 5


def test_hostile_names_stay_inside_the_output_directory():
    hostile = [b"..", b".", b"../../escape", b"/etc/passwd", b"nul\0byte", b"n" * 255, b"same"]
    items = list(ROOT_DIR_ITEMS)
    for number, name in enumerate(hostile, start=300):
        items += file_items(number, name, b"x%d" % number)
    items += file_items(400, b"same", b"the second 'same'")
    with synthetic({"current": items}) as (conn, reader, out):
        done, _ = run(conn, reader, out)
        assert dict(done.counts) == {"complete": len(hostile) + 1}
        written = files_under(out)
        assert len(written) == len(hostile) + 1
        top = out / "current/tree_5"
        assert all(Path(name).parent == top.relative_to(out) for name in written)
        assert {p.name for p in out.parent.iterdir()} == {"out", "synthetic.db", "fs.img"}
        assert written["current/tree_5/same"] == b"x306"
        assert written["current/tree_5/same~inode400"] == b"the second 'same'"
        assert "written as" in artifacts(conn)[300]["problems"]


def test_parent_cycles_missing_parents_and_nameless_inodes_go_under_unattached():
    items = [
        *ROOT_DIR_ITEMS,
        *dir_items_(257, b"a", parent=258),
        *dir_items_(258, b"b", parent=257),
        *file_items(259, b"in-cycle", b"1", parent=257),
        *file_items(260, b"orphan", b"2", parent=999),
        ((261, K["INODE_ITEM"], 0), inode_item(1)),
        ((261, K["EXTENT_DATA"], 0), inline(b"3")),
    ]
    with synthetic({"current": items}) as (conn, reader, out):
        done, _ = run(conn, reader, out)
        assert done.counts["failed"] == 0
        rows = artifacts(conn)
        assert {o: rows[o]["attached"] for o in (259, 260, 261)} == {259: 0, 260: 0, 261: 0}
        unattached = out / "current/tree_5" / UNATTACHED.decode()
        assert (unattached / "999/orphan").read_bytes() == b"2"
        assert (unattached / "261").read_bytes() == b"3"
        assert [p for p in out.rglob("in-cycle")][0].read_bytes() == b"1"


def test_paths_are_bounded_on_a_long_parent_chain():
    from btrfska.recover.inodes import InodeRecord, Name

    inodes = {n: InodeRecord(n, names=[Name(n + 1, b"d", 2, False)]) for n in range(300, 9000)}
    located = paths(inodes)
    assert not located[300][1] and len(located[300][0]) <= 4096 + 2


def test_safe_component_changes_only_what_it_must():
    assert safe_component(b"plain name.txt", 5) == (b"plain name.txt", None)
    for name in (b"", b".", b"..", b"a/b", b"a\0b", b"x" * 300):
        cleaned, changed = safe_component(name, 5)
        assert changed and cleaned not in (b"", b".", b"..")
        assert b"/" not in cleaned and b"\0" not in cleaned and len(cleaned) <= 255 - len(PARTIAL)


def test_an_encrypted_extent_is_refused_with_a_report_line_and_nothing_is_written():
    items = [
        *ROOT_DIR_ITEMS,
        ((257, K["INODE_ITEM"], 0), inode_item(4096)),
        ((257, K["INODE_REF"], 256), inode_ref(b"secret")),
        ((257, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, 4096, encryption=1)),
        ((256, K["DIR_INDEX"], 2), dir_item(257, b"secret", ondisk.FT_REG_FILE | 0x80)),
    ]
    notes = []
    with synthetic({"current": items}, {DATA_PHYS: b"c" * 4096}) as (conn, reader, out):
        done, _ = run(conn, reader, out, notes=notes)
        assert dict(done.counts) == {"refused_encrypted": 1} and files_under(out) == {}
        row = artifacts(conn)[257]
        assert row["output_path"] is None and row["bytes_written"] == 0
        assert "FT_ENCRYPTED" in row["problems"] and "encrypted extent" in row["problems"]
    assert len(notes) == 1 and notes[0].startswith("refused: inode 257 of current: encrypted")


def test_an_unreadable_extent_leaves_a_hole_in_a_partial_file():
    good, lost = DATA_LOGICAL, DATA_LOGICAL + 600 * MIB  # the second lies in no chunk
    items = [
        *ROOT_DIR_ITEMS,
        ((257, K["INODE_ITEM"], 0), inode_item(8192)),
        ((257, K["INODE_REF"], 256), inode_ref(b"half")),
        ((257, K["EXTENT_DATA"], 0), regular(good, 4096)),
        ((257, K["EXTENT_DATA"], 4096), regular(lost, 4096)),
    ]
    with synthetic({"current": items}, {DATA_PHYS: b"g" * 4096}) as (conn, reader, out):
        done, _ = run(conn, reader, out)
        assert dict(done.counts) == {"partial": 1}
        assert files_under(out) == {"current/tree_5/half.partial": b"g" * 4096 + bytes(4096)}
        row = artifacts(conn)[257]
        assert row["sha256"] is None and json.loads(row["missing"]) == [[4096, 4096, "unmapped"]]
        kinds = conn.execute(
            "SELECT error_kind, extent_sha256 IS NOT NULL FROM provenance"
            " WHERE role = 'extent_data' ORDER BY seq"
        ).fetchall()
        assert [tuple(k) for k in kinds] == [(None, 1), ("unmapped", 0)]


def test_overlapping_extents_a_missing_inode_item_and_a_symlink():
    items = [
        *ROOT_DIR_ITEMS,
        ((257, K["INODE_ITEM"], 0), inode_item(8192)),
        ((257, K["INODE_REF"], 256), inode_ref(b"overlap")),
        ((257, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, 8192)),
        ((257, K["EXTENT_DATA"], 4096), regular(DATA_LOGICAL, 4096)),
        ((258, K["INODE_REF"], 256), inode_ref(b"no-inode-item")),
        ((258, K["EXTENT_DATA"], 0), inline(b"content without a size")),
        ((259, K["INODE_ITEM"], 0), inode_item(11, mode=0o120777)),
        ((259, K["INODE_REF"], 256), inode_ref(b"link")),
        ((259, K["EXTENT_DATA"], 0), inline(b"/etc/shadow")),
        ((260, K["INODE_ITEM"], 0), inode_item(0, mode=0o010644)),
        ((260, K["INODE_REF"], 256), inode_ref(b"fifo")),
    ]
    with synthetic({"current": items}, {DATA_PHYS: b"d" * 8192}) as (conn, reader, out):
        run(conn, reader, out)
        rows = artifacts(conn)
        assert rows[257]["status"] == "partial" and "overlaps" in rows[257]["problems"]
        assert rows[258]["status"] == "partial" and "size is unknown" in rows[258]["problems"]
        assert (rows[259]["kind"], rows[259]["status"]) == ("symlink", "recorded")
        assert rows[259]["symlink_target"] == "/etc/shadow" and rows[259]["output_path"] is None
        assert (rows[260]["kind"], rows[260]["status"]) == ("other", "recorded")
        assert not any(p.is_symlink() for p in out.rglob("*"))
        assert sorted(files_under(out)) == [
            "current/tree_5/no-inode-item.partial",
            "current/tree_5/overlap.partial",
        ]


def test_a_file_that_cannot_be_given_its_name_stays_partial_and_is_reported():
    items = [*ROOT_DIR_ITEMS, *file_items(257, b"taken", b"content")]
    with synthetic({"current": items}) as (conn, reader, out_dir):
        roots = tuple(resolve_roots(conn, "current", 5))
        with OutputTree(out_dir) as out:
            out.make_dir((b"current", b"tree_5"), None, None)
            (out_dir / "current/tree_5/taken").write_bytes(b"somebody else's file")
            done, _ = recover_roots(conn, reader, out, 1, roots, no_holes=True)
        assert dict(done.counts) == {"failed": 1}
        assert (out_dir / "current/tree_5/taken").read_bytes() == b"somebody else's file"
        assert (out_dir / "current/tree_5/taken.partial").read_bytes() == b"content"
        row = artifacts(conn)[257]
        assert row["sha256"] is None and row["output_path"].endswith("taken.partial")


def test_an_unchanged_file_is_written_once_across_roots_unless_dedup_is_off():
    same = [*ROOT_DIR_ITEMS, *file_items(257, b"kept", b"unchanged")]
    changed = [*ROOT_DIR_ITEMS, *file_items(257, b"kept", b"changed!!")]
    trees = {"current": changed, "backup:8": same, "backup:7": same}
    with synthetic(trees) as (conn, reader, out):
        done, _ = run(conn, reader, out, sources=("current", "backup:8", "backup:7"))
        assert dict(done.counts) == {"complete": 2, "duplicate": 1}
        assert sorted(files_under(out)) == ["backup_8/tree_5/kept", "current/tree_5/kept"]
        rows = conn.execute(
            "SELECT source, status, duplicate_of, artifact_id, in_current FROM artifacts"
        ).fetchall()
        first = next(r["artifact_id"] for r in rows if r["source"] == "backup:8")
        assert [r["duplicate_of"] for r in rows if r["source"] == "backup:7"] == [first]
        assert {r["source"]: r["in_current"] for r in rows} == {
            "current": 1, "backup:8": 1, "backup:7": 1,
        }  # fmt: skip
    with synthetic(trees) as (conn, reader, out):
        done, _ = run(conn, reader, out, sources=("backup:8", "backup:7"), dedup=False)
        assert dict(done.counts) == {"complete": 2} and len(files_under(out)) == 2


def test_a_file_missing_from_the_current_tree_is_labelled_so():
    before = [*ROOT_DIR_ITEMS, *file_items(257, b"gone", b"deleted later", generation=8)]
    reused = [*ROOT_DIR_ITEMS, *file_items(257, b"other", b"same number", generation=9)]
    with synthetic({"current": reused, "backup:8": before}) as (conn, reader, out):
        run(conn, reader, out, sources=("backup:8", "current"))
        flags = {r["source"]: r["in_current"] for r in conn.execute("SELECT * FROM artifacts")}
        assert flags == {"backup:8": 0, "current": 1}  # the inode number alone proves nothing


def test_random_item_payloads_never_raise_and_never_escape():
    rng = random.Random(5)
    types = [K[n] for n in ("INODE_ITEM", "INODE_REF", "INODE_EXTREF", "XATTR_ITEM",
                            "EXTENT_DATA", "DIR_INDEX")]  # fmt: skip
    for _ in range(25):
        items, seen = list(ROOT_DIR_ITEMS), {(256, K["INODE_ITEM"], 0)}
        for _ in range(40):
            key = (rng.randrange(256, 262), rng.choice(types), rng.randrange(0, 4) * 4096)
            if key not in seen:
                seen.add(key)
                items.append((key, rng.randbytes(rng.randrange(0, 60))))
        with synthetic({"current": items}) as (conn, reader, out):
            run(conn, reader, out)
            assert {p.name for p in out.parent.iterdir()} == {"out", "synthetic.db", "fs.img"}
            assert not any(p.is_symlink() for p in out.rglob("*"))


def test_a_large_file_is_streamed_in_bounded_memory():
    size = 96 * MIB
    items = [
        *ROOT_DIR_ITEMS,
        ((257, K["INODE_ITEM"], 0), inode_item(size)),
        ((257, K["INODE_REF"], 256), inode_ref(b"large")),
        ((257, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, size)),
    ]
    marks = {DATA_PHYS: b"start", DATA_PHYS + size - 3: b"end"}
    with synthetic({"current": items}, marks, size=128 * MIB) as (conn, reader, out):
        tracemalloc.start()
        done, _ = run(conn, reader, out)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert dict(done.counts) == {"complete": 1}
        written = out / "current/tree_5/large"
        assert written.stat().st_size == size
        with written.open("rb") as f:
            assert f.read(5) == b"start" and f.seek(size - 3) and f.read() == b"end"
        assert peak < 8 * MIB  # one 1 MiB piece at a time, not 96 MiB


def test_stream_extent_gives_the_bytes_read_extent_gives():
    data = random.Random(1).randbytes(3 * MIB + 17)
    item = Item(0, Key(257, K["EXTENT_DATA"], 0), 0, 53, regular(DATA_LOGICAL, len(data)))
    with synthetic({"current": list(ROOT_DIR_ITEMS)}, {DATA_PHYS: data}) as (_, reader, _out):
        record, pieces = stream_extent(reader, item, META_LOGICAL)
        pieces = list(pieces)
        assert record.error_kind is None and b"".join(pieces) == data
        assert max(map(len, pieces)) == MIB and len(pieces) == 4


def test_a_gap_in_the_tree_is_reported_and_an_unknown_root_is_an_error():
    with synthetic({"current": list(ROOT_DIR_ITEMS)}) as (conn, _reader, _out):
        lost = Root("state:9", 9, 5, 123 * NODESIZE, 4, 0)
        leaves, gaps = tree_leaves(conn, lost)
        assert leaves == [] and "not among the valid scanned blocks" in gaps[0]
        for spec in ("backup:99", "state:99", "nonsense"):
            with pytest.raises(RootNotCataloged):
                resolve_roots(conn, spec, 5)
        with pytest.raises(RootNotCataloged, match="names no tree 300"):
            resolve_roots(conn, "current", 300)


# ---------------------------------------------------------------------------
# Real images, against the read path of `btrfska cat`
# ---------------------------------------------------------------------------
def _expected(image: Path, every: int):
    """What an independent walk through the image finds: for each (source, tree), the inodes of
    the regular files, and the SHA-256 `read_file` gives for every `every`-th of them."""
    inodes, digests = {}, {}
    with open_image(image) as img:
        fs = open_filesystem(img)
        no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
        for root_set in root_sets(fs.fields):
            for subvolume in subvolumes(fs.reader, root_set)[0]:
                root = subvolume.root
                if root is None:
                    continue
                files = []
                for visit in walk(fs.reader, root.bytenr, root.expect()):
                    node = visit.node
                    for item in node.items if node.valid and node.level == 0 else ():
                        if item.key.type != K["INODE_ITEM"] or item.key.objectid == 256:
                            continue
                        if stat.S_ISREG(parsers.inode_item(item.data)["mode"]):
                            files.append(item.key.objectid)
                inodes[root_set.source, subvolume.id] = set(files)
                for inode in files[::every]:
                    result = read_file(fs.reader, root, inode, no_holes=no_holes)
                    assert result.complete
                    content = b"".join(result.chunks())
                    digests[root_set.source, subvolume.id, inode] = hashlib.sha256(
                        content
                    ).hexdigest()
    return inodes, digests


def _assert_recovery_equals_cat(image: Path, every: int = 1) -> None:
    inodes, digests = _expected(image, every)
    assert digests
    sources = tuple(dict.fromkeys(source for source, _ in inodes))
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    with scratch_dir("test_recover_") as d:
        database = d / "evidence.db"
        build_catalog(image, database, full_sweep=True)
        done = recover(image, database, d / "out", roots=sources, tree_id=None, dedup=False)
        for failed in ("partial", "failed", "refused_encrypted"):
            assert done.counts.get(failed, 0) == 0
        conn = db.open_readonly(database)
        rows = conn.execute(
            "SELECT source, tree_id, objectid, sha256, output_path FROM artifacts"
            " WHERE kind = 'file' AND status = 'complete'"
        ).fetchall()
        conn.close()
        recovered = {(r["source"], r["tree_id"], r["objectid"]): r for r in rows}
        found = {}
        for source, tree, inode in recovered:
            found.setdefault((source, tree), set()).add(inode)
        assert found == {key: value for key, value in inodes.items() if value}
        for key, digest in digests.items():
            assert recovered[key]["sha256"] == digest
            written = (d / "out" / recovered[key]["output_path"]).read_bytes()
            assert hashlib.sha256(written).hexdigest() == digest  # the bytes on disk, too
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before


def test_sandbox_files_come_out_as_cat_reads_them_from_every_root():
    _assert_recovery_equals_cat(SANDBOX)


def test_sandbox_recovery_gives_the_files_the_prototype_recovered():
    """Migration gate, plan.md §4.3: the same recovered files, from every cataloged state."""
    golden = json.loads(
        (REPO_ROOT / "tests/ground_truth/sandbox_legacy_recovered.json").read_text()
    )
    with scratch_dir("test_recover_") as d:
        database = _sandbox_db(d)
        conn = db.open_readonly(database)
        states = [f"state:{row[0]}" for row in conn.execute("SELECT state_id FROM states")]
        conn.close()
        recover(SANDBOX, database, d / "out", roots=tuple(states))
        conn = db.open_readonly(database)
        rows = conn.execute(
            "SELECT DISTINCT path, objectid, size, sha256, inode_generation FROM artifacts"
            " WHERE kind = 'file' AND status = 'complete'"
        ).fetchall()
        conn.close()
    ours = {(r["path"], r["objectid"], r["size"], r["sha256"]) for r in rows}
    theirs = {
        (f["filename"], f["inode"], f["size"], f["sha256"]) for f in golden["recovered_files"]
    }
    assert ours == theirs
    # one inode number, two files: what the prototype reports as a rename is a reuse
    assert len({r["inode_generation"] for r in rows}) == 2


@pytest.mark.parametrize(
    ("name", "every"), [("m1_lzo", 1), ("m1_zlib", 1), ("m1_blake2b", 1), ("m3_wide", 40)]
)
def test_corpus_files_come_out_as_cat_reads_them_from_every_root(name, every):
    """Every subvolume of every root; on m3_wide `read_file` checks every 40th file (it walks the
    tree once per file), while the set of files is compared in full."""
    image = SCENARIOS / f"{name}.img"
    if not image.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    _assert_recovery_equals_cat(image, every)


def test_deleted_files_come_back_from_a_backup_root_and_from_a_discovered_state():
    image = SCENARIOS / "m3_wide.img"
    if not image.exists():
        pytest.skip("m3_wide.img absent: build it with corpus/build.py")
    with scratch_dir("test_recover_") as d:
        database = d / "evidence.db"
        build_catalog(image, database, full_sweep=True)
        conn = db.open_readonly(database)
        states = conn.execute("SELECT state_id FROM states").fetchall()
        conn.close()
        recover(image, database, d / "out", roots=tuple(f"state:{s[0]}" for s in states))
        conn = db.open_readonly(database)
        deleted = conn.execute(
            "SELECT s.known_as = '[]' AS discovered, COUNT(*) AS files FROM artifacts a"
            " JOIN states s USING (state_id)"
            " WHERE a.kind = 'file' AND a.status = 'complete' AND a.in_current = 0"
            " GROUP BY 1"
        ).fetchall()
        assert {row["discovered"] for row in deleted} == {0, 1}  # from both kinds of root
        # every one of them has a chain: an INODE_ITEM and a name, each naming leaf and slot
        unexplained = conn.execute(
            "SELECT COUNT(*) FROM artifacts a WHERE a.kind = 'file' AND a.in_current = 0 AND ("
            " NOT EXISTS (SELECT 1 FROM provenance p WHERE p.artifact_id = a.artifact_id"
            "             AND p.role = 'inode_item')"
            " OR NOT EXISTS (SELECT 1 FROM provenance p WHERE p.artifact_id = a.artifact_id"
            "                AND p.role IN ('inode_ref', 'inode_extref')))"
        ).fetchone()[0]
        assert unexplained == 0
        conn.close()


def test_every_subvolume_is_recovered_with_tree_all():
    image = SCENARIOS / "s01_discard_none_r1.img"
    if not image.exists():
        pytest.skip("s01_discard_none_r1.img absent: build it with corpus/build.py")
    with scratch_dir("test_recover_") as d:
        database = d / "evidence.db"
        build_catalog(image, database, full_sweep=True)
        done = recover(image, database, d / "out", tree_id=None)
        conn = db.open_readonly(database)
        named = {r[0] for r in conn.execute(
            "SELECT tree_id FROM state_trees t JOIN states s USING (state_id)"
            " WHERE s.known_as LIKE '%current%' AND (tree_id = 5 OR tree_id >= 256)")}  # fmt: skip
        conn.close()
        assert {root.tree_id for root in done.roots} == named and len(named) > 1
        assert all((d / "out" / "current" / f"tree_{tree}").is_dir() for tree in named)


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------
def test_recover_refuses_another_image_an_existing_output_and_an_image_as_output():
    with scratch_dir("test_recover_") as d:
        database = _sandbox_db(d)
        other = d / "other.img"
        other.write_bytes(SANDBOX.read_bytes()[:-1] + b"\x01")
        with pytest.raises(RecoveryError, match="not the image the database was built from"):
            recover(other, database, d / "out1")
        short = d / "short.img"
        short.write_bytes(b"x" * 4096)
        with pytest.raises(RecoveryError, match="4096 bytes"):
            recover(short, database, d / "out2")
        assert not (d / "out1").exists() and not (d / "out2").exists()
        (d / "taken").mkdir()
        for target in (d / "taken", other):
            with pytest.raises(OutputError):
                recover(SANDBOX, database, target)
        assert other.read_bytes()[-1:] == b"\x01"


def test_cli_recover_reports_and_exits_zero_only_when_everything_is_complete(capsys):
    with scratch_dir("test_recover_") as d:
        database = _sandbox_db(d)
        arguments = ["recover", str(SANDBOX), "--db", str(database)]
        assert main([*arguments, "--out", str(d / "out"), "--root", "backup:13"]) == 0
        out = capsys.readouterr().out
        assert "root backup:13: state" in out and "artifacts: complete 1, partial 0" in out
        assert main([*arguments, "--out", str(d / "out")]) == 1  # exists now
        assert "already exists" in capsys.readouterr().err
        assert main([*arguments, "--out", str(d / "o2"), "--root", "backup:99"]) == 1
        assert "holds no root tree" in capsys.readouterr().err
        with pytest.raises(SystemExit):
            main([*arguments, "--out", str(d / "o3"), "--root", "yesterday"])


def test_readme_documents_the_command_its_statuses_and_every_manifest_key():
    readme = (REPO_ROOT / "README.md").read_text()
    section = readme.split("### `btrfska recover`", 1)[1].split("\n## ", 1)[0]
    with synthetic({"current": [*ROOT_DIR_ITEMS, *file_items(257, b"f", b"x")]}) as (c, r, out):
        run(c, r, out)
        keys = set(json.loads((out / "manifest.jsonl").read_text().splitlines()[0]))
    from btrfska.recover.cli import STATUSES

    options = {"--db", "--out", "--root", "--tree", "--no-dedup", "--no-rehash"}
    wanted = {f"`{name}`" for name in keys | set(STATUSES)} | options
    assert {name for name in wanted if name not in section} == set()
