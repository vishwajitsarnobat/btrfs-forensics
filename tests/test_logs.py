"""Log trees in recovery (plan.md M5e-1): which subvolume a log tree logged, a read-only replay
over its base state, and the rule that a range a log does not hold is not a hole.
"""

import json
import re
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.dbtree import Root
from btrfska.recover.engine import recover
from btrfska.recover.inodes import InodeRecord, Name
from btrfska.recover.logs import overlay, replay
from btrfska.substrate import items, ondisk
from btrfska.substrate.node import Item, Key
from tests.helpers import SCENARIOS, scratch_dir
from tests.test_recover import (
    DATA_LOGICAL,
    DATA_PHYS,
    ROOT_DIR_ITEMS,
    by_source,
    inode_item,
    inode_ref,
    run,
    synthetic,
)

K = ondisk.ITEM_KEYS
SECTOR = 4096
LOGTREE = SCENARIOS / "m2_logtree.img"
DEEP = SCENARIOS / "m4_deep.img"
LOG = ondisk.TREE_LOG_OBJECTID


def extent(file_offset: int, sectors: int, disk: int = 1 << 30, into: int = 0) -> tuple:
    data = struct.pack(
        ondisk.FILE_EXTENT_ITEM.format, 7, 64 * SECTOR, 0, 0, 0, ondisk.FILE_EXTENT_REG,
        disk, 64 * SECTOR, into, sectors * SECTOR,
    )  # fmt: skip
    return Item(0, Key(257, K["EXTENT_DATA"], file_offset), 0, len(data), data), "leaf"


def shape(extents: list) -> list[tuple]:
    found = []
    for item, _ in extents:
        fe = items.file_extent(item.data)
        found.append((item.key.offset, fe["num_bytes"], fe["disk_bytenr"], fe["offset"]))
    return found


def test_a_logged_extent_replaces_its_range_and_the_rest_of_the_base_extent_stays():
    base = [extent(0, 8, disk=100)]
    merged, problems = overlay(base, [extent(2 * SECTOR, 2, disk=900)], 8 * SECTOR, SECTOR)
    assert problems == [] and shape(merged) == [
        (0, 2 * SECTOR, 100, 0),
        (2 * SECTOR, 2 * SECTOR, 900, 0),
        (4 * SECTOR, 4 * SECTOR, 100, 4 * SECTOR),  # the same disk extent, further in
    ]
    front, _ = overlay(base, [extent(0, 3, disk=900)], 8 * SECTOR, SECTOR)
    assert shape(front) == [(0, 3 * SECTOR, 900, 0), (3 * SECTOR, 5 * SECTOR, 100, 3 * SECTOR)]
    end, _ = overlay(base, [extent(7 * SECTOR, 2, disk=900)], 9 * SECTOR, SECTOR)
    assert shape(end) == [(0, 7 * SECTOR, 100, 0), (7 * SECTOR, 2 * SECTOR, 900, 0)]


def test_a_log_that_shrinks_the_file_keeps_nothing_past_the_sector_of_its_end():
    base = [extent(0, 4, disk=100), extent(4 * SECTOR, 4, disk=200)]
    merged, _ = overlay(base, [], SECTOR + 1, SECTOR)
    assert shape(merged) == [(0, 2 * SECTOR, 100, 0)]


def test_a_logged_extent_replaces_an_inline_base_as_a_whole():
    data = struct.pack("<QQBBHB", 7, 5, 0, 0, 0, ondisk.FILE_EXTENT_INLINE) + b"small"
    inline = (Item(0, Key(257, K["EXTENT_DATA"], 0), 0, len(data), data), "leaf")
    merged, _ = overlay([inline], [extent(0, 1, disk=900)], SECTOR, SECTOR)
    assert shape(merged) == [(0, SECTOR, 900, 0)]
    alone, _ = overlay([inline], [], 5, SECTOR)
    assert alone == [inline]


def test_a_lone_log_leaf_does_not_pass_an_unlogged_range_off_as_a_hole():
    logged = extent(SECTOR, 1, disk=DATA_LOGICAL)[0].data
    appended = {"owner": LOG, "items": [
        ((257, K["INODE_ITEM"], 0), inode_item(2 * SECTOR)),
        ((257, K["INODE_REF"], 256), inode_ref(b"grown")),
        ((257, K["EXTENT_DATA"], SECTOR), logged)]}  # fmt: skip
    trees, data = {"current": list(ROOT_DIR_ITEMS)}, {DATA_PHYS: b"x" * SECTOR}
    with synthetic(trees, data, loose=(appended,)) as (conn, reader, out):
        run(conn, reader, out, orphans=True)
        row = by_source(conn)["orphan_node", 257]
        assert row["status"] == "partial"
        assert json.loads(row["missing"]) == [[0, SECTOR, "not_logged"]]


def test_a_committed_tree_still_reads_the_same_range_as_a_hole():
    sparse = [*ROOT_DIR_ITEMS, ((257, K["INODE_ITEM"], 0), inode_item(2 * SECTOR)),
              ((257, K["INODE_REF"], 256), inode_ref(b"sparse")),
              ((257, K["EXTENT_DATA"], SECTOR),
               extent(SECTOR, 1, disk=DATA_LOGICAL)[0].data)]  # fmt: skip
    with synthetic({"current": sparse}, {DATA_PHYS: b"x" * SECTOR}) as (conn, reader, out):
        run(conn, reader, out)
        assert by_source(conn)["anchored_root", 257]["status"] == "complete"


def _record(generation: int, extents=(), size: int = 2 * SECTOR) -> InodeRecord:
    inode = {"generation": generation, "transid": 9, "size": size, "mode": 0o100644}
    return InodeRecord(257, inode, [Name(256, b"f", 2, False)], extents=list(extents))


def test_a_base_is_only_the_same_inode_and_generation_0_means_names_without_content():
    log = Root("log:1@9", None, LOG, 1, 9, 0, kind="log_tree", subvolume=5, named_by=2)
    below = Root("current", 1, 5, 3, 8, 0)
    same, _ = replay({257: _record(7, [extent(SECTOR, 1)])}, {257: _record(7, [extent(0, 2)])},
                     below, log, SECTOR)  # fmt: skip
    assert [j["kind"] for j in same[257].joins] == ["log_root", "log_replay"]
    assert not same[257].log_only and len(same[257].extents) == 2
    reused, _ = replay({257: _record(9, [extent(SECTOR, 1)])}, {257: _record(7, [extent(0, 2)])},
                       below, log, SECTOR)  # fmt: skip
    assert [j["kind"] for j in reused[257].joins] == ["log_root"] and reused[257].log_only
    nothing, _ = replay({257: _record(7, [extent(SECTOR, 1)])}, None, None, log, SECTOR)
    assert nothing[257].log_only
    exists, _ = replay({257: _record(0, [extent(0, 1)])}, {257: _record(7)}, below, log, SECTOR)
    assert exists[257].exists_only and exists[257].extents == []


# ---------------------------------------------------------------------------
# m2_logtree: a live log, with the hashes the guest logged
# ---------------------------------------------------------------------------


def logged_hashes(image) -> dict[str, str]:
    found = re.findall(r"([0-9a-f]{64})\s+/mnt/(\S+)", image.with_suffix(".log").read_text())
    return {path: digest for digest, path in found}


@pytest.fixture(scope="module")
def logtree():
    if not LOGTREE.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    with scratch_dir("test_logs_") as directory:
        build_catalog(LOGTREE, directory / "evidence.db", full_sweep=True)
        recover(LOGTREE, directory / "evidence.db", directory / "out", tree_id=None, logs=True)
        conn = db.open_readonly(directory / "evidence.db")
        yield conn
        conn.close()


def test_the_live_log_is_replayed_over_the_current_state_and_gives_the_logged_hashes(logtree):
    truth = logged_hashes(LOGTREE)
    rows = {r["path"]: r for r in logtree.execute(
        "SELECT * FROM artifacts WHERE source_kind = 'log_tree' AND kind = 'file'")}  # fmt: skip
    assert set(rows) == {"committed.txt", "fsynced.txt"}
    for name, row in rows.items():
        assert (row["status"], row["sha256"]) == ("complete", truth[f"sv1/{name}"])
        assert row["source"].startswith("log:") and row["output_path"].startswith(
            "log_trees/subvol_256/"
        )
        kinds = [join["kind"] for join in json.loads(row["joined"])]
        assert kinds[0] == "log_root"
    # appended after the commit: the committed tree alone gives the old content
    old = logtree.execute(
        "SELECT sha256 FROM artifacts WHERE source = 'current' AND tree_id = 256"
        " AND path = 'committed.txt'"
    ).fetchone()[0]
    assert old == truth["committed.txt"] != rows["committed.txt"]["sha256"]
    replayed = json.loads(rows["committed.txt"]["joined"])
    assert [j["kind"] for j in replayed] == ["log_root", "log_replay"]
    assert replayed[0]["subvolume"] == 256 and replayed[1]["base"] == "current"
    assert [j["kind"] for j in json.loads(rows["fsynced.txt"]["joined"])] == ["log_root"]


def test_the_flash_files_of_the_deep_image_come_out_under_the_subvolume_their_log_names():
    if not DEEP.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    flash = dict(
        re.findall(r"=== FLASH (\S+) ([0-9a-f]{64})", DEEP.with_suffix(".log").read_text())
    )
    with scratch_dir("test_logs_deep_") as directory:
        build_catalog(DEEP, directory / "evidence.db", full_sweep=True)
        done = recover(DEEP, directory / "evidence.db", directory / "out", logs=True)
        conn = db.open_readonly(directory / "evidence.db")
        rows = conn.execute(
            "SELECT path, sha256, tree_id, status FROM artifacts WHERE source_kind = 'log_tree'"
            " AND kind = 'file' AND status = 'complete'"
        ).fetchall()
        conn.close()
    found = {row["path"]: row for row in rows if row["path"] in flash}
    assert set(found) == set(flash) and done.counts.get("failed", 0) == 0
    for name, row in found.items():
        assert (row["sha256"], row["tree_id"]) == (flash[name], 5)
