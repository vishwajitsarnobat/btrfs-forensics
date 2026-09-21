"""`m4_deep`: M4's definition of done on a history deeper than the backup roots (plan.md M4e).

The image's serial log is its ground truth: `=== VICTIM|FLASH|ORPHAN name sha256`. Every claim
below is made relative to that log and to the image, never as a count: guest runs are not
bit-stable, and the claims are about which *source* gives a file back, not about how many.
"""

import hashlib
import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import u64
from btrfska.recover.engine import recover
from btrfska.substrate import ondisk
from tests.helpers import SCENARIOS, scratch_dir

TRUTH = re.compile(r"=== (VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})")
SOURCES = {"anchored_root", "orphan_node", "orphan_item"}


@pytest.fixture(scope="module")
def deep():
    """(truth by kind, artifact rows, states, output directory) of one full recovery."""
    image, log = SCENARIOS / "m4_deep.img", SCENARIOS / "m4_deep.log"
    if not image.exists() or not log.exists():
        pytest.skip("m4_deep.img absent: build it with corpus/build.py")
    truth: dict[str, dict[str, str]] = {"VICTIM": {}, "FLASH": {}, "ORPHAN": {}}
    for kind, name, digest in TRUTH.findall(log.read_text()):
        truth[kind][name] = digest
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    with scratch_dir("test_deep_") as d:
        database = d / "evidence.db"
        build_catalog(image, database, full_sweep=True)
        recover(image, database, d / "out", roots=("all",), tree_id=None, orphans=True)
        conn = db.open_readonly(database)
        rows = conn.execute("SELECT * FROM artifacts").fetchall()
        states = conn.execute("SELECT state_id, generation, known_as FROM states").fetchall()
        capped = conn.execute("SELECT COUNT(*) FROM problems WHERE source = 'roots'").fetchone()[0]
        conn.close()
        assert capped == 0  # every root tree on the image was evaluated: "all" means all
        assert hashlib.sha256(image.read_bytes()).hexdigest() == before
        yield truth, rows, states, d / "out"


def _complete(rows, digest):
    return [r for r in rows if r["status"] == "complete" and r["sha256"] == digest]


def test_the_log_lists_victims_flash_files_and_the_open_unlinked_file(deep):
    truth, *_ = deep
    assert len(truth["VICTIM"]) >= 8 and len(truth["FLASH"]) >= 2 and len(truth["ORPHAN"]) == 1
    digests = [d for kind in truth.values() for d in kind.values()]
    assert len(set(digests)) == len(digests)  # a hash names one file


def test_the_history_is_deeper_than_the_backup_roots(deep):
    _, _, states, _ = deep
    named = [s for s in states if json.loads(s["known_as"])]
    beyond = [s for s in states if not json.loads(s["known_as"])]
    assert len(named) <= 5 and len(beyond) > 4 * len(named)
    assert min(u64(s["generation"]) for s in beyond) < min(u64(s["generation"]) for s in named)


def test_states_beyond_the_backup_roots_give_back_victims_the_backup_roots_cannot(deep):
    """(a) anchored historical roots, labelled as such, hash-exact."""
    truth, rows, states, out = deep
    named = {s["state_id"] for s in states if json.loads(s["known_as"])}
    by_backup, only_beyond = set(), set()
    for name, digest in truth["VICTIM"].items():
        anchored = [r for r in _complete(rows, digest) if r["source_kind"] == "anchored_root"]
        if any(r["state_id"] in named for r in anchored):
            by_backup.add(name)
        elif anchored:
            only_beyond.add(name)
            row = anchored[0]
            assert row["in_current"] == 0 and row["path"].endswith(name)
            written = (out / row["output_path"]).read_bytes()
            assert hashlib.sha256(written).hexdigest() == digest
    # A victim lives in one committed generation: the backup roots hold the last ones at most.
    assert len(by_backup) <= 4
    assert len(only_beyond) > len(by_backup) and len(only_beyond) >= 4
    # both kinds of victim come back: inline (odd rounds) and regular (even rounds)
    rounds = {int(re.search(r"(\d+)", name).group(1)) % 2 for name in only_beyond}
    assert rounds == {0, 1}


def test_flash_files_come_back_from_orphan_nodes_and_from_no_anchored_root(deep):
    """(b) recovers what (a) cannot: a flash file never was in any committed tree."""
    truth, rows, _, out = deep
    for name, digest in truth["FLASH"].items():
        found = _complete(rows, digest)
        assert found, f"{name} was not recovered"
        assert {r["source_kind"] for r in found} == {"orphan_node"}
        row = found[0]
        assert u64(row["tree_id"]) == ondisk.TREE_LOG_OBJECTID and row["state_id"] is None
        assert row["path"].endswith(name)
        written = (out / row["output_path"]).read_bytes()
        assert hashlib.sha256(written).hexdigest() == digest
        # no root names the file at all, complete or not
        assert not [
            r for r in rows if r["source_kind"] == "anchored_root" and r["path"].endswith(name)
        ]
    sizes = {r["size"] for d in truth["FLASH"].values() for r in _complete(rows, d)}
    assert min(sizes) < 2048 < max(sizes)  # an inline one and a regular one


def test_the_open_unlinked_file_comes_back_as_an_orphan_item_with_its_name(deep):
    """(c) the kernel's ORPHAN_ITEM: content intact, no name left in the last committed tree."""
    truth, rows, _, out = deep
    ((name, digest),) = truth["ORPHAN"].items()
    found = [r for r in _complete(rows, digest) if r["source_kind"] == "orphan_item"]
    assert found
    row = found[0]
    assert row["attached"] == 0 and row["in_current"] == 1
    names = json.loads(row["names"])
    assert [n["name"] for n in names if n.get("former")] == [name]
    assert row["path"] == f".btrfska-orphan-items/{u64(row['objectid'])}_{name}"
    assert hashlib.sha256((out / row["output_path"]).read_bytes()).hexdigest() == digest


def test_every_artifact_is_labelled_with_its_source_and_has_a_chain(deep):
    _, rows, _, _ = deep
    assert {r["source_kind"] for r in rows} == SOURCES
    for row in rows:
        anchored = row["source_kind"] != "orphan_node"
        assert (row["state_id"] is not None) == anchored
        assert row["source"].startswith("state:" if anchored else "orphan_node:")


def test_nothing_is_called_complete_that_does_not_hash_to_what_was_written(deep):
    _, rows, _, out = deep
    written = [r for r in rows if r["kind"] == "file" and r["output_path"]]
    assert written
    for row in written[:: max(1, len(written) // 200)]:  # a spread of about 200 files
        data = (out / row["output_path"]).read_bytes()
        assert len(data) == row["bytes_written"]
        if row["status"] == "complete":
            assert hashlib.sha256(data).hexdigest() == row["sha256"]
        else:
            assert row["output_path"].endswith(".partial") and row["sha256"] is None


def test_the_lost_parent_image_has_a_root_tree_leaf_as_a_state():
    """EXP-004 §6.8: the corrupted node is gone from the catalog, its orphaned leaf is a state."""
    image, source = SCENARIOS / "m4_deep_lost_parent.img", SCENARIOS / "m4_deep.img"
    if not image.exists() or not source.exists():
        pytest.skip("m4_deep_lost_parent.img absent: build it with corpus/build.py")
    with scratch_dir("test_deep_") as d:
        found = {}
        for path in (source, image):
            build_catalog(path, d / f"{path.stem}.db", full_sweep=True)
            conn = db.open_readonly(d / f"{path.stem}.db")
            found[path.stem] = {
                (u64(r["bytenr"]), u64(r["generation"]), r["level"])
                for r in conn.execute("SELECT bytenr, generation, level FROM states")
            }
            conn.close()
    lost = found["m4_deep"] - found["m4_deep_lost_parent"]
    gained = found["m4_deep_lost_parent"] - found["m4_deep"]
    assert len(lost) == 1 and len(gained) >= 1
    ((_, generation, level),) = lost
    assert level >= 1
    assert {(g, lv) for _, g, lv in gained} == {(generation, level - 1)}
