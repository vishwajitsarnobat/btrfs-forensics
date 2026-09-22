"""A deleted subvolume on real images (plan.md M5e-2): `m5_delsubvol`, whose older root trees
still name the subvolume, and `m5_delsubvol_lost_items`, where no ROOT_ITEM of any generation
does. Everything is asserted relative to the images and the scenario's own log.
"""

import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover
from btrfska.timeline.build import Timeline
from tests.helpers import SCENARIOS, scratch_dir

DELETED = SCENARIOS / "m5_delsubvol.img"
LOST = SCENARIOS / "m5_delsubvol_lost_items.img"


def truth() -> tuple[int, dict[str, str]]:
    log = DELETED.with_suffix(".log").read_text()
    tree = int(re.search(r"=== DOOMED-ID (\d+)", log).group(1))
    return tree, dict(re.findall(r"=== DOOMED (\S+) ([0-9a-f]{64})", log))


def recovered(image, **options):
    if not image.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    directory = scratch_dir(f"test_delsubvol_{image.stem}_")
    path = directory.__enter__()
    build_catalog(image, path / "evidence.db", full_sweep=True)
    recover(image, path / "evidence.db", path / "out", roots=("all",), tree_id=None, **options)
    return directory, db.open_readonly(path / "evidence.db")


@pytest.fixture(scope="module")
def deleted():
    directory, conn = recovered(DELETED)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


@pytest.fixture(scope="module")
def lost():
    directory, conn = recovered(LOST, graph=True)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


def files(conn, tree: int, where: str) -> dict[str, list]:
    rows = conn.execute(
        f"SELECT a.*, c.sha256 AS content FROM artifacts a LEFT JOIN artifacts c"
        f" ON c.artifact_id = COALESCE(a.duplicate_of, a.artifact_id)"
        f" WHERE a.tree_id = ? AND a.kind = 'file' AND {where}",
        (tree,),
    ).fetchall()
    found: dict[str, list] = {}
    for row in rows:
        found.setdefault(row["path"], []).append(row)
    return found


def test_the_newest_states_do_not_name_the_subvolume_and_older_ones_do(deleted):
    tree, _ = truth()
    naming = [r[0] for r in deleted.execute(
        "SELECT s.generation FROM state_trees t JOIN states s USING (state_id)"
        " WHERE t.tree_id = ?", (tree,))]  # fmt: skip
    newest = deleted.execute("SELECT MAX(generation) FROM states").fetchone()[0]
    assert naming and max(naming) < newest
    current = deleted.execute(
        "SELECT COUNT(*) FROM state_trees t JOIN states s USING (state_id)"
        " WHERE t.tree_id = ? AND s.known_as LIKE '%current%'", (tree,)
    ).fetchone()[0]  # fmt: skip
    assert current == 0


def test_the_deleted_subvolumes_files_come_back_hash_exact_from_a_state_that_names_it(deleted):
    tree, logged = truth()
    found = files(deleted, tree, "a.source_kind = 'anchored_root'")
    for name, digest in logged.items():
        assert name in found, name
        assert {row["content"] for row in found[name]} == {digest}
        assert all(row["attached"] for row in found[name])


def test_the_timeline_reports_one_deleted_subvolume_and_no_delete_per_file(deleted):
    tree, _ = truth()
    timeline = Timeline(deleted)
    (event,) = [e for e in timeline.subvolume_events() if e["tree_id"] == tree]
    assert event["event"] == "subvolume_deleted"
    assert event["generations"][0] < event["generations"][1]
    inside = [e["event"] for e in timeline.events(tree)]
    assert "create" in inside and "delete" not in inside


def test_after_the_mutation_no_root_item_of_any_generation_names_the_subvolume(lost):
    tree, _ = truth()
    assert (
        lost.execute("SELECT COUNT(*) FROM root_items WHERE tree_id = ?", (tree,)).fetchone()[0]
        == 0
    )
    assert (
        lost.execute("SELECT COUNT(*) FROM state_trees WHERE tree_id = ?", (tree,)).fetchone()[0]
        == 0
    )
    assert lost.execute("SELECT COUNT(*) FROM blocks WHERE owner = ?", (tree,)).fetchone()[0]


def test_then_only_the_orphan_graph_gives_its_files_back_with_their_paths(lost):
    tree, logged = truth()
    assert not files(lost, tree, "a.source_kind = 'anchored_root'")
    found = files(lost, tree, "a.source_kind = 'orphan_graph'")
    for name, digest in logged.items():
        whole = [row for row in found.get(name, ()) if row["content"] == digest]
        assert whole, name
        assert all(row["attached"] and row["source"].startswith("fragment:") for row in whole)
        joins = json.loads(whole[0]["joined"])
        assert (
            joins[0]["kind"] == "pointer"
            and "cannot be taken for a committed state" in joins[0]["evidence"]
        )
    # nothing that is called complete under that tree has a content the log contradicts
    for name, rows in found.items():
        for row in rows:
            if name in logged and row["status"] == "complete":
                assert row["sha256"] == logged[name]
