"""Free space and overwrite risk on corpus images (plan.md M6b): the free space tree against the
free space derived from the extent tree, the discard mode observed on the `s01` trio, the files
of the current state still in use, and deleted files freed in the commit the scenario's log
names. Everything is asserted relative to the images and their logs.
"""

import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover
from btrfska.recover.space import SpaceViews
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import SCENARIOS, scratch_dir

WITH_FST = [
    "m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m2_logtree", "m4_deep",
    "m5_delsubvol", "m5_reuse", "m5_reuse_same", "m6_datacsum",
    "s01_discard_none_r1", "s01_discard_async_r1", "s01_discard_sync_r1",
]  # fmt: skip


def image(name: str):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{path.name} not built (./setup.sh)")
    return path


class Catalog:
    """A cataloged corpus image for a module fixture, with recoveries made on demand."""

    def __init__(self, name: str) -> None:
        self.image = image(name)
        self.directory = scratch_dir(f"test_freespace_{name}_")
        self.path = self.directory.__enter__()
        self.database = self.path / "evidence.db"
        build_catalog(self.image, self.database, full_sweep=True)
        self.runs = 0

    def recover(self, **options) -> int:
        self.runs += 1
        recover(self.image, self.database, self.path / f"out{self.runs}", **options)
        return self.runs

    def views(self, **options) -> SpaceViews:
        conn = db.open_readonly(self.database)
        with open_image(self.image) as img:
            return SpaceViews(conn, open_filesystem(img).reader, **options)

    def close(self) -> None:
        self.directory.__exit__(None, None, None)


@pytest.fixture(scope="module")
def deep():
    found = Catalog("m4_deep")
    yield found
    found.close()


def events(name: str, kind: str) -> dict[str, int]:
    """path -> generation of the scenario log's `=== EVENT KIND INODE GENERATION PATH` lines."""
    text = (SCENARIOS / f"{name}.log").read_text(errors="replace")
    return {path: int(gen) for gen, path in re.findall(rf"=== EVENT {kind} \d+ (\d+) (\S+)", text)}


def files(conn, recovery_id: int, where: str = "1") -> list:
    return conn.execute(
        "SELECT * FROM artifacts WHERE recovery_id = ? AND kind = 'file' AND status != 'duplicate'"
        f" AND {where}",
        (recovery_id,),
    ).fetchall()


@pytest.mark.parametrize("name", WITH_FST)
def test_the_free_space_tree_equals_the_free_space_derived_from_the_extent_tree(name):
    catalog = Catalog(name)
    try:
        views = catalog.views()
        view = views.view
        assert (view.source, view.complete) == ("free_space_tree", True)
        assert view.cross_check() == {
            "free_space_tree_only": 0, "extent_tree_only": 0, "ranges": [],
        }  # fmt: skip
        assert view.notes() == [] and view.fst.inconsistent == []
        derived = catalog.views(use_fst=False).view
        assert derived.source == "extent_tree" and derived.free.pairs == view.free.pairs
        # every older free space tree that survives reads without a finding
        assert all(not v.fst.notes() for _, v, _ in views.history())
    finally:
        catalog.close()


@pytest.mark.parametrize(
    ("name", "observed"),
    [("s01_discard_none_r1", "not_trimmed"), ("s01_discard_async_r1", "not_trimmed"),
     ("s01_discard_sync_r1", "trimmed_metadata")],
)  # fmt: skip
def test_the_discard_mode_observed_on_the_trio(name, observed):
    catalog = Catalog(name)
    try:
        discard = catalog.views().discard
        assert (discard.stated, discard.observed) == (None, observed)
        evidence = discard.evidence
        if observed == "trimmed_metadata":
            assert evidence["metadata_zeroed"] > 0
        else:  # freed tree blocks still hold their bytes, and nothing reads as trimmed
            assert evidence["metadata_intact"] > 0 and evidence["metadata_zeroed"] == 0
            assert evidence["data_zeroed"] == 0
    finally:
        catalog.close()


def test_the_current_state_s_files_are_in_use_and_deleted_ones_freed_where_the_log_says(deep):
    run = deep.recover(roots=("all",))
    conn = db.open_readonly(deep.database)
    try:
        current = files(conn, run, "source = 'state:1' AND status = 'complete'")
        assert current
        assert {(r["space_verdict"], r["overwrite_risk"]) for r in current} == {("in_use", 0)}
        deleted = events("m4_deep", "delete")
        victims = {}
        for row in files(conn, run, "path LIKE 'victims/victim_%' AND status = 'complete'"):
            records = [
                json.loads(r[0]) for r in conn.execute(
                    "SELECT read_record FROM provenance WHERE artifact_id = ?"
                    " AND role = 'extent_data'", (row["artifact_id"],),
                )
            ]  # fmt: skip
            on_disk = [r for r in records if r["space"] is not None]
            if on_disk:  # the even victims: regular extents
                victims[row["path"]] = (row, on_disk)
        assert len(victims) >= 10
        for path, (row, on_disk) in victims.items():
            assert row["space_verdict"] == "free" and row["overwrite_risk"] >= 2, path
            for record in on_disk:
                freed = record["space"]["freed_in"]
                # freed by the commit the scenario deleted it in, and allocated in the one before
                assert freed["by"] == deleted[path], path
                assert freed["after"] is not None and freed["after"] < freed["by"]
            assert json.loads(row["risk_reasons"])[0] == "free_in_block_group"
        summary = json.loads(conn.execute(
            "SELECT summary FROM recovery_runs WHERE recovery_id = ?", (run,)
        ).fetchone()[0])["free_space"]  # fmt: skip
        assert (
            summary["source"] == "free_space_tree" and summary["discard"]["mode"] == "not_trimmed"
        )
        assert summary["by_space"]["in_use"] >= len(current)
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("stated", "reason"), [("sync", "discard_sync"), ("async", "discard_async")]
)
def test_a_stated_discard_mode_raises_the_risk_of_freed_data(deep, stated, reason):
    run = deep.recover(roots=("all",), discard=stated)
    conn = db.open_readonly(deep.database)
    try:
        freed = files(conn, run, "space_verdict = 'free' AND path LIKE 'victims/victim_%'")
        assert freed
        for row in freed:
            reasons = json.loads(row["risk_reasons"])
            # inline victims sit in metadata block groups, which async discard does not trim
            if reason in reasons:
                assert row["overwrite_risk"] == 3
        assert any(reason in json.loads(row["risk_reasons"]) for row in freed)
        options = json.loads(conn.execute(
            "SELECT options FROM recovery_runs WHERE recovery_id = ?", (run,)
        ).fetchone()[0])  # fmt: skip
        assert options["discard"] == stated
    finally:
        conn.close()


def test_without_a_free_space_tree_the_extent_tree_gives_the_same_placements(deep):
    run = deep.recover(roots=("all",))
    conn = db.open_readonly(deep.database)
    try:
        rows = conn.execute(
            "SELECT p.read_record FROM provenance p JOIN artifacts a USING (artifact_id)"
            " WHERE a.recovery_id = ? AND p.space_verdict IS NOT NULL",
            (run,),
        ).fetchall()
        assert rows
    finally:
        conn.close()
    with open_image(deep.image) as img:
        reader = open_filesystem(img).reader
        conn = db.open_readonly(deep.database)
        both = [SpaceViews(conn, reader), SpaceViews(conn, reader, use_fst=False)]
        assert [v.view.source for v in both] == ["free_space_tree", "extent_tree"]
        for (raw,) in rows:
            record = json.loads(raw)
            pieces = [
                (copy["devid"], copy["physical"], piece["length"])
                for piece in record["ranges"] for copy in piece["copies"] if copy["used"]
            ]  # fmt: skip
            got = [v._place(pieces, lambda view: False, 0) for v in both]
            assert (got[0].verdict, got[0].free_bytes, got[0].allocated_bytes) == (
                got[1].verdict, got[1].free_bytes, got[1].allocated_bytes,
            )  # fmt: skip
        conn.close()


def test_the_files_of_m6_datacsum_are_in_use():
    catalog = Catalog("m6_datacsum")
    try:
        run = catalog.recover()
        conn = db.open_readonly(catalog.database)
        found = files(conn, run)
        assert found and {(r["space_verdict"], r["overwrite_risk"]) for r in found} == {
            ("in_use", 0)
        }
        conn.close()
    finally:
        catalog.close()
