"""Data checksums on corpus images (plan.md M6a): every csum type and compression, a nodatasum
file, a sector repaired from its mirror and a mismatch (`m6_datacsum`, `m6_datacsum_flipped`),
and log trees verified against their own EXTENT_CSUM items (`m4_deep`). Everything is asserted
relative to the images and the scenarios' own logs.
"""

import hashlib
import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.cli import main
from btrfska.recover.engine import recover
from tests.helpers import SCENARIOS, scratch_dir

DATACSUM = SCENARIOS / "m6_datacsum.img"
FLIPPED = SCENARIOS / "m6_datacsum_flipped.img"


def recovered(image, **options):
    """(the evidence database, open, after one recovery) for a module fixture."""
    if not image.exists():
        pytest.skip(f"{image.name} not built (./setup.sh)")
    directory = scratch_dir(f"test_datacsum_{image.stem}_")
    path = directory.__enter__()
    build_catalog(image, path / "evidence.db", full_sweep=True)
    recover(image, path / "evidence.db", path / "out", **options)
    return directory, db.open_readonly(path / "evidence.db")


def files(conn, where: str = "1") -> dict[str, dict]:
    rows = conn.execute(
        f"SELECT * FROM artifacts WHERE kind = 'file' AND status != 'duplicate' AND {where}"
    ).fetchall()
    return {row["path"]: row for row in rows}


def extent_checks(conn, artifact_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT read_record FROM provenance WHERE artifact_id = ? AND role = 'extent_data'"
        " ORDER BY seq",
        (artifact_id,),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


def logged(image) -> dict[str, str]:
    return dict(re.findall(r"=== FILE (\S+) ([0-9a-f]{64})", image.with_suffix(".log").read_text()))


@pytest.mark.parametrize(
    "name", ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m6_datacsum"]
)
def test_every_file_of_the_current_state_that_has_data_on_disk_matches(name):
    directory, conn = recovered(SCENARIOS / f"{name}.img", tree_id=None)
    try:
        found = files(conn, "status = 'complete'")
        assert found
        csum_type = conn.execute("SELECT csum_name FROM scan_runs").fetchone()[0]
        matched = 0
        for row in found.values():
            on_disk = [e for e in extent_checks(conn, row["artifact_id"]) if e["kind"] == "regular"]
            if on_disk:
                flags = conn.execute(
                    "SELECT i.flags FROM provenance p JOIN inodes i USING (content_id, slot)"
                    " WHERE p.artifact_id = ? AND p.role = 'inode_item'",
                    (row["artifact_id"],),
                ).fetchone()[0]
                if flags & 1:  # NODATASUM
                    assert row["csum_verdict"] == "no_csum", row["path"]
                    continue
                assert row["csum_verdict"] == "match", (csum_type, row["path"])
                assert json.loads(row["csum_sources"]) == ["current"]
                assert all(e["csum"]["matched"] == e["csum"]["sectors"] > 0 for e in on_disk)
                matched += 1
            else:
                assert row["csum_verdict"] in ("no_csum", None), row["path"]
        assert matched
        summary = json.loads(conn.execute("SELECT summary FROM recovery_runs").fetchone()[0])
        assert summary["csum_trees"]["current"]["complete"] is True
        assert summary["csum_trees"]["current"]["problems"] == []
    finally:
        conn.close()
        directory.__exit__(None, None, None)


@pytest.fixture(scope="module")
def datacsum():
    directory, conn = recovered(DATACSUM)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


@pytest.fixture(scope="module")
def flipped():
    directory, conn = recovered(FLIPPED)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


def test_each_kind_of_file_gets_its_verdict(datacsum):
    found, truth = files(datacsum), logged(DATACSUM)
    assert set(truth) <= set(found)
    for name in truth:
        assert found[name]["sha256"] == truth[name], name
    verdicts = {name: found[name]["csum_verdict"] for name in truth}
    assert verdicts == {
        "plain.txt": "match",
        "repairable.txt": "match",
        "damaged.txt": "match",
        "compressed.txt": "match",
        "inline.txt": "no_csum",
        "prealloc.bin": "no_csum",
        "nosum.txt": "no_csum",
    }
    reasons = {
        name: [e["csum"]["reason"] for e in extent_checks(datacsum, found[name]["artifact_id"])]
        for name in ("inline.txt", "prealloc.bin", "nosum.txt")
    }
    assert reasons == {
        "inline.txt": ["inline"], "prealloc.bin": ["prealloc"], "nosum.txt": ["nodatasum"],
    }  # fmt: skip
    (compressed, *_) = extent_checks(datacsum, found["compressed.txt"]["artifact_id"])
    assert compressed["compression"] == "zstd"
    assert compressed["csum"]["sectors"] == compressed["disk_num_bytes"] // 4096


def test_a_sector_flipped_on_one_mirror_is_read_from_the_other(flipped):
    found, truth = files(flipped), logged(DATACSUM)
    row = found["repairable.txt"]
    assert (row["status"], row["csum_verdict"], row["sha256"]) == (
        "complete", "match", truth["repairable.txt"],
    )  # fmt: skip
    (extent,) = extent_checks(flipped, row["artifact_id"])
    assert extent["csum"]["repaired"] == [[extent["disk_bytenr"], 2]]
    assert extent["csum"]["repaired_count"] == 1
    # the two copies differ, which the extent reader reports as before
    assert any("mirror 2 differs from mirror 1" in p for p in extent["problems"])


def test_a_sector_flipped_on_both_mirrors_is_a_mismatch_naming_it(flipped):
    found, truth = files(flipped), logged(DATACSUM)
    row = found["damaged.txt"]
    assert (row["status"], row["csum_verdict"]) == ("complete", "mismatch")
    assert row["sha256"] != truth["damaged.txt"]
    (extent,) = extent_checks(flipped, row["artifact_id"])
    assert extent["csum"]["bad_sectors"] == [extent["disk_bytenr"]]
    assert (extent["csum"]["mismatched"], extent["csum"]["repaired"]) == (1, [])
    assert (
        flipped.execute(
            "SELECT csum_verdict FROM provenance WHERE artifact_id = ? AND role = 'extent_data'",
            (row["artifact_id"],),
        ).fetchone()[0]
        == "mismatch"
    )
    # nothing else changed
    for name in ("plain.txt", "compressed.txt", "nosum.txt"):
        assert found[name]["sha256"] == truth[name]


def test_cat_repairs_and_reports_the_same(flipped, capsysbinary):
    truth, found = logged(DATACSUM), files(flipped)
    for name, verdict in (("repairable.txt", "match"), ("damaged.txt", "mismatch")):
        inode = found[name]["objectid"]
        assert main(["cat", str(FLIPPED), "--inode", str(inode)]) == 0
        captured = capsysbinary.readouterr()
        file_record = [json.loads(line) for line in captured.err.decode().splitlines()
                       if line.startswith('{"record":"file"')][0]  # fmt: skip
        assert file_record["csum"] == verdict
        assert (hashlib.sha256(captured.out).hexdigest() == truth[name]) is (verdict == "match")


def test_log_trees_and_lone_leaves_are_verified_against_the_trees_of_their_time():
    image = SCENARIOS / "m4_deep.img"
    directory, conn = recovered(image, roots=("current",), logs=True, orphans=True)
    try:
        found = files(conn, "source_kind = 'log_tree'")
        regular = {path: row for path, row in found.items() if "flash_regular" in path}
        assert regular
        for row in regular.values():
            assert row["csum_verdict"] == "match"
            assert json.loads(row["csum_sources"]) == [row["source"]]
        # a leaf no state reaches: the oldest state not older than the leaf has the checksums of
        # what it points to, where the current csum tree no longer does
        lone = files(conn, "source_kind = 'orphan_node' AND csum_verdict = 'match'")
        assert lone
        assert all(json.loads(row["csum_sources"]) != ["current"] for row in lone.values())
        assert not files(conn, "csum_verdict IN ('mismatch', 'unavailable')")
    finally:
        conn.close()
        directory.__exit__(None, None, None)


@pytest.mark.sandbox
def test_each_state_is_verified_against_its_own_csum_tree(sandbox_img):
    directory, conn = recovered(sandbox_img, roots=("all",))
    try:
        rows = conn.execute(
            "SELECT source_kind, source, state_id, csum_verdict, csum_sources FROM artifacts"
            " WHERE kind = 'file' AND csum_verdict = 'match'"
        ).fetchall()
        anchored = [row for row in rows if row["source_kind"] == "anchored_root"]
        assert anchored
        for row in anchored:  # the state's own csum tree decided, not the current one
            (known_as,) = conn.execute(
                "SELECT known_as FROM states WHERE state_id = ?", (row["state_id"],)
            ).fetchone()
            assert json.loads(row["csum_sources"]) == json.loads(known_as)[:1]
    finally:
        conn.close()
        directory.__exit__(None, None, None)
