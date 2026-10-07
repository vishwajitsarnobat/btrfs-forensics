"""A logical chunk range reused on real images (plan.md M5f, EXP-010): `m5_reuse`, where the new
chunk lies on other physical bytes, and `m5_reuse_same`, where it lies on the removed chunk's own
bytes. Everything is asserted relative to the images and the scenarios' own logs.
"""

import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover
from tests.helpers import SCENARIOS, scratch_dir

REUSE = SCENARIOS / "m5_reuse.img"
SAME = SCENARIOS / "m5_reuse_same.img"
PIECE = 4 << 20
B_PIECES = {"m5_reuse": 10, "m5_reuse_same": 14}  # corpus/vm/scenarios/reuse*.guest.sh


def logged(image) -> dict[str, str]:
    log = image.with_suffix(".log").read_text()
    return {name: digest for digest, name in re.findall(r"([0-9a-f]{64})\s+/mnt/(\S+)", log)}


def cataloged(image, recovered: bool):
    if not image.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    directory = scratch_dir(f"test_reuse_{image.stem}_")
    path = directory.__enter__()
    build_catalog(image, path / "evidence.db", full_sweep=True)
    if recovered:
        recover(image, path / "evidence.db", path / "out", roots=("all",), tree_id=None)
    return directory, db.open_readonly(path / "evidence.db")


@pytest.fixture(scope="module")
def reuse():
    directory, conn = cataloged(REUSE, recovered=True)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


@pytest.fixture(scope="module")
def same():
    directory, conn = cataloged(SAME, recovered=True)
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


def data_chunks(conn) -> list[dict]:
    """Every accepted data chunk of the CHUNK_ITEM maps, with its map's place in time (the
    current map last) and its stripes."""
    rows = conn.execute(
        "SELECT c.chunk_id, c.logical, c.length, m.name, m.kind, m.root_generation"
        " FROM chunks c JOIN chunk_maps m USING (map_id)"
        " WHERE c.accepted AND c.type & 1 AND m.kind IN ('historical', 'current')"
    ).fetchall()
    found = []
    for row in rows:
        stripes = tuple(
            tuple(s)
            for s in conn.execute(
                "SELECT devid, physical FROM stripes WHERE chunk_id = ? ORDER BY stripe_index",
                (row["chunk_id"],),
            )
        )
        place = 1 << 64 if row["kind"] == "current" else row["root_generation"]
        found.append(dict(row) | {"stripes": stripes, "place": place})
    return found


def reused(conn) -> list[tuple[dict, dict]]:
    """(older chunk, current chunk) pairs that start at the same logical address."""
    chunks = data_chunks(conn)
    current = [c for c in chunks if c["kind"] == "current"]
    return [
        (old, new)
        for new in current
        for old in chunks
        if old["kind"] == "historical" and old["logical"] == new["logical"]
    ]


def b_versions(conn, image) -> list[dict]:
    """Every full version of b.bin, resolved to the artifact that holds its content."""
    return [
        dict(r)
        for r in conn.execute(
            "SELECT c.status, c.sha256, c.problems, c.chunk_maps FROM artifacts a"
            " JOIN artifacts c ON c.artifact_id = COALESCE(a.duplicate_of, a.artifact_id)"
            " WHERE a.kind = 'file' AND (a.path = 'b.bin' OR a.path LIKE '%/b.bin')"
            " AND a.size = ?",
            (B_PIECES[image.stem] * PIECE,),
        )
    ]


def test_two_chunks_of_different_maps_hold_one_logical_address_on_other_bytes(reuse):
    pairs = [(old, new) for old, new in reused(reuse) if old["stripes"] != new["stripes"]]
    assert pairs
    old, new = pairs[0]
    assert old["place"] < new["place"]
    # the older chunk's device bytes lie in no chunk of the current map: nothing reused them
    current = [c for c in data_chunks(reuse) if c["kind"] == "current"]
    for devid, physical in old["stripes"]:
        assert not any(
            d == devid and p < physical + old["length"] and physical < p + c["length"]
            for c in current
            for d, p in c["stripes"]
        )


def test_the_dev_extents_map_rejects_the_reused_address(reuse):
    (old, _), *_ = [(o, n) for o, n in reused(reuse) if o["stripes"] != n["stripes"]]
    row = reuse.execute(
        "SELECT chunks.accepted, chunks.problems FROM chunks JOIN chunk_maps USING (map_id)"
        " WHERE kind = 'dev_extents' AND logical = ?",
        (old["logical"],),
    ).fetchone()
    assert row is not None and not row["accepted"]
    assert "no dev-tree leaf holds these device extents together" in row["problems"]


def test_b_bin_reads_hash_exact_through_its_own_map_and_names_the_reuse(reuse):
    versions = b_versions(reuse, REUSE)
    assert versions
    for version in versions:
        assert (version["status"], version["sha256"]) == ("complete", logged(REUSE)["b.bin"])
        assert any(
            "places this address in a different chunk" in p for p in json.loads(version["problems"])
        )
        assert "current" not in json.loads(version["chunk_maps"])


def test_the_control_reuses_the_address_on_the_same_bytes_with_a_map_in_between(same):
    maps = sorted({(c["place"], c["name"]) for c in data_chunks(same)})
    chunks = data_chunks(same)
    pairs = [(old, new) for old, new in reused(same) if old["stripes"] == new["stripes"]]
    assert pairs
    found = False
    for old, new in pairs:
        between = [name for place, name in maps if old["place"] < place < new["place"]]
        found |= any(
            not any(
                c["name"] == name and c["logical"] <= new["logical"] < c["logical"] + c["length"]
                for c in chunks
            )
            for name in between
        )
    assert found


def test_the_control_overwrite_is_invisible_to_the_maps(same):
    """Same placement: the own map reads the reused bytes like any map would, and no note says
    so. Only data checksums (M6) can tell; the log's hash stands in for them here."""
    versions = b_versions(same, SAME)
    assert versions
    for version in versions:
        assert version["status"] == "complete"
        assert version["sha256"] != logged(SAME)["b.bin"]
        notes = json.loads(version["problems"])
        assert not any("different chunk" in p or "allocated again" in p for p in notes)
