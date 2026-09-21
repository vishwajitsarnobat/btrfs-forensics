"""The evidence database (plan.md M3a): schema, the single write site, one-pass build, custody."""

import json
import re
import sqlite3

import pytest

from btrfska.catalog import build, db
from btrfska.catalog.schema import DDL, RECOVERY_TABLES, SCHEMA_VERSION, s64, u64
from btrfska.cli import main
from btrfska.scan.classify import scan_image
from btrfska.scan.roots import discover_image
from btrfska.substrate.fs import NoValidSuperblock, open_filesystem
from btrfska.substrate.image import open_image
from conftest import SANDBOX_SHA256
from tests.helpers import REPO_ROOT, SCENARIOS, scratch_dir, write_sparse_image

SANDBOX = REPO_ROOT / "sandbox.img"
DOC = REPO_ROOT / "docs" / "evidence-db.md"


# ---------------------------------------------------------------------------
# u64 storage
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "stored"),
    [
        (0, 0),
        (5, 5),
        ((1 << 63) - 1, (1 << 63) - 1),
        (1 << 63, -(1 << 63)),
        ((1 << 64) - 6, -6),  # the log tree
        ((1 << 64) - 9, -9),  # the data relocation tree
        ((1 << 64) - 1, -1),
    ],
)
def test_u64_is_stored_as_its_twos_complement_and_comes_back(value, stored):
    assert s64(value) == stored
    assert u64(stored) == value


def test_none_stays_none_and_non_u64_values_are_refused():
    assert s64(None) is None and u64(None) is None
    for bad in (-1, 1 << 64):
        with pytest.raises(ValueError, match="not a u64"):
            s64(bad)


def test_every_stored_value_fits_sqlite_integers():
    conn = sqlite3.connect(":memory:")
    for value in (0, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
        assert u64(conn.execute("SELECT ?", (s64(value),)).fetchone()[0]) == value


# ---------------------------------------------------------------------------
# catalog/db.py: the single write site
# ---------------------------------------------------------------------------
def test_create_makes_an_empty_database_of_the_current_schema():
    with scratch_dir("catalog-") as directory:
        conn = db.create(directory / "new.db")
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert set(build.TABLES) <= tables
        conn.close()


def test_create_refuses_anything_that_already_exists():
    with scratch_dir("catalog-") as directory:
        existing = directory / "evidence.img"
        existing.write_bytes(b"not to be touched")
        link = directory / "link.db"
        link.symlink_to(directory / "nowhere")
        for path in (existing, link, directory):
            with pytest.raises(db.CatalogError, match="already exists"):
                db.create(path)
        assert existing.read_bytes() == b"not to be touched"
        with pytest.raises(db.CatalogError, match="is not a directory"):
            db.create(directory / "missing" / "new.db")


def test_open_readonly_refuses_an_unfinished_build_and_files_that_are_not_ours():
    with scratch_dir("catalog-") as directory:
        path = directory / "unfinished.db"
        db.create(path).close()  # the schema, but no finished scan run
        with pytest.raises(db.CatalogError, match="no finished scan run"):
            db.open_readonly(path)
    with scratch_dir("catalog-") as directory:
        text = directory / "notes.txt"
        text.write_text("hello")
        with pytest.raises(db.CatalogError, match="not a btrfska evidence database"):
            db.open_readonly(text)
        with pytest.raises(db.CatalogError, match="is not a file"):
            db.open_readonly(directory / "absent.db")
        other = directory / "other.db"
        raw = sqlite3.connect(other)
        raw.executescript(DDL)
        raw.execute("PRAGMA user_version = 99")
        raw.commit()
        raw.close()
        with pytest.raises(db.CatalogError, match="schema version 99"):
            db.open_readonly(other)


# ---------------------------------------------------------------------------
# The schema document is the contract
# ---------------------------------------------------------------------------
def _schema_columns() -> dict[str, list[str]]:
    conn = sqlite3.connect(":memory:")
    conn.executescript(DDL)
    names = [
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
    ]
    return {name: [r[1] for r in conn.execute(f"PRAGMA table_info({name})")] for name in names}


def test_every_table_and_column_is_documented():
    text = DOC.read_text()
    missing = []
    for table, columns in _schema_columns().items():
        if f"`{table}`" not in text:
            missing.append(table)
            continue
        for column in columns:
            if f"`{column}`" not in text and f"`{table}.{column}`" not in text:
                missing.append(f"{table}.{column}")
    assert missing == []


def test_the_document_names_the_current_schema_version():
    text = DOC.read_text()
    assert f"**Schema version: {SCHEMA_VERSION}.**" in text
    assert re.search(rf"^- \*\*{SCHEMA_VERSION}\*\* \(", text, re.M)


def test_build_tables_lists_every_table_of_the_schema():
    conn = sqlite3.connect(":memory:")
    conn.executescript(DDL)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert tables == set(build.TABLES) | set(RECOVERY_TABLES)  # appended to by `recover`


# ---------------------------------------------------------------------------
# One pass over an image
# ---------------------------------------------------------------------------
def _reference(path, full_sweep):
    """Independent runs of what `btrfska scan` and `btrfska roots` compute."""
    with open_image(path) as img:
        fs = open_filesystem(img)
        scan = scan_image(img, fs, full_sweep=full_sweep)
        stream = list(scan.classified)
        found = discover_image(img, fs, full_sweep=full_sweep).discovery
        return stream, scan.summary, found


def _assert_database_equals_scan_and_roots(path, database, full_sweep):
    stream, summary, found = _reference(path, full_sweep)
    conn = db.open_readonly(database)

    nodes = conn.execute("SELECT * FROM nodes ORDER BY physical").fetchall()
    assert [
        (n["physical"], n["status"], n["valid"], n["orphan"], n["outside_map"]) for n in nodes
    ] == [
        (i.record.physical, i.status, int(i.record.valid), int(i.orphan), int(i.outside_map))
        for i in stream
    ]
    assert [
        (u64(n["bytenr"]), u64(n["generation"]), u64(n["owner"]), n["level"]) for n in nodes
    ] == [(i.record.bytenr, i.record.generation, i.record.owner, i.record.level) for i in stream]
    checks = conn.execute("SELECT node_id, name, ok FROM node_checks ORDER BY node_id, rowid")
    assert [(r["node_id"], r["name"], r["ok"]) for r in checks] == [
        (n, c.name, None if c.ok is None else int(c.ok))
        for n, item in enumerate(stream, start=1)
        for c in item.record.checks
    ]

    by_status = dict(conn.execute("SELECT status, COUNT(*) FROM nodes GROUP BY status").fetchall())
    for status in ("live", "backup_reachable", "unreferenced", "invalid"):
        assert by_status.get(status, 0) == summary[status]
    assert len(nodes) == summary["candidates"]
    stored = json.loads(conn.execute("SELECT scan_summary FROM scan_runs").fetchone()[0])
    assert stored["candidates"] == summary["candidates"] and stored["valid"] == summary["valid"]

    states = conn.execute("SELECT * FROM states ORDER BY state_id").fetchall()
    assert [
        (u64(s["bytenr"]), u64(s["generation"]), s["level"], json.loads(s["known_as"]),
         s["found"], s["referenced"], s["completeness"], json.loads(s["missing"]))
        for s in states
    ] == [
        (s.bytenr, s.generation, s.level, list(s.known_as), s.found, s.referenced,
         s.completeness, s.missing)
        for s in found.states
    ]  # fmt: skip
    trees = conn.execute("SELECT * FROM state_trees ORDER BY state_id, position").fetchall()
    assert [(u64(t["tree_id"]), u64(t["bytenr"]), t["status"], t["blocks"]) for t in trees] == [
        (t.tree_id, t.bytenr, t.status, t.blocks) for s in found.states for t in s.trees
    ]
    known = conn.execute("SELECT * FROM known_roots ORDER BY known_root_id").fetchall()
    assert [
        (k["source"], k["tree"], u64(k["bytenr"]), k["indexed"], k["candidate"]) for k in known
    ] == [
        (r.root.source, r.root.tree, r.root.bytenr, int(r.indexed), int(r.candidate))
        for r in found.rediscovered
    ]
    failures = conn.execute("SELECT source, failure_class FROM walk_failures").fetchall()
    assert sorted(map(tuple, failures)) == sorted((f[0], f[3]) for f in found.walk_failures)
    blocks = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    assert blocks == len({
        (i.record.bytenr, i.record.generation, i.record.level, i.record.owner)
        for i in stream if i.record.valid
    })  # fmt: skip
    conn.close()


@pytest.mark.sandbox
def test_sandbox_database_equals_scan_and_roots_and_the_golden_numbers():
    with scratch_dir("catalog-") as directory:
        database = directory / "sandbox.db"
        built = build.build_catalog(SANDBOX, database)
        assert built.image_unchanged is True and built.image_sha256 == SANDBOX_SHA256
        _assert_database_equals_scan_and_roots(SANDBOX, database, full_sweep=False)
        conn = db.open_readonly(database)
        # the project's golden numbers (plan.md §6.1), now one query each
        assert tuple(
            conn.execute(
                "SELECT COUNT(*), SUM(outside_map) FROM nodes WHERE legacy_orphan"
            ).fetchone()
        ) == (71, 21)
        assert conn.execute("SELECT COUNT(*) FROM states").fetchone()[0] == 5
        sources = conn.execute("SELECT source FROM known_roots WHERE tree = 'root'")
        assert {r[0] for r in sources} == {
            "current", "backup:11", "backup:12", "backup:13", "backup:14",
        }  # fmt: skip
        run = conn.execute("SELECT * FROM scan_runs").fetchone()
        assert run["image_sha256_before"] == run["image_sha256_after"] == SANDBOX_SHA256
        assert run["schema_version"] == SCHEMA_VERSION and run["gate_status"] == "OK"
        assert run["image_size"] == SANDBOX.stat().st_size and run["finished_utc"]
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM nodes")
        conn.close()


@pytest.mark.sandbox
def test_scanned_and_skipped_regions_cover_the_image_exactly_once():
    with scratch_dir("catalog-") as directory:
        build.build_catalog(SANDBOX, directory / "s.db", rehash=False)
        conn = db.open_readonly(directory / "s.db")
        spans = conn.execute("SELECT start_offset, end_offset FROM regions ORDER BY 1").fetchall()
        assert spans[0][0] == 0 and spans[-1][1] == SANDBOX.stat().st_size
        assert all(a[1] == b[0] for a, b in zip(spans, spans[1:], strict=False))
        assert conn.execute("SELECT image_sha256_after FROM scan_runs").fetchone()[0] is None
        conn.close()


@pytest.mark.sandbox
def test_a_second_build_is_refused_and_a_failed_build_leaves_no_file(monkeypatch):
    with scratch_dir("catalog-") as directory:
        database = directory / "sandbox.db"
        build.build_catalog(SANDBOX, database, rehash=False)
        before = database.read_bytes()
        with pytest.raises(db.CatalogError, match="already exists"):
            build.build_catalog(SANDBOX, database)
        assert database.read_bytes() == before

        def broken(*args, **kwargs):
            raise RuntimeError("discovery failed")

        monkeypatch.setattr(build, "discover", broken)
        with pytest.raises(RuntimeError, match="discovery failed"):
            build.build_catalog(SANDBOX, directory / "partial.db")
        assert not (directory / "partial.db").exists()


def test_an_image_without_a_valid_superblock_creates_no_database():
    with scratch_dir("catalog-") as directory:
        image = write_sparse_image(directory / "zero.img", 1 << 20, {})
        with pytest.raises(NoValidSuperblock):
            build.build_catalog(image, directory / "zero.db")
        assert not (directory / "zero.db").exists()
        assert main(["catalog", "build", str(image), "--db", str(directory / "zero.db")]) == 2
        assert not (directory / "zero.db").exists()


@pytest.mark.sandbox
def test_cli_build_then_info(capsys):
    with scratch_dir("catalog-") as directory:
        database = directory / "cli.db"
        assert main(["catalog", "build", str(SANDBOX), "--db", str(database)]) == 0
        out = capsys.readouterr().out
        assert "image unchanged after the pass: yes" in out
        assert "candidates: 85 (valid 84); live 20, backup_reachable 34, unreferenced 30" in out
        assert main(["catalog", "build", str(SANDBOX), "--db", str(database)]) == 1
        assert "already exists" in capsys.readouterr().err
        assert main(["catalog", "build", str(SANDBOX), "--db", str(SANDBOX)]) == 1
        capsys.readouterr()

        assert main(["catalog", "info", str(database), "--json"]) == 0
        info = json.loads(capsys.readouterr().out)
        assert info["scan_run"]["image_sha256_before"] == SANDBOX_SHA256
        assert info["rows"]["nodes"] == 85 and info["rows"]["node_checks"] == 85 * 12
        assert info["classes"] == {
            "backup_reachable": 34, "invalid": 1, "live": 20, "unreferenced": 30,
        }  # fmt: skip
        assert info["blocks"] == 52
        assert main(["catalog", "info", str(directory / "absent.db")]) == 1


# ---------------------------------------------------------------------------
# The corpus images (vm): every checksum type, a log tree, damaged nodes, discard
# ---------------------------------------------------------------------------
COMPARED = [
    "m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m1_mirror_damage",
    "m1_foreign_mirror", "m1_badnode", "m1_badnode_both", "m2_logtree",
    "s01_discard_none_r1", "s01_discard_async_r1", "s01_discard_sync_r1",
]  # fmt: skip


def _corpus_image(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    return path


@pytest.mark.vm
@pytest.mark.parametrize("name", COMPARED)
def test_corpus_database_equals_scan_and_roots(name):
    path = _corpus_image(name)
    with scratch_dir("catalog-") as directory:
        built = build.build_catalog(path, directory / f"{name}.db", full_sweep=True)
        assert built.image_unchanged is True
        _assert_database_equals_scan_and_roots(path, directory / f"{name}.db", full_sweep=True)


@pytest.mark.vm
def test_high_objectids_are_stored_negative_as_btrfs_names_them():
    path = _corpus_image("m2_logtree")
    with scratch_dir("catalog-") as directory:
        build.build_catalog(path, directory / "log.db", rehash=False)
        conn = db.open_readonly(directory / "log.db")
        owners = dict(conn.execute("SELECT owner, COUNT(*) FROM nodes GROUP BY owner").fetchall())
        assert owners[-6] > 0  # BTRFS_TREE_LOG_OBJECTID
        assert all(owner > -256 for owner in owners if owner is not None)
        log = conn.execute("SELECT COUNT(*) FROM nodes WHERE owner = -6 AND log_tree").fetchone()
        assert log[0] > 0
        conn.close()


@pytest.mark.vm
def test_a_refused_format_creates_no_database_unless_overridden(capsys):
    path = _corpus_image("m1_unknown_incompat")
    with scratch_dir("catalog-") as directory:
        database = directory / "gate.db"
        assert main(["catalog", "build", str(path), "--db", str(database)]) == 2
        assert "UNSUPPORTED_INCOMPAT" in capsys.readouterr().err
        assert not database.exists()
        args = ["catalog", "build", str(path), "--db", str(database), "--allow-unsupported"]
        assert main(args) == 0
        conn = db.open_readonly(database)
        run = conn.execute(
            "SELECT gate_status, unsupported_format, gate_unsupported FROM scan_runs"
        )
        assert tuple(run.fetchone()) == ("OVERRIDDEN", 1, '["UNKNOWN_BIT_40"]')
        conn.close()
