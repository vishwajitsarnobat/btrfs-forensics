"""Confidence tiers (plan.md M6c): every rule on a forged record, the back-reference question on
a forged extent tree, the engine on synthetic trees, and the claims of the definition of done on
corpus images, asserted relative to each image and its scenario's log.
"""

import json
import re
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.content import ContentWriter
from btrfska.recover.engine import recover
from btrfska.recover.tiers import CONTRADICTIONS, RULES, TIERS, Backrefs, Evidence, decide
from btrfska.recover.tiers import ExtentEvidence as X
from btrfska.substrate import ondisk
from tests.helpers import NODESIZE, REPO_ROOT, SCENARIOS, make_node, scratch_dir
from tests.test_recover import (
    DATA_LOGICAL,
    DATA_PHYS,
    ROOT_DIR_ITEMS,
    by_source,
    file_items,
    inode_item,
    inode_ref,
    regular,
    run,
    synthetic,
)

K = ondisk.ITEM_KEYS
MIB = 1 << 20
MATCH_OWN = X("match", ("current",), {"current": "agrees"})


def tier(**fields) -> tuple[str, list[str]]:
    return decide(Evidence(**({"anchored": True} | fields)))


# ---------------------------------------------------------------------------
# Each rule on a forged record
# ---------------------------------------------------------------------------
def test_anchored_and_proven_by_the_data_checksum_is_confirmed():
    found, rules = tier(own="current", own_state="current", csum_verdict="match",
                        extents=(MATCH_OWN,))  # fmt: skip
    assert found == "confirmed"
    assert rules == ["blocks_validated", "anchored", "csum_match", "backref_agrees",
                     "generation_owner_consistent"]  # fmt: skip


def test_content_in_a_checksummed_leaf_is_proven_without_a_data_checksum():
    assert tier(csum_verdict="no_csum") == (
        "confirmed", ["blocks_validated", "anchored", "content_in_leaf",
                      "generation_owner_consistent"],
    )  # fmt: skip
    # the same content in a leaf no commit vouches for
    found, rules = tier(anchored=False, csum_verdict="no_csum")
    assert found == "probable" and "not_committed" in rules and "content_in_leaf" in rules


@pytest.mark.parametrize(
    ("verdict", "rule"),
    [("no_csum", "csum_no_csum"), ("unavailable", "csum_unavailable"),
     ("partial_match", "csum_partial_match"), (None, "csum_not_checked")],
)  # fmt: skip
def test_data_without_a_proving_checksum_is_at_most_probable(verdict, rule):
    extent = X(verdict, ("current",) if verdict else (), {"current": "agrees"})
    found, rules = tier(own="current", own_state="current", csum_verdict=verdict,
                        extents=(extent,))  # fmt: skip
    assert (found, rule in rules, "csum_match" in rules) == ("probable", True, False)
    found, rules = tier(anchored=False, csum_verdict=verdict, extents=(extent,))
    assert found == "unattached" and "not_committed" in rules


def test_a_mismatch_is_never_confirmed():
    extent = X("mismatch", ("current",), {"current": "agrees"})
    found, rules = tier(own="current", own_state="current", csum_verdict="mismatch",
                        extents=(extent,))  # fmt: skip
    assert found == "unattached" and "csum_mismatch" in rules and "csum_match" not in rules


def test_a_match_in_another_state_s_csum_tree_needs_that_state_s_back_reference():
    # an older state's file, verified against the current csum tree: the address may be reused
    reused = X("match", ("current",), {"state:9": "agrees", "current": "disagrees"})
    found, rules = tier(own="state:9", own_state="state:9", csum_verdict="match",
                        extents=(reused,))  # fmt: skip
    assert found == "probable" and "csum_match_unattributed" in rules
    assert "backref_agrees" in rules  # its own state's extent tree does give it to the inode
    kept = X("match", ("current",), {"state:9": "agrees", "current": "agrees"})
    assert tier(own="state:9", own_state="state:9", csum_verdict="match",
                extents=(kept,))[0] == "confirmed"  # fmt: skip


def test_an_orphan_is_tied_to_a_commit_only_through_a_vouched_match():
    vouched = X("match", ("state:4",), {"state:4": "agrees"})
    found, rules = tier(anchored=False, csum_verdict="match", extents=(vouched,))
    assert found == "confirmed" and "backref_attributed" in rules and "csum_match" in rules
    for refs in ({"state:4": "unknown"}, {"state:4": "disagrees"}, {}):
        found, rules = tier(anchored=False, csum_verdict="match",
                            extents=(X("match", ("state:4",), refs),))  # fmt: skip
        assert found == "unattached" and "not_committed" in rules, refs
        assert "csum_match_unattributed" in rules
    # one extent vouched for, another not: no commit vouches for the whole file
    other = X("no_csum", ("state:4",), {"state:4": "agrees"})
    assert tier(anchored=False, csum_verdict="partial_match",
                extents=(vouched, other))[0] == "unattached"  # fmt: skip


def test_a_log_tree_s_own_checksums_prove_content_but_tie_it_to_no_commit():
    own = X("match", ("log:9@12",), {})
    found, rules = tier(anchored=False, own="log:9@12", csum_verdict="match", extents=(own,))
    assert found == "probable" and "csum_match" in rules and "not_committed" in rules


@pytest.mark.parametrize(
    ("fields", "rule"),
    [
        ({"validated": False}, "block_not_validated"),
        ({"generation_problems": ("the INODE_ITEM is newer than its leaf",)},
         "generation_inconsistent"),
        ({"owner_problems": ("leaf 1 is owned by tree 2, not 5",)}, "owner_inconsistent"),
        ({"inode_older": True}, "inode_item_older_than_extent"),
    ],
)  # fmt: skip
def test_every_contradiction_gives_unattached_whatever_else_holds(fields, rule):
    found, rules = tier(own="current", own_state="current", csum_verdict="match",
                        extents=(MATCH_OWN,), **fields)  # fmt: skip
    assert found == "unattached" and rule in rules
    consistent = rule not in ("generation_inconsistent", "owner_inconsistent")
    assert ("generation_owner_consistent" in rules) == consistent


def test_the_own_state_s_extent_tree_supports_contradicts_or_says_nothing():
    for verdict, rule, expected in (
        ("agrees", "backref_agrees", "confirmed"),
        ("unknown", "backref_unknown", "confirmed"),
        ("disagrees", "backref_disagrees", "unattached"),
    ):
        extent = X("match", ("current",), {"current": verdict})
        found, rules = tier(own="current", own_state="current", csum_verdict="match",
                            extents=(extent,))  # fmt: skip
        assert (found, rule in rules) == (expected, True), verdict


def test_unread_content_and_a_missing_inode_item_are_not_proven():
    found, rules = tier(content_read=False)
    assert found == "probable" and "not_complete" in rules and "content_in_leaf" not in rules
    found, rules = tier(has_inode=False)
    assert found == "probable" and "no_inode_item" in rules
    assert tier(anchored=False, content_read=False)[0] == "unattached"


def test_rules_are_listed_in_table_order_and_every_tier_and_contradiction_is_named():
    _, rules = tier(own="current", own_state="current", csum_verdict="match",
                    extents=(MATCH_OWN,), inode_older=True, owner_problems=("x",))  # fmt: skip
    assert rules == sorted(rules, key=RULES.index)
    assert CONTRADICTIONS <= set(RULES) and TIERS == ("confirmed", "probable", "unattached")


def test_the_documents_give_every_rule():
    readme = (REPO_ROOT / "README.md").read_text()
    section = readme.split("### `btrfska recover`", 1)[1].split("\n## ", 1)[0]
    evidence = (REPO_ROOT / "docs" / "evidence-db.md").read_text()
    table = evidence.split("### Confidence tiers", 1)[1].split("\n## ", 1)[0]
    plan = (REPO_ROOT / "docs" / "plan.md").read_text().split("**M6c:", 1)[1].split("**M6f:")[0]
    for text in (section, table, plan):
        assert {rule for rule in RULES if f"`{rule}`" not in text} == set()
        assert {t for t in TIERS if f"`{t}`" not in text} == set()


# ---------------------------------------------------------------------------
# The back-reference question on a forged extent tree
# ---------------------------------------------------------------------------
EXTENT, PARENT, STATE_GEN = 8 * MIB, 50 * MIB, 20


def extent_item(bytenr: int, length: int, *refs: bytes) -> tuple:
    head = struct.pack("<QQQ", 1, 9, ondisk.EXTENT_FLAG_DATA)
    return (bytenr, K["EXTENT_ITEM"], length), head + b"".join(refs)


def data_ref(objectid: int, root: int = 5) -> bytes:
    return struct.pack("<BQQQI", K["EXTENT_DATA_REF"], root, objectid, 0, 1)


def shared_ref(parent: int) -> bytes:
    return struct.pack("<BQI", K["SHARED_DATA_REF"], parent, 1)


def forged(d, extent_items: list, *, state_tree: bool = True, gap: bool = False,
           file_leaf: list | None = None):  # fmt: skip
    """A database with one state whose extent tree is one leaf holding `extent_items` (or, with
    `gap`, a root whose only child was never scanned), and a file-tree leaf at PARENT."""
    conn = db.create(d / "forged.db")
    conn.execute("INSERT INTO regions (region_id, scanned, kind, start_offset, end_offset)"
                 " VALUES (1, 1, 'METADATA', 0, 1)")  # fmt: skip
    writer = ContentWriter(conn, NODESIZE)
    blocks = [(40 * MIB, ondisk.EXTENT_TREE_OBJECTID, sorted(extent_items), 0)]
    if gap:
        blocks = [(40 * MIB, ondisk.EXTENT_TREE_OBJECTID, [((0, 0, 0), 41 * MIB, 9)], 1)]
    if file_leaf is not None:
        blocks.append((PARENT, 5, sorted(file_leaf), 0))
    for number, (bytenr, owner, entries, level) in enumerate(blocks):
        block = (make_node(bytenr, level=1, ptrs=entries, owner=owner, generation=9) if level
                 else make_node(bytenr, items=entries, owner=owner, generation=9))  # fmt: skip
        conn.execute(
            "INSERT INTO nodes (physical, region_id, bytenr, generation, owner, level, nritems,"
            " valid, status, orphan, outside_map, legacy_orphan, log_tree, bytenr_mapped,"
            " maps_here, problems, content_id)"
            " VALUES (?, 1, ?, 9, ?, ?, ?, 1, 'live', 0, 0, 0, 0, 1, 1, '[]', ?)",
            (MIB + number * NODESIZE, bytenr, owner, level, len(entries),
             writer.add(block, True)),
        )  # fmt: skip
    writer.flush()
    conn.execute(
        "INSERT INTO states (state_id, bytenr, generation, level, known_as, root_tree_blocks,"
        " root_tree_missing, found, referenced, completeness, missing, maps_current,"
        " maps_neither, level_consistent, problems)"
        " VALUES (1, 9000, ?, 0, '[\"current\"]', 1, 0, 1, 1, 1.0, '{}', 1, 0, 1, '[]')",
        (STATE_GEN,),
    )
    if state_tree:
        conn.execute("INSERT INTO state_trees VALUES (1, 0, 2, 0, ?, 9, ?, 9000, 0, 'found', 1, 0)",
                     (40 * MIB, int(gap)))  # fmt: skip
    conn.commit()
    return conn


def test_an_extent_data_ref_to_the_inode_agrees_and_its_absence_disagrees():
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [extent_item(EXTENT, 4096, data_ref(257))])
        refs = Backrefs(conn)
        assert refs.check(1, EXTENT, 4096, 257) == "agrees"
        assert refs.check(1, EXTENT, 4096, 258) == "disagrees"  # another inode's extent
        assert refs.check(1, EXTENT, 8192, 257) == "disagrees"  # another allocation
        assert refs.check(1, EXTENT + 4096, 4096, 257) == "disagrees"  # no extent there
        assert refs.tree(1)[1] is True
        conn.close()


def test_a_snapshot_s_copy_agrees_through_the_original_tree_s_reference():
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [extent_item(EXTENT, 4096, data_ref(257, root=256))])
        assert Backrefs(conn).check(1, EXTENT, 4096, 257) == "agrees"
        conn.close()


def test_a_shared_data_ref_agrees_only_through_a_leaf_holding_the_file_extent():
    holder = [((257, K["EXTENT_DATA"], 0), regular(EXTENT, 4096))]
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [extent_item(EXTENT, 4096, shared_ref(PARENT))], file_leaf=holder)
        refs = Backrefs(conn)
        assert refs.check(1, EXTENT, 4096, 257) == "agrees"
        assert refs.check(1, EXTENT, 4096, 300) == "disagrees"
        conn.close()
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [extent_item(EXTENT, 4096, shared_ref(PARENT + NODESIZE))],
                      file_leaf=holder)  # fmt: skip
        assert Backrefs(conn).check(1, EXTENT, 4096, 257) == "disagrees"
        conn.close()


def test_a_missing_or_gapped_extent_tree_says_nothing():
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [extent_item(EXTENT, 4096, data_ref(257))], state_tree=False)
        assert Backrefs(conn).check(1, EXTENT, 4096, 257) == "unknown"
        conn.close()
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, [], gap=True)
        refs = Backrefs(conn)
        assert refs.check(1, EXTENT, 4096, 257) == "unknown" and refs.tree(1)[1] is False
        conn.close()


def test_hostile_back_references_do_not_raise():
    entries = [
        extent_item(EXTENT, 4096, b"\xff" * 5),  # an inline ref of no known type
        ((EXTENT, K["EXTENT_DATA_REF"], 1), b"\x00" * 3),  # too short
        ((EXTENT, K["SHARED_DATA_REF"], 1 << 63), struct.pack("<I", 1)),
        extent_item(EXTENT + 4096, 0, data_ref(257)),  # an empty extent
    ]
    with scratch_dir("test_tiers_") as d:
        conn = forged(d, entries)
        refs = Backrefs(conn)
        assert refs.check(1, EXTENT, 4096, 257) == "disagrees"
        assert refs.check(1, EXTENT + 4096, 0, 257) in ("agrees", "disagrees")
        assert refs.check(1, (1 << 64) - 4096, 4096, (1 << 64) - 1) == "disagrees"
        conn.close()


# ---------------------------------------------------------------------------
# The engine on synthetic trees
# ---------------------------------------------------------------------------
def rules_of(row) -> list[str]:
    return json.loads(row["tier_rules"])


def test_every_artifact_gets_a_tier_its_rules_and_its_chain():
    current = [*ROOT_DIR_ITEMS, *file_items(257, b"inline", b"in the leaf"),
               ((258, K["INODE_ITEM"], 0), inode_item(4096)),
               ((258, K["INODE_REF"], 256), inode_ref(b"on-disk")),
               ((258, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, 4096))]  # fmt: skip
    with synthetic({"current": current}, data={DATA_PHYS: b"d" * 4096}) as (conn, reader, out):
        done, _ = run(conn, reader, out)
        rows = by_source(conn)
        # inline content in a committed tree: proven by the leaf checksum
        assert rows["anchored_root", 257]["tier"] == "confirmed"
        assert rules_of(rows["anchored_root", 257]) == [
            "blocks_validated", "anchored", "content_in_leaf", "generation_owner_consistent"
        ]  # fmt: skip
        # data on disk with no csum tree to check it against, no extent tree to ask
        on_disk = rows["anchored_root", 258]
        assert on_disk["csum_verdict"] == "unavailable" and on_disk["tier"] == "probable"
        assert {"csum_unavailable", "backref_unknown"} <= set(rules_of(on_disk))
        chain = json.loads(on_disk["provenance_chain"])
        assert chain["root"] == {"source": "current", "kind": "anchored_root", "state_id": 1,
                                 "tree_id": 5, "subvolume": None, "bytenr": chain["root"]["bytenr"],
                                 "generation": 8, "level": 0, "named_by": None}  # fmt: skip
        assert [leaf["owner"] for leaf in chain["leaves"]] == [5]
        assert chain["extent_trees"] == [{"state": "current", "complete": None}]
        backref = conn.execute(
            "SELECT backref, read_record FROM provenance WHERE artifact_id = ?"
            " AND role = 'extent_data'",
            (on_disk["artifact_id"],),
        ).fetchone()
        assert backref[0] == "unknown"
        assert json.loads(backref[1])["backref"] == [{"state": "current", "verdict": "unknown"}]
        assert done.by_tier == {("anchored_root", "confirmed"): 1, ("anchored_root", "probable"): 1}
        manifest = [json.loads(line) for line in (out / "manifest.jsonl").read_text().splitlines()]
        assert {m["tier"] for m in manifest} == {"confirmed", "probable"}
        assert all(isinstance(m["tier_rules"], list) and m["provenance_chain"] for m in manifest)


def test_a_lone_leaf_is_not_tied_to_a_commit():
    lost = [*ROOT_DIR_ITEMS, *file_items(300, b"gone", b"only in a lone leaf", generation=6),
            ((301, K["INODE_ITEM"], 0), inode_item(4096, generation=6)),
            ((301, K["INODE_REF"], 256), inode_ref(b"data")),
            ((301, K["EXTENT_DATA"], 0), regular(DATA_LOGICAL, 4096))]  # fmt: skip
    with synthetic({"current": ROOT_DIR_ITEMS}, data={DATA_PHYS: b"x" * 4096},
                   loose=(lost,)) as (conn, reader, out):  # fmt: skip
        run(conn, reader, out, orphans=True)
        rows = by_source(conn)
        inline = rows["orphan_node", 300]
        assert inline["tier"] == "probable"
        assert {"not_committed", "content_in_leaf"} <= set(rules_of(inline))
        assert rows["orphan_node", 301]["tier"] == "unattached"
        assert "backref_unknown" not in rules_of(rows["orphan_node", 301])  # not anchored


def test_an_inode_item_newer_than_its_leaf_contradicts_the_artifact():
    forged_items = [*ROOT_DIR_ITEMS, *file_items(257, b"f", b"x", transid=30)]
    with synthetic({"current": forged_items}) as (conn, reader, out):
        run(conn, reader, out)
        row = by_source(conn)["anchored_root", 257]
        assert row["tier"] == "unattached" and "generation_inconsistent" in rules_of(row)
        assert any("is newer than its leaf" in p for p in json.loads(row["problems"]))


def test_a_duplicate_repeats_its_original_s_notes_verdicts_and_tier():
    same = [*ROOT_DIR_ITEMS, *file_items(257, b"kept", b"unchanged")]
    with synthetic({"backup:8": same, "backup:7": same}) as (conn, reader, out):
        run(conn, reader, out, sources=("backup:8", "backup:7"))
        rows = {
            r["source"]: r for r in conn.execute("SELECT * FROM artifacts WHERE objectid = 257")
        }
        first, copy = rows["backup:8"], rows["backup:7"]
        assert copy["status"] == "duplicate" and copy["tier"] == first["tier"] == "confirmed"
        assert rules_of(copy) == [*rules_of(first), "duplicate"]
        for column in ("csum_verdict", "csum_sources", "space_verdict", "overwrite_risk"):
            assert copy[column] == first[column], column
        notes = json.loads(copy["problems"])
        assert notes[0] == f"the same file as artifact {first['artifact_id']}, whose notes follow"
        assert notes[1:] == json.loads(first["problems"])
        chain = json.loads(copy["provenance_chain"])
        assert (
            chain["duplicate_of"] == first["artifact_id"] and chain["root"]["source"] == "backup:7"
        )


# ---------------------------------------------------------------------------
# Corpus images
# ---------------------------------------------------------------------------
def recovered(image, **options):
    if not image.exists():
        pytest.skip(f"{image.name} not built (./setup.sh)")
    directory = scratch_dir(f"test_tiers_{image.stem}_")
    path = directory.__enter__()
    build_catalog(image, path / "evidence.db", full_sweep=True)
    recover(image, path / "evidence.db", path / "out", **options)
    return directory, db.open_readonly(path / "evidence.db")


@pytest.fixture
def image_db(request):
    directory, conn = recovered(SCENARIOS / f"{request.param[0]}.img", **request.param[1])
    yield conn
    conn.close()
    directory.__exit__(None, None, None)


def files(conn, where: str = "1") -> list:
    return conn.execute(
        f"SELECT * FROM artifacts WHERE kind = 'file' AND status != 'duplicate' AND {where}"
    ).fetchall()


def has_data_with_checksums(conn, artifact_id: int) -> bool:
    records = [json.loads(r[0]) for r in conn.execute(
        "SELECT read_record FROM provenance WHERE artifact_id = ? AND role = 'extent_data'",
        (artifact_id,),
    )]  # fmt: skip
    flags = conn.execute(
        "SELECT i.flags FROM provenance p JOIN inodes i USING (content_id, slot)"
        " WHERE p.artifact_id = ? AND p.role = 'inode_item'",
        (artifact_id,),
    ).fetchone()
    on_disk = any(r and r["kind"] == "regular" and r["csum"] for r in records)
    return on_disk and not (flags and flags[0] & ondisk.INODE_NODATASUM)


@pytest.mark.parametrize(
    "image_db",
    [(name, {"tree_id": None}) for name in
     ("m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m6_datacsum")],
    indirect=True,
)  # fmt: skip
def test_current_files_with_checksummed_data_are_confirmed(image_db):
    found = files(image_db)
    checked = [row for row in found if has_data_with_checksums(image_db, row["artifact_id"])]
    assert checked
    for row in checked:
        assert row["tier"] == "confirmed", (row["path"], rules_of(row))
        assert {"anchored", "csum_match", "backref_agrees"} <= set(rules_of(row))
    assert all(row["tier"] for row in image_db.execute("SELECT tier FROM artifacts"))
    disagree = image_db.execute(
        "SELECT COUNT(*) FROM artifacts WHERE tier_rules LIKE '%backref_disagrees%'"
    ).fetchone()[0]
    assert disagree == 0


def logged(image) -> dict[str, str]:
    return dict(re.findall(r"=== FILE (\S+) ([0-9a-f]{64})", image.with_suffix(".log").read_text()))


@pytest.mark.parametrize("image_db", [("m6_datacsum", {})], indirect=True)
def test_the_nodatasum_file_is_probable_and_inline_and_prealloc_files_are_confirmed(image_db):
    rows = {row["path"]: row for row in files(image_db)}
    assert set(logged(SCENARIOS / "m6_datacsum.img")) <= set(rows)
    assert rows["nosum.txt"]["tier"] == "probable"
    assert "csum_no_csum" in rules_of(rows["nosum.txt"])
    for name in ("inline.txt", "prealloc.bin"):
        assert rows[name]["tier"] == "confirmed" and "content_in_leaf" in rules_of(rows[name])


@pytest.mark.parametrize("image_db", [("m6_datacsum_flipped", {})], indirect=True)
def test_a_mismatch_on_the_flipped_image_is_never_confirmed(image_db):
    rows = {row["path"]: row for row in files(image_db)}
    damaged = rows["damaged.txt"]
    assert damaged["csum_verdict"] == "mismatch" and damaged["tier"] == "unattached"
    assert "csum_mismatch" in rules_of(damaged)
    repaired = rows["repairable.txt"]  # read from the other mirror, checksum and all
    assert repaired["tier"] == "confirmed"
    assert not files(image_db, "csum_verdict = 'mismatch' AND tier = 'confirmed'")


@pytest.mark.parametrize(
    "image_db", [("m4_deep", {"roots": ("all",), "orphans": True, "logs": True})], indirect=True
)
def test_deep_orphan_versions_are_confirmed_only_when_a_commit_vouches_for_their_checksum(image_db):
    orphans = files(image_db, "source_kind IN ('orphan_node', 'orphan_graph')")
    assert orphans
    for row in orphans:
        rules = rules_of(row)
        if row["tier"] == "confirmed":
            assert {"csum_match", "backref_attributed"} <= set(rules), row["path"]
        assert "anchored" not in rules
    assert {row["tier"] for row in orphans} >= {"probable", "unattached"}
    # every log-tree file with data on disk is proven by the log's own checksums, and no more
    logs = files(image_db, "source_kind = 'log_tree' AND tier = 'confirmed'")
    assert all("backref_attributed" in rules_of(row) for row in logs)
    summary = json.loads(image_db.execute("SELECT summary FROM recovery_runs").fetchone()[0])
    assert (
        sum(summary["by_tier"].values())
        == image_db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    )
    assert set(summary["tier_rules"]) <= set(RULES)


@pytest.mark.parametrize("image_db", [("m5_reuse", {"roots": ("all",), "tree_id": None})],
                         indirect=True)  # fmt: skip
def test_every_version_of_b_bin_carries_the_reuse_note_in_its_own_row(image_db):
    versions = image_db.execute(
        "SELECT * FROM artifacts WHERE kind = 'file' AND (path = 'b.bin' OR path LIKE '%/b.bin')"
        " AND size = ?",
        (10 * 4 * MIB,),
    ).fetchall()
    duplicates = [row for row in versions if row["status"] == "duplicate"]
    assert duplicates and len(versions) > len(duplicates)
    for row in versions:
        notes = json.loads(row["problems"])
        assert any("places this address in a different chunk" in note for note in notes)
        if row["status"] == "duplicate":
            original = image_db.execute(
                "SELECT tier, tier_rules, csum_verdict FROM artifacts WHERE artifact_id = ?",
                (row["duplicate_of"],),
            ).fetchone()
            assert (row["tier"], row["csum_verdict"]) == (original[0], original[2])
            assert rules_of(row) == [*json.loads(original[1]), "duplicate"]
