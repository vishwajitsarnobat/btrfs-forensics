"""Timelines (plan.md M5d, claim C3): versions of every inode identity across every cataloged
state, and the events between them. Synthetic trees for each kind of event; `sandbox.img` for
the known history of generations 11 to 14; `m4_deep` against the hashes its log holds.
"""

import json
import re
import struct

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.cli import main
from btrfska.recover.engine import recover
from btrfska.substrate import ondisk
from btrfska.timeline.build import Timeline, delta, hashes
from tests.helpers import REPO_ROOT, SCENARIOS, scratch_dir
from tests.test_recover import (
    DATA_LOGICAL,
    META_LOGICAL,
    NODESIZE,
    ROOT_DIR_ITEMS,
    dir_items_,
    file_items,
    inode_item,
    inode_ref,
    synthetic,
)
from tests.test_scan_roots import root_item

K = ondisk.ITEM_KEYS
SECTOR = 4096
SANDBOX = REPO_ROOT / "sandbox.img"
DEEP = SCENARIOS / "m4_deep.img"
LOG = ondisk.TREE_LOG_OBJECTID


def regular(sector: int, sectors: int = 1, generation: int = 7, offset: int = 0) -> bytes:
    length = sectors * SECTOR
    return struct.pack(
        ondisk.FILE_EXTENT_ITEM.format, generation, length, 0, 0, 0, ondisk.FILE_EXTENT_REG,
        DATA_LOGICAL + sector * SECTOR, 16 * SECTOR, offset, length,
    )  # fmt: skip


def events_of(trees: dict, loose=(), **options) -> list[dict]:
    """Events of tree 5; `trees` oldest first (the synthetic catalog numbers them in order)."""
    with synthetic(trees, loose=tuple(loose)) as (conn, _, _):
        timeline = Timeline(conn, **options)
        return [*timeline.subvolume_events(), *timeline.events(5)]


def kinds(events: list[dict], objectid: int) -> list[str]:
    return [e["event"] for e in events if e["objectid"] == objectid]


def test_create_modify_rename_move_attr_and_delete_each_with_the_states_that_bound_it():
    first = [*ROOT_DIR_ITEMS, *dir_items_(300, b"docs"), *file_items(257, b"a.txt", b"one")]
    second = [*ROOT_DIR_ITEMS, *dir_items_(300, b"docs"),
              *file_items(257, b"b.txt", b"two!", generation=7, transid=9)]  # fmt: skip
    third = [*ROOT_DIR_ITEMS, *dir_items_(300, b"docs"),
             *file_items(257, b"b.txt", b"two!", parent=300, generation=7, transid=10,
                         mode=0o100600)]  # fmt: skip
    events = events_of({"backup:8": first, "backup:9": second, "backup:10": third,
                        "current": [*ROOT_DIR_ITEMS, *dir_items_(300, b"docs")]})  # fmt: skip
    mine = [e for e in events if e["objectid"] == 257]
    assert [e["event"] for e in mine] == ["create", "rename", "modify", "move", "attr", "delete"]
    create, rename, modify, move, attr, delete = mine
    assert (create["transaction"], create["path"], create["first_seen"]["source"]) == (
        7, "a.txt", "backup:8",
    )  # fmt: skip
    assert (rename["from"]["name"], rename["to"]["name"], rename["transaction"]) == (
        "a.txt", "b.txt", 9,
    )  # fmt: skip
    assert rename["between"] == ["backup:8", "backup:9"]
    assert modify["size_before"] == 3 and modify["size"] == 4
    assert modify["delta"] == [{"offset": 0, "length": 3, "change": "replaced"},
                               {"offset": 3, "length": 1, "change": "added"}]  # fmt: skip
    assert (move["from"]["path"], move["to"]["path"]) == ("b.txt", "docs/b.txt")
    assert attr["before"]["mode"] == 0o100644 and attr["after"]["mode"] == 0o100600
    assert delete["between"] == ["backup:10", "current"] and delete["transaction"] is None
    assert delete["generations"][0] < delete["generations"][1]
    assert delete["path"] == "docs/b.txt"  # what was deleted is the last version seen


def test_a_reused_inode_number_is_two_files_not_a_rename():
    before = [*ROOT_DIR_ITEMS, *file_items(257, b"gone", b"deleted later", generation=7)]
    after = [*ROOT_DIR_ITEMS, *file_items(257, b"other", b"same number", generation=9)]
    events = events_of({"backup:8": before, "current": after})
    mine = [(e["event"], e["created"], e["path"]) for e in events if e["objectid"] == 257]
    assert mine == [("create", 7, "gone"), ("delete", 7, "gone"), ("create", 9, "other")]
    second = [e for e in events if e["created"] == 9][0]
    assert second["reused_inode_number"] and second["previous_creation_generations"] == [7]
    assert "rename" not in kinds(events, 257)


def test_hard_links_come_and_go_as_link_and_unlink():
    one = [*ROOT_DIR_ITEMS, *file_items(257, b"a", b"x", nlink=1)]
    two = [*ROOT_DIR_ITEMS, *file_items(257, b"a", b"x", nlink=2, transid=9),
           ((257, K["INODE_REF"], 300), inode_ref(b"b"))]  # fmt: skip
    events = events_of({"backup:8": one, "backup:9": two, "current": one})
    mine = [e for e in events if e["objectid"] == 257]
    assert [e["event"] for e in mine] == ["create", "link", "unlink"]
    assert mine[1]["name"] == {"parent": 300, "name": "b"}


def test_a_change_of_the_inode_item_alone_is_a_touch_and_an_unchanged_file_is_one_version():
    same = [*ROOT_DIR_ITEMS, *file_items(257, b"a", b"x")]
    touched = [*ROOT_DIR_ITEMS, *file_items(257, b"a", b"x", transid=9)]
    events = events_of(
        {"backup:8": same, "backup:9": same, "backup:10": touched, "current": touched}
    )
    assert kinds(events, 257) == ["create", "touch"]
    create = [e for e in events if e["objectid"] == 257][0]
    assert create["seen_in"] == 2 and create["last_seen"]["source"] == "backup:9"


def test_two_states_of_one_generation_are_ordered_by_an_assumption_and_the_event_says_so():
    empty = [*ROOT_DIR_ITEMS, *file_items(257, b"f", b"")]
    written = [*ROOT_DIR_ITEMS, *file_items(257, b"f", b"data")]
    with synthetic({"state:a": empty, "current": written}) as (conn, _, _):
        conn.execute("UPDATE states SET generation = 9")  # both root trees of generation 9
        conn.execute("UPDATE states SET known_as = '[]' WHERE known_as LIKE '%state:a%'")
        events = [e for e in Timeline(conn).events(5) if e["objectid"] == 257]
    assert [(e["event"], e["order_assumed"]) for e in events] == [
        ("create", False), ("modify", True),
    ]  # fmt: skip
    assert events[1]["between"][1] == "current"  # the one a superblock slot names comes last


def test_delta_compares_what_the_extents_point_at_not_how_they_are_cut():
    whole = ((0, 3 * SECTOR, ("regular", 100, 0), 0),)
    split = ((0, SECTOR, ("regular", 100, 0), 0), (SECTOR, 2 * SECTOR, ("regular", 100, 0), SECTOR))
    assert delta(whole, split) == []  # the same bytes of the same extent, in two items
    middle = ((0, SECTOR, ("regular", 100, 0), 0), (SECTOR, SECTOR, ("regular", 900, 0), 0),
              (2 * SECTOR, SECTOR, ("regular", 100, 0), 2 * SECTOR))  # fmt: skip
    assert delta(whole, middle) == [{"offset": SECTOR, "length": SECTOR, "change": "replaced"}]
    assert delta(whole, whole[:0]) == [{"offset": 0, "length": 3 * SECTOR, "change": "removed"}]
    hole = ((0, SECTOR, ("hole",), None),)
    assert delta(hole, hole) == [] and delta((), hole)[0]["change"] == "added"


def test_absence_from_a_walk_with_a_gap_is_not_a_delete():
    held = [*ROOT_DIR_ITEMS, *file_items(257, b"a", b"x")]
    with synthetic({"backup:8": held, "current": list(ROOT_DIR_ITEMS)}) as (conn, _, _):
        timeline = Timeline(conn)
        assert [e["event"] for e in timeline.events(5) if e["objectid"] == 257][-1] == "delete"
        for shown in timeline.trees[5]:
            if shown.seen.source == "current":
                shown.complete = False  # as when a block of that tree was not found
        last = [e for e in timeline.events(5) if e["objectid"] == 257][-1]
        assert last["event"] == "not_seen" and "absence proves nothing" in last["reason"]


def test_uncommitted_sources_add_versions_never_a_delete_and_name_what_was_never_committed():
    committed = [*ROOT_DIR_ITEMS, *file_items(257, b"kept", b"x")]
    lone = {"items": [*ROOT_DIR_ITEMS, *file_items(300, b"flash", b"never committed",
                                                   generation=9)],
            "generation": 9}  # fmt: skip
    trees = {"backup:8": committed, "current": committed}  # generations 8 and 9
    assert kinds(events_of(trees, [lone]), 300) == []
    events = events_of(trees, [lone], uncommitted=True)
    assert kinds(events, 300) == ["create", "never_committed"]
    assert all(e["uncommitted_only"] for e in events if e["objectid"] == 300)
    assert kinds(events, 257) == ["create"]  # absent from the lone leaf: that proves nothing


def test_never_committed_needs_the_commit_of_its_creating_transaction_walked_whole():
    """EXP-009: a file committed in generation 10, whose only view left was an uncommitted leaf
    of 10 while the committed state of 10 survived only with gaps, was said never committed.
    Absence proves it only from the tree as that transaction's commit left it, walked whole."""
    committed = [*ROOT_DIR_ITEMS, *file_items(257, b"kept", b"x")]
    created_in_9 = [*ROOT_DIR_ITEMS, *file_items(300, b"f", b"y", generation=9)]
    trees = {"backup:8": committed, "current": committed}  # generations 8 and 9

    def ending(items=created_in_9, gapped=False, current_generation=9):
        with synthetic(trees, loose=({"items": items, "generation": 9},)) as (conn, _, _):
            for table in ("states", "state_trees"):
                conn.execute(f"UPDATE {table} SET generation = ? WHERE state_id = 2",
                             (current_generation,))  # fmt: skip
            timeline = Timeline(conn, uncommitted=True)
            for shown in timeline.trees[5]:
                if shown.seen.source == "current" and gapped:
                    shown.complete = False  # as when a block of that tree was not found
            return [e for e in timeline.events(5) if e["objectid"] == 300][-1]

    proved = ending()
    assert (proved["event"], proved["generations"], proved["order_assumed"]) == (
        "never_committed", [8, 9], False,
    )  # fmt: skip
    gapped = ending(gapped=True)
    assert gapped["event"] == "not_seen" and "walked with gaps" in gapped["reason"]
    assert gapped["between"] is None and gapped["generations"] is None  # when it ended: unknown
    lost = ending(current_generation=10)  # no committed state of generation 9 survives
    assert lost["event"] == "not_seen" and "whether a commit held it is unknown" in lost["reason"]
    # created in 7 and still there in 9: a commit held it, even if no surviving one does
    older = ending([*ROOT_DIR_ITEMS, *file_items(300, b"f", b"y", generation=7)])
    assert older["event"] == "not_seen" and "so a commit held it" in older["reason"]


def test_a_name_that_a_walk_did_not_reach_is_no_link_and_no_unlink():
    """EXP-009: `pad/p2` had no name in states whose walks had gaps (its INODE_REF lay in a leaf
    they did not reach) and its name again from the next whole walk on: a `link` that never
    happened. A fragment or a lone leaf is a part of a tree and can miss a name the same way."""
    inode_item_, _, extent = file_items(257, b"p2", b"x")
    nameless = [*ROOT_DIR_ITEMS, inode_item_, extent]
    named = [*ROOT_DIR_ITEMS, *file_items(257, b"p2", b"x")]
    renamed = [*ROOT_DIR_ITEMS, *file_items(257, b"p3", b"x", transid=11)]
    trees = {"backup:8": named, "backup:9": nameless, "backup:10": named, "current": renamed}
    with synthetic(trees) as (conn, _, _):
        timeline = Timeline(conn)
        # walked whole, the name really was gone in 9
        assert kinds(list(timeline.events(5)), 257) == ["create", "unlink", "link", "rename"]
        for shown in timeline.trees[5]:
            if shown.seen.source == "backup:9":
                shown.complete = False
        # with a gap it may only have been out of reach; the rename between whole walks stays
        assert kinds(list(timeline.events(5)), 257) == ["create", "rename"]
    lone = {"items": nameless, "generation": 10}
    events = events_of({"backup:8": named, "backup:9": named, "current": named}, [lone],
                       uncommitted=True)  # fmt: skip
    assert kinds(events, 257) == ["create"]


def test_an_uncommitted_version_with_a_stale_inode_item_is_marked_inconsistent():
    stale = {"generation": 9, "items": [
        *ROOT_DIR_ITEMS, ((257, K["INODE_ITEM"], 0), inode_item(SECTOR, generation=7)),
        ((257, K["INODE_REF"], 256), inode_ref(b"f")),
        ((257, K["EXTENT_DATA"], 0), regular(0, 1, generation=9))]}  # fmt: skip
    events = events_of({"current": list(ROOT_DIR_ITEMS)}, [stale], uncommitted=True)
    assert [e["inconsistent"] for e in events if e["objectid"] == 257] == [True, True]


def test_payloads_that_do_not_parse_and_parent_cycles_do_not_stop_a_timeline():
    broken = [*ROOT_DIR_ITEMS, ((257, K["INODE_ITEM"], 0), b"short"),
              ((258, K["INODE_ITEM"], 0), inode_item(5)),
              ((258, K["INODE_REF"], 259), inode_ref(b"a")),
              ((258, K["EXTENT_DATA"], 0), b"\x00" * 7),
              *dir_items_(259, b"loop", parent=260),
              *dir_items_(260, b"pool", parent=259)]  # fmt: skip
    events = events_of({"backup:8": broken, "current": list(ROOT_DIR_ITEMS)})
    assert kinds(events, 257) == []  # no INODE_ITEM that parses: no identity
    assert kinds(events, 258) == ["create", "delete"]
    assert not [e for e in events if e["objectid"] == 258][0]["attached"]


def test_hundreds_of_states_cost_one_walk_per_distinct_tree_root_and_give_one_version():
    same = [*ROOT_DIR_ITEMS, *file_items(257, b"f", b"x")]
    trees = {f"backup:{n}": same for n in range(8, 308)} | {"current": list(ROOT_DIR_ITEMS)}
    with synthetic(trees) as (conn, _, _):
        timeline = Timeline(conn)
        events = [e for e in timeline.events(5) if e["objectid"] == 257]
    assert [e["event"] for e in events] == ["create", "delete"]
    assert events[0]["seen_in"] == 300 and len(timeline.trees[5]) == 301


def test_a_log_leaf_is_replayed_over_its_base_not_read_as_a_version_of_its_own():
    """A 3-sector file committed, then one sector rewritten and fsynced: the log holds one
    extent. Read on its own it would be a modify that removed two sectors; replayed it is one
    sector replaced. An inode logged in exists-only mode (generation 0) is no identity."""
    base = [*ROOT_DIR_ITEMS, ((257, K["INODE_ITEM"], 0), inode_item(3 * SECTOR)),
            ((257, K["INODE_REF"], 256), inode_ref(b"f")),
            ((257, K["EXTENT_DATA"], 0), regular(0, 3))]  # fmt: skip
    log_leaf = META_LOGICAL + 100 * NODESIZE
    logged = {"owner": LOG, "generation": 9, "bytenr": log_leaf, "items": [
        ((257, K["INODE_ITEM"], 0), inode_item(3 * SECTOR, transid=9)),
        ((257, K["EXTENT_DATA"], SECTOR), regular(8, 1, generation=9)),
        ((300, K["INODE_ITEM"], 0), inode_item(0, generation=0, transid=9)),
        ((300, K["INODE_REF"], 256), inode_ref(b"exists"))]}  # fmt: skip
    # the log root tree: one ROOT_ITEM per logged subvolume, its key offset the subvolume
    log_root = {"owner": LOG, "generation": 9, "items": [((LOG, K["ROOT_ITEM"], 5),
                                                         root_item(log_leaf, 9))]}  # fmt: skip
    with synthetic({"current": base}, loose=(logged, log_root)) as (conn, _, _):
        conn.execute("UPDATE states SET generation = 8")
        events = list(Timeline(conn, uncommitted=True).events(5))
    mine = [e for e in events if e["objectid"] == 257]
    assert [e["event"] for e in mine] == ["create", "modify"]
    assert mine[1]["delta"] == [{"offset": SECTOR, "length": SECTOR, "change": "replaced"}]
    assert mine[1]["first_seen"]["source"].startswith("log:") and not mine[1]["log_only"]
    assert kinds(events, 300) == []


# ---------------------------------------------------------------------------
# sandbox.img: the known history of generations 11 to 14
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sandbox_db():
    with scratch_dir("test_timeline_sandbox_") as directory:
        build_catalog(SANDBOX, directory / "evidence.db", full_sweep=True)
        yield directory / "evidence.db"


def test_sandbox_inode_257_is_two_files_each_created_and_deleted(sandbox_db):
    conn = db.open_readonly(sandbox_db)
    events = [e for e in Timeline(conn).events(5) if e["objectid"] == 257]
    conn.close()
    told = [(e["event"], e["path"], e["created"]) for e in events]
    first, second = sorted({e["created"] for e in events})
    assert told == [
        ("create", "target_file.txt", first), ("delete", "target_file.txt", first),
        ("create", "large_target.txt", second), ("delete", "large_target.txt", second),
    ]  # fmt: skip
    create_a, delete_a, create_b, delete_b = events
    assert (create_a["size"], create_b["size"]) == (31, 5 * 1024 * 1024)
    assert create_b["reused_inode_number"] and not create_a["reused_inode_number"]
    # each event lies between two states the superblock names, in generation order
    assert create_a["first_seen"]["source"] == "backup:11"
    assert delete_a["between"] == ["backup:11", "backup:12"]
    assert create_b["first_seen"]["source"] == "backup:13"
    assert delete_b["between"] == ["backup:13", "current"]
    assert delete_a["generations"] == [11, 12] and delete_b["generations"] == [13, 14]


def test_the_command_renders_that_history_and_its_json_has_the_documented_keys(sandbox_db, capsys):
    assert main(["timeline", str(sandbox_db)]) == 0
    text = capsys.readouterr().out
    assert "inode 257 created in generation" in text and text.count("delete") == 2
    assert "the inode number was used before by another file" in text
    assert main(["timeline", str(sandbox_db), "--inode", "257", "--json", "--uncommitted"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {r["objectid"] for r in records} == {257}
    assert any(r["uncommitted_only"] for r in records)  # the size-0 versions of large_target.txt
    readme = (REPO_ROOT / "README.md").read_text()
    section = readme.split("### `btrfska timeline`", 1)[1].split("\n### ", 1)[0]
    keys = {key for record in records for key in record}
    assert {key for key in keys if f"`{key}`" not in section} == set()
    for kind in ("create", "modify", "rename", "move", "link", "unlink", "attr", "touch",
                 "delete", "not_seen", "never_committed", "subvolume_deleted"):  # fmt: skip
        assert f"`{kind}`" in section
    assert main(["timeline", str(sandbox_db.with_name("absent.db"))]) == 1


# ---------------------------------------------------------------------------
# m4_deep: against the hashes its log holds
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deep():
    if not DEEP.exists():
        pytest.skip("corpus image not built (./setup.sh)")
    with scratch_dir("test_timeline_deep_") as directory:
        build_catalog(DEEP, directory / "evidence.db", full_sweep=True)
        recover(DEEP, directory / "evidence.db", directory / "out", roots=("all",))
        conn = db.open_readonly(directory / "evidence.db")
        yield conn
        conn.close()


def test_every_recoverable_victim_has_one_create_one_delete_and_its_logged_hash(deep):
    log = DEEP.with_suffix(".log").read_text()
    truth = dict(re.findall(r"=== VICTIM (\S+) ([0-9a-f]{64})", log))
    known = hashes(deep)
    events = list(Timeline(deep, tree_id=5).events(5))
    found = 0
    for name, digest in truth.items():
        mine = [e for e in events if e["path"] == f"victims/{name}"]
        if not mine:
            continue  # the oldest victims: no state that held them survives (EXP-006)
        found += 1
        told = [e["event"] for e in mine if e["event"] not in ("touch",)]
        assert told == ["create", "delete"], (name, told)
        create, delete = mine[0], mine[-1]
        key = (5, create["objectid"], create["created"], create["extent_signature"])
        assert known[key] == digest
        assert create["transaction"] == create["created"] <= delete["generations"][0]
        assert delete["generations"][0] < delete["generations"][1]
    assert found >= len(truth) // 2


def test_flash_files_are_never_committed_and_belong_to_the_tree_their_log_root_names(deep):
    log = DEEP.with_suffix(".log").read_text()
    flash = set(re.findall(r"=== FLASH (\S+) ", log))
    committed = {e["path"] for e in Timeline(deep, tree_id=5).events(5)}
    assert not flash & committed
    events = [
        e for e in Timeline(deep, tree_id=5, uncommitted=True).events(5) if e["path"] in flash
    ]
    assert {e["path"] for e in events} == flash
    for name in flash:
        assert [e["event"] for e in events if e["path"] == name] == ["create", "never_committed"]
    assert all(e["first_seen"]["source"].startswith("log:") for e in events)


def test_names_change_only_where_the_scenario_changed_them(deep):
    """EXP-009 found one `link` per build that the scenario never did, on `pad/p2`, from versions
    seen through walks with gaps. The scenario renames within one directory and makes no hard
    link, so the only other name change is the unlink of the file unlinked while open."""
    log = DEEP.with_suffix(".log").read_text()
    unlinked = {int(n) for n in re.findall(r"=== EVENT unlink (\d+) ", log)}
    if not unlinked:
        pytest.skip("m4_deep was built before its scenario logged events: rebuild it")
    events = list(Timeline(deep, tree_id=5, uncommitted=True).events(5))
    changed = [(e["event"], e["objectid"], e["path"]) for e in events
               if e["event"] in ("link", "unlink", "move")]  # fmt: skip
    assert [c for c in changed if c[0] != "unlink" or c[1] not in unlinked] == []


def test_events_agree_with_the_generations_the_log_holds(deep):
    """The scenario logs every create, rename and delete with its inode and the transaction it
    happened in (EXP-009). A create carries that transaction exactly; a rename, a delete and a
    `never_committed` lie between their bounding states. EXP-009 found a `never_committed` for a
    file committed in a generation whose state survived only with gaps: that is `not_seen` now."""
    log = DEEP.with_suffix(".log").read_text()
    logged = re.findall(r"=== EVENT (create|rename|delete) (\d+) (\d+) (\S+)(?: (\S+))?", log)
    if not logged:
        pytest.skip("m4_deep was built before its scenario logged events: rebuild it")
    created = {int(n): int(g) for kind, n, g, _, _ in logged if kind == "create"}
    when = {(kind, int(n)): int(g) for kind, n, g, _, _ in logged}
    renamed = {int(n): new.rsplit("/", 1)[-1] for _, n, _, _, new in logged if new}
    events = [e for e in Timeline(deep, tree_id=5, uncommitted=True).events(5)
              if e["objectid"] in created]  # fmt: skip
    assert {"create", "rename", "delete"} <= {e["event"] for e in events}
    for event in events:
        assert event["created"] == created[event["objectid"]]
        if event["event"] in ("rename", "delete", "never_committed"):
            low, high = event["generations"]
            kind = "rename" if event["event"] == "rename" else "delete"
            assert low <= when[kind, event["objectid"]] <= high, event
        if event["event"] == "rename":
            assert event["to"]["name"] == renamed[event["objectid"]]
    found = {e["objectid"] for e in events if e["event"] == "create"}
    assert len(found) >= len(created) // 2
