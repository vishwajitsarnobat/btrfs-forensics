"""Root sets (current and backup), tree resolution and subvolume enumeration."""

import json
from pathlib import Path

import pytest

from btrfska.substrate import ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.roots import (
    RootNotFound,
    find_root_set,
    parse_root_spec,
    resolve_tree,
    root_sets,
    subvolumes,
)
from btrfska.substrate.tree import walk
from tests.helpers import make_block

GROUND_TRUTH = json.loads((Path(__file__).parent / "ground_truth" / "sandbox.json").read_text())


def test_parse_root_spec():
    assert parse_root_spec("current") == ("current", None)
    assert parse_root_spec("backup:12") == ("backup", 12)
    assert parse_root_spec("bytenr:30720000") == ("bytenr", 30720000)
    for bad in ("backup", "backup:x", "bytenr:-1", "slot:1", ""):
        with pytest.raises(ValueError, match="current, backup:GEN or bytenr:N"):
            parse_root_spec(bad)


def test_root_sets_are_backups_by_generation_then_current():
    fields = sb.parse_copy(
        make_block(generation=9, backups=[(0, 8), (1, 9), (2, 6), (3, 7)]), 0
    ).fields
    sets = root_sets(fields)
    assert [(s.source, s.generation, s.slot) for s in sets] == [
        ("backup:6", 6, 2),
        ("backup:7", 7, 3),
        ("backup:8", 8, 0),
        ("backup:9", 9, 1),
        ("current", 9, None),
    ]
    current = sets[-1].trees["root"]
    assert (current.bytenr, current.generation, current.via) == (fields["root"], 9, "superblock")
    assert set(sets[0].trees) == {"root", "chunk", "extent", "fs", "dev", "csum"}
    assert set(sets[-1].trees) == {"root", "chunk"}
    assert sets[0].trees["root"].via == "backup slot 2"
    assert find_root_set(fields, "backup:7").slot == 3
    with pytest.raises(
        RootNotFound, match=r"no backup root with generation 99 \(have 6, 7, 8, 9\)"
    ):
        find_root_set(fields, "backup:99")


@pytest.fixture(scope="module")
def sandbox_fs(sandbox_img):
    with open_image(sandbox_img) as img:
        yield open_filesystem(img)


@pytest.mark.sandbox
def test_sandbox_backup_trees_resolve_through_slots_and_root_items_alike(sandbox_fs):
    fs = sandbox_fs
    slots = {r["slot"]: r for r in GROUND_TRUTH["backup_roots_by_slot"]}
    for gen in (11, 12, 13, 14):
        root_set = find_root_set(fs.fields, f"backup:{gen}")
        slot = slots[root_set.slot]
        for name, tree_id in (("fs", 5), ("extent", 2), ("csum", 7)):
            via_slot = resolve_tree(fs.reader, root_set, name)
            via_item = resolve_tree(fs.reader, root_set, tree_id)
            assert via_slot.bytenr == slot[f"{name}_root"] == via_item.bytenr, (gen, name)
            assert via_slot.generation == slot[f"{name}_root_gen"] == via_item.generation
            assert via_slot.level == via_item.level == 0
            assert via_slot.via == f"backup slot {root_set.slot}"
            assert via_item.via.startswith(f"ROOT_ITEM ({tree_id} 132 0) in root tree ")
        assert resolve_tree(fs.reader, root_set, "root").bytenr == slot["tree_root"]
        assert resolve_tree(fs.reader, root_set, "chunk").bytenr == slot["chunk_root"]


@pytest.mark.sandbox
def test_sandbox_current_trees_resolve_through_the_root_tree(sandbox_fs):
    fs = sandbox_fs
    current = find_root_set(fs.fields, "current")
    fs_tree = resolve_tree(fs.reader, current, "fs")
    assert (fs_tree.bytenr, fs_tree.generation, fs_tree.tree_id) == (30703616, 14, 5)
    bgt = resolve_tree(fs.reader, current, ondisk.BLOCK_GROUP_TREE_OBJECTID)
    assert (bgt.bytenr, bgt.generation) == (30687232, 14)
    with pytest.raises(RootNotFound, match="no ROOT_ITEM for tree 256"):
        resolve_tree(fs.reader, current, 256)


@pytest.mark.sandbox
@pytest.mark.parametrize("source", ["backup:11", "backup:12", "backup:13", "backup:14", "current"])
def test_sandbox_has_only_the_top_level_subvolume(sandbox_fs, source):
    root_set = find_root_set(sandbox_fs.fields, source)
    found, problems = subvolumes(sandbox_fs.reader, root_set)
    assert problems == ()
    assert [(s.id, s.name, s.parent, s.problems) for s in found] == [(5, None, None, ())]
    assert found[0].root.via.startswith("ROOT_ITEM (5 132 0) in root tree ")


@pytest.mark.sandbox
@pytest.mark.parametrize("source", ["backup:11", "backup:12", "backup:13", "backup:14", "current"])
def test_sandbox_every_tree_of_every_root_set_walks_valid(sandbox_fs, source):
    """Anchored provenance: superblock -> root set -> root tree -> ROOT_ITEM -> every node valid."""
    fs = sandbox_fs
    root_set = find_root_set(fs.fields, source)
    roots = [resolve_tree(fs.reader, root_set, "root"), resolve_tree(fs.reader, root_set, "chunk")]
    for visit in walk(fs.reader, roots[0].bytenr, roots[0].expect()):
        for item in visit.node.items if visit.node.level == 0 else ():
            if item.key.type == ondisk.ITEM_KEYS["ROOT_ITEM"]:
                roots.append(resolve_tree(fs.reader, root_set, item.key.objectid))
    assert len(roots) == 2 + 8
    for tree_root in roots:
        visits = list(walk(fs.reader, tree_root.bytenr, tree_root.expect()))
        assert visits, tree_root
        for visit in visits:
            assert visit.node.valid and visit.problems == (), (tree_root, visit.node.problems)
            assert all(copy.ok for copy in visit.node.copies)
