"""sandbox.img ground truth (tests/ground_truth/sandbox.json, captured with btrfs-progs dump-tree).

Superblock-level facts are asserted now. The per-generation fs-tree contents
need the tree walker (plan.md M1 task 7) and are strict xfails until M1b
lands it: an unexpected pass fails the run, so M1b must remove the marker.
"""

import json
import uuid
from pathlib import Path

import pytest

from btrfska.substrate import ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.image import open_image

GROUND_TRUTH = json.loads((Path(__file__).parent / "ground_truth" / "sandbox.json").read_text())
EXPECTED_SB = GROUND_TRUTH["superblock"]

pytestmark = pytest.mark.sandbox


@pytest.fixture(scope="module")
def selection(sandbox_img):
    with open_image(sandbox_img) as img:
        return sb.read_superblock(img)


def test_ground_truth_describes_this_image():
    from conftest import SANDBOX_SHA256

    assert GROUND_TRUTH["sha256"] == SANDBOX_SHA256


def test_two_valid_copies_and_mirror_2_beyond_the_image(selection):
    copies = selection.copies
    assert [(c.mirror, c.present, c.valid) for c in copies] == [
        (0, True, True),
        (1, True, True),
        (2, False, False),
    ]
    for copy, expected in zip(copies, EXPECTED_SB["copies"], strict=False):
        assert copy.offset == expected["bytenr"]
        assert copy.fields["csum"][:4].hex() == expected["csum"]
        assert copy.fields["generation"] == expected["generation"]
    assert selection.selected.mirror == 0
    assert selection.disagreements == []


def test_superblock_fields(selection):
    fields = selection.selected.fields
    for name in (
        "generation",
        "root",
        "chunk_root",
        "chunk_root_generation",
        "total_bytes",
        "bytes_used",
        "sectorsize",
        "nodesize",
        "csum_type",
        "compat_flags",
        "compat_ro_flags",
        "incompat_flags",
        "num_devices",
    ):
        assert fields[name] == EXPECTED_SB[name], name
    assert fields["sys_chunk_array_size"] == EXPECTED_SB["sys_array_size"]
    assert str(uuid.UUID(bytes=fields["fsid"])) == EXPECTED_SB["fsid"]
    assert fields["total_bytes"] == 268435456
    assert fields["chunk_root_generation"] == 8


def test_backup_slots_hold_generations_13_14_11_12(selection):
    roots = sb.backup_roots(selection.selected.fields)
    by_slot = sorted(roots, key=lambda r: r["slot"])
    assert [r["tree_root_gen"] for r in by_slot] == [13, 14, 11, 12]
    assert [r["tree_root_gen"] for r in roots] == [11, 12, 13, 14]
    for root, expected in zip(by_slot, GROUND_TRUTH["backup_roots_by_slot"], strict=True):
        for key, value in expected.items():
            assert root[key] == value, (expected["slot"], key)


def test_all_backups_share_chunk_root_gen_8_and_total_bytes(selection):
    for root in sb.backup_roots(selection.selected.fields):
        assert root["chunk_root_gen"] == 8
        assert root["chunk_root"] == EXPECTED_SB["chunk_root"]
        assert root["total_bytes"] == 268435456


def test_newest_backup_tree_root_is_the_superblock_root(selection):
    fields = selection.selected.fields
    newest = sb.backup_roots(fields)[-1]
    assert newest["tree_root"] == fields["root"] == 30720000
    assert newest["tree_root_gen"] == fields["generation"] == 14


def test_gate_passes_and_notes_block_group_tree(selection):
    verdict = sb.gate(selection.selected.fields)
    assert verdict.status == "OK"
    assert verdict.block_group_tree
    assert ondisk.flag_names(EXPECTED_SB["compat_ro_flags"], ondisk.COMPAT_RO) == [
        "FREE_SPACE_TREE",
        "FREE_SPACE_TREE_VALID",
        "BLOCK_GROUP_TREE",
    ]


def test_fs_tree_roots_in_ground_truth_match_backup_roots(selection):
    by_gen = {r["fs_root_gen"]: r["fs_root"] for r in sb.backup_roots(selection.selected.fields)}
    for gen, state in GROUND_TRUTH["fs_tree_by_generation"].items():
        assert by_gen[int(gen)] == state["fs_root"]


@pytest.mark.xfail(strict=True, reason="tree walker lands in M1b")
@pytest.mark.parametrize("gen", ["11", "12", "13", "14"])
def test_fs_tree_contents_per_generation(sandbox_img, gen):
    """Gen 11: target_file.txt 31 B inline; gen 12: root dir only; gen 13: large_target.txt
    5 242 880 B; gen 14: root dir only. M1b replaces the import with the real walker API."""
    from btrfska.substrate.tree import fs_tree_inventory

    expected = GROUND_TRUTH["fs_tree_by_generation"][gen]
    with open_image(sandbox_img) as img:
        assert fs_tree_inventory(img, expected["fs_root"]) == expected["inodes"]
