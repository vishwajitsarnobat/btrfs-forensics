"""Superblock copies, best-copy selection, backup roots and the feature gate (synthetic input)."""

import random

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.image import open_image
from tests.helpers import SANDBOX_INCOMPAT, make_block, scratch_dir, write_sparse_image


# ---------------------------------------------------------------------------
# One copy
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("csum_type", sorted(ondisk.CSUM_TYPES))
def test_valid_copy_for_every_csum_type(csum_type):
    copy = sb.parse_copy(make_block(csum_type=csum_type), mirror=0)
    assert copy.valid
    assert copy.problems == ()
    assert copy.fields["generation"] == 7
    assert copy.fields["csum_type"] == csum_type


def test_zeroed_copy_is_invalid_with_reasons():
    copy = sb.parse_copy(bytes(ondisk.SUPER_INFO_SIZE), mirror=0)
    assert not copy.valid
    assert not copy.magic_ok and not copy.csum_ok and not copy.bytenr_ok
    assert "magic mismatch" in copy.problems
    assert "csum mismatch" in copy.problems


def test_copy_at_the_wrong_offset_fails_the_bytenr_check():
    copy = sb.parse_copy(make_block(mirror=0), mirror=1)
    assert copy.magic_ok and copy.csum_ok and not copy.bytenr_ok
    assert copy.problems == (f"bytenr 65536 != expected {64 * 1024**2}",)


def test_unknown_csum_type_cannot_validate():
    copy = sb.parse_copy(make_block(csum_type=9), mirror=0)
    assert copy.magic_ok and not copy.csum_ok and not copy.valid
    assert "unknown csum_type 9" in copy.problems


def test_flipped_byte_breaks_csum():
    block = bytearray(make_block(csum_type=csum.XXHASH))
    block[0x100] ^= 0x01
    copy = sb.parse_copy(bytes(block), mirror=0)
    assert copy.magic_ok and not copy.csum_ok
    assert copy.problems == ("csum mismatch",)


# ---------------------------------------------------------------------------
# Geometry sanity (kernel v7.0 disk-io.c:2360-2580 btrfs_validate_super)
# ---------------------------------------------------------------------------
def test_helper_block_has_sane_geometry():
    assert sb.parse_copy(make_block(), 0).geometry_ok


# (field overrides, expected problem). Each one invalidates the copy.
INVALIDATING = [
    pytest.param({"sectorsize": 0}, "invalid sectorsize 0", id="sectorsize-0"),
    pytest.param({"sectorsize": 2048}, "invalid sectorsize 2048", id="sectorsize-below-min"),
    pytest.param({"sectorsize": 6000}, "invalid sectorsize 6000", id="sectorsize-not-pow2"),
    pytest.param(
        {"sectorsize": 131072, "nodesize": 131072},
        "invalid sectorsize 131072",
        id="sectorsize-above-max",
    ),
    pytest.param({"nodesize": 0}, "invalid nodesize 0", id="nodesize-0"),
    pytest.param({"nodesize": 20000}, "invalid nodesize 20000", id="nodesize-not-pow2"),
    pytest.param(
        {"sectorsize": 8192, "nodesize": 4096, "root": 0x100000},
        "invalid nodesize 4096",
        id="nodesize-below-sectorsize",
    ),
    pytest.param({"nodesize": 131072}, "invalid nodesize 131072", id="nodesize-above-max"),
    pytest.param({"root_level": 8}, "root_level 8 >= 8", id="root-level"),
    pytest.param({"chunk_root_level": 9}, "chunk_root_level 9 >= 8", id="chunk-root-level"),
    pytest.param({"log_root_level": 255}, "log_root_level 255 >= 8", id="log-root-level"),
    pytest.param(
        {"sys_chunk_array_size": 2049},
        "sys_chunk_array_size 2049 > 2048",
        id="sys-array-too-big",
    ),
    pytest.param(
        {"sys_chunk_array_size": 96}, "sys_chunk_array_size 96 < 97", id="sys-array-too-small"
    ),
]


@pytest.mark.parametrize(("overrides", "problem"), INVALIDATING)
def test_geometry_violation_invalidates_the_copy(overrides, problem):
    copy = sb.parse_copy(make_block(**overrides), mirror=0)
    assert copy.magic_ok and copy.bytenr_ok and copy.csum_ok
    assert not copy.geometry_ok
    assert not copy.valid
    assert problem in copy.problems


# Recorded as a problem, but the copy stays valid (see the module docstring for why).
WARNING_ONLY = [
    pytest.param({"root": 0x100001}, "root 1048577 not aligned to sectorsize 4096", id="root"),
    pytest.param(
        {"chunk_root": 0x200200}, "chunk_root 2097664 not aligned to sectorsize 4096", id="chunk"
    ),
    pytest.param({"log_root": 12345}, "log_root 12345 not aligned to sectorsize 4096", id="log"),
    pytest.param({"num_devices": 0}, "num_devices is 0", id="no-devices"),
    pytest.param(
        {"num_devices": (1 << 31) + 1}, "suspicious num_devices 2147483649", id="many-devices"
    ),
]


@pytest.mark.parametrize(("overrides", "problem"), WARNING_ONLY)
def test_geometry_warning_keeps_the_copy_valid(overrides, problem):
    copy = sb.parse_copy(make_block(**overrides), mirror=0)
    assert copy.valid and copy.geometry_ok
    assert copy.problems == (problem,)


def test_alignment_is_not_judged_against_an_invalid_sectorsize():
    copy = sb.parse_copy(make_block(sectorsize=6000), mirror=0)
    assert copy.problems == ("invalid sectorsize 6000",)


def test_geometry_is_not_judged_without_the_magic():
    copy = sb.parse_copy(make_block(magic=0, sectorsize=0), mirror=0)
    assert copy.problems == ("magic mismatch",)


def test_unknown_csum_type_is_rejected_like_the_kernel():
    # disk-io.c:3345-3351 open_ctree(): btrfs_supported_super_csum() before the csum check.
    copy = sb.parse_copy(make_block(csum_type=4), mirror=0)
    assert not copy.valid
    assert copy.problems == ("unknown csum_type 4",)


def test_parse_copy_never_raises_on_hostile_input():
    """Property-style: random blocks and mutated valid blocks parse to a (usually invalid) copy."""
    rng = random.Random(20260915)
    valid = make_block(csum_type=csum.SHA256)
    for _ in range(300):
        assert not sb.parse_copy(rng.randbytes(ondisk.SUPER_INFO_SIZE), mirror=0).valid
        mutated = bytearray(valid)
        for _ in range(rng.randint(1, 8)):
            mutated[rng.randrange(ondisk.CSUM_SIZE, len(mutated))] = rng.randrange(256)
        copy = sb.parse_copy(bytes(mutated), mirror=0)
        assert copy.valid is (bytes(mutated) == valid)
        sb.backup_roots(copy.fields)
        sb.gate(copy.fields)


# ---------------------------------------------------------------------------
# Selection across copies
# ---------------------------------------------------------------------------
def test_identical_copies_select_primary_without_disagreement():
    selection = sb.select([sb.parse_copy(make_block(mirror=m), m) for m in (0, 1)])
    assert selection.selected.mirror == 0
    assert selection.disagreements == []


def test_damaged_primary_selects_mirror_1_and_reports_it():
    copies = [sb.parse_copy(bytes(4096), 0), sb.parse_copy(make_block(mirror=1), 1)]
    selection = sb.select(copies)
    assert selection.selected.mirror == 1
    assert selection.disagreements == ["mirror 0 invalid: magic mismatch, csum mismatch"]


def test_highest_generation_wins_among_valid_copies():
    copies = [
        sb.parse_copy(make_block(mirror=0, generation=5), 0),
        sb.parse_copy(make_block(mirror=1, generation=6), 1),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 1
    assert selection.foreign == []
    # The other differing fields are always listed, not only the generation.
    assert selection.disagreements == [
        "mirror 0 generation 5 != selected generation 6, differs in: root"
    ]


FSID_A = bytes.fromhex("aa" * 16)
FSID_B = bytes.fromhex("bb" * 16)
UUID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
UUID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
METADATA_UUID = ondisk.INCOMPAT["METADATA_UUID"]


def test_foreign_mirror_with_a_higher_generation_is_not_selected():
    # btrfs-progs v7.1 kernel-shared/disk-io.c:2037-2056: copies whose fsid differs from the
    # first accepted copy "contain data of different filesystems" and are skipped.
    copies = [
        sb.parse_copy(make_block(0, generation=5, fsid=FSID_A), 0),
        sb.parse_copy(make_block(1, generation=900, fsid=FSID_B, csum_type=csum.SHA256), 1),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 0
    assert selection.foreign == [copies[1]]
    assert selection.disagreements == [
        f"mirror 1 foreign superblock at {ondisk.sb_offset(1)} (fsid {UUID_B}, generation 900)"
    ]


def test_anchor_is_the_lowest_offset_valid_copy():
    copies = [
        sb.parse_copy(bytes(4096), 0),
        sb.parse_copy(make_block(1, generation=5, fsid=FSID_A), 1),
        sb.parse_copy(make_block(2, generation=6, fsid=FSID_B), 2),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 1
    assert selection.foreign == [copies[2]]
    assert selection.disagreements == [
        "mirror 0 invalid: magic mismatch, csum mismatch",
        f"mirror 2 foreign superblock at {ondisk.sb_offset(2)} (fsid {UUID_B}, generation 6)",
    ]


def test_metadata_uuid_anchors_when_the_anchor_sets_the_feature():
    incompat = SANDBOX_INCOMPAT | METADATA_UUID
    copies = [
        sb.parse_copy(make_block(0, incompat=incompat, fsid=FSID_A, metadata_uuid=FSID_A), 0),
        sb.parse_copy(
            make_block(1, generation=8, incompat=incompat, fsid=FSID_A, metadata_uuid=FSID_B), 1
        ),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 0
    assert selection.foreign == [copies[1]]
    assert selection.disagreements == [
        f"mirror 1 foreign superblock at {ondisk.sb_offset(1)} "
        f"(fsid {UUID_A}, metadata_uuid {UUID_B}, generation 8)"
    ]


def test_metadata_uuid_is_ignored_when_the_anchor_lacks_the_feature():
    # progs compares metadata_uuid only if the first accepted copy has METADATA_UUID set.
    copies = [
        sb.parse_copy(make_block(0, fsid=FSID_A), 0),
        sb.parse_copy(make_block(1, fsid=FSID_A, metadata_uuid=FSID_B), 1),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 0
    assert selection.foreign == []
    assert selection.disagreements == ["mirror 1 differs from mirror 0 in: metadata_uuid"]


def test_tree_fsid_follows_the_metadata_uuid_feature():
    # volumes.c:734-740 btrfs_sb_fsid_ptr(): the UUID stamped into tree block headers.
    plain = sb.parse_copy(make_block(fsid=FSID_A, metadata_uuid=FSID_B), 0).fields
    assert sb.tree_fsid(plain) == FSID_A
    flagged = make_block(
        incompat=SANDBOX_INCOMPAT | METADATA_UUID, fsid=FSID_A, metadata_uuid=FSID_B
    )
    assert sb.tree_fsid(sb.parse_copy(flagged, 0).fields) == FSID_B


def test_same_generation_different_content_is_reported():
    copies = [
        sb.parse_copy(make_block(mirror=0), 0),
        sb.parse_copy(make_block(mirror=1, incompat=SANDBOX_INCOMPAT | 1 << 40), 1),
    ]
    selection = sb.select(copies)
    assert selection.selected.mirror == 0
    assert selection.disagreements == ["mirror 1 differs from mirror 0 in: incompat_flags"]


def test_no_valid_copy_selects_nothing():
    selection = sb.select([sb.parse_copy(bytes(4096), 0)])
    assert selection.selected is None
    assert selection.disagreements == ["mirror 0 invalid: magic mismatch, csum mismatch"]


# ---------------------------------------------------------------------------
# Reading copies from an image
# ---------------------------------------------------------------------------
@pytest.fixture
def scratch():
    with scratch_dir("test_superblock_") as path:
        yield path


def test_read_copies_lists_every_mirror_slot(scratch):
    size = 64 * 1024**2 + 8192
    image = write_sparse_image(
        scratch / "two_copies.img",
        size,
        {ondisk.sb_offset(0): make_block(0), ondisk.sb_offset(1): make_block(1)},
    )
    with open_image(image) as img:
        copies = sb.read_copies(img)
    assert [c.mirror for c in copies] == [0, 1, 2]
    assert [c.present for c in copies] == [True, True, False]
    assert [c.offset for c in copies] == [ondisk.sb_offset(m) for m in range(3)]
    assert all(c.valid for c in copies[:2])


def test_copy_ending_at_image_end_is_not_used(scratch):
    # volumes.c:1356 btrfs_read_disk_super(): bytenr + BTRFS_SUPER_INFO_SIZE >= size -> -EINVAL
    size = ondisk.sb_offset(1) + ondisk.SUPER_INFO_SIZE
    image = write_sparse_image(
        scratch / "edge.img",
        size,
        {ondisk.sb_offset(0): make_block(0), ondisk.sb_offset(1): make_block(1)},
    )
    with open_image(image) as img:
        assert [c.present for c in sb.read_copies(img)] == [True, False, False]


@pytest.mark.parametrize(
    "size", [1, ondisk.SUPER_INFO_OFFSET, ondisk.SUPER_INFO_OFFSET + ondisk.SUPER_INFO_SIZE - 1]
)
def test_image_too_small_for_the_primary_has_no_copies(scratch, size):
    # A truncated acquisition: even the primary copy (64 KiB + 4096) does not fit.
    image = write_sparse_image(scratch / "truncated.img", size, {})
    with open(image, "r+b") as f:
        f.write(make_block(0)[: max(0, size - 1)])
    with open_image(image) as img:
        selection = sb.read_superblock(img)
    assert [c.present for c in selection.copies] == [False, False, False]
    assert selection.selected is None
    assert selection.disagreements == []


def test_read_superblock_returns_selection(scratch):
    blocks = {ondisk.sb_offset(0): make_block(0, generation=3)}
    image = write_sparse_image(scratch / "one.img", 1 << 24, blocks)
    with open_image(image) as img:
        selection = sb.read_superblock(img)
    assert selection.selected.fields["generation"] == 3


# ---------------------------------------------------------------------------
# Backup roots
# ---------------------------------------------------------------------------
def test_backup_roots_sorted_by_generation_keeping_slot():
    fields = sb.parse_copy(make_block(backups=[(0, 13), (1, 14), (2, 11), (3, 12)]), 0).fields
    roots = sb.backup_roots(fields)
    assert [(r["tree_root_gen"], r["slot"]) for r in roots] == [(11, 2), (12, 3), (13, 0), (14, 1)]
    assert roots[0]["tree_root"] == 0x200000 + 11
    assert set(ondisk.ROOT_BACKUP.fields) <= set(roots[0])


# ---------------------------------------------------------------------------
# Feature gate
# ---------------------------------------------------------------------------
def fields_with(incompat=SANDBOX_INCOMPAT, compat_ro=0):
    return sb.parse_copy(make_block(incompat=incompat, compat_ro=compat_ro), 0).fields


def test_stable_features_pass_the_gate():
    verdict = sb.gate(fields_with(ondisk.INCOMPAT_SUPP_STABLE))
    assert verdict.status == "OK"
    assert not verdict.refused
    assert verdict.report_lines() == []


@pytest.mark.parametrize("name", ["EXTENT_TREE_V2", "RAID_STRIPE_TREE", "REMAP_TREE"])
def test_experimental_features_are_refused(name):
    verdict = sb.gate(fields_with(SANDBOX_INCOMPAT | ondisk.INCOMPAT[name]))
    assert verdict.refused
    assert verdict.status == "REFUSED"
    assert verdict.report_lines() == [f"UNSUPPORTED_INCOMPAT {name}"]


@pytest.mark.parametrize("bit", [15, 18, 40, 63])
def test_unknown_incompat_bits_are_refused(bit):
    verdict = sb.gate(fields_with(SANDBOX_INCOMPAT | 1 << bit))
    assert verdict.refused
    assert verdict.report_lines() == [f"UNSUPPORTED_INCOMPAT UNKNOWN_BIT_{bit}"]


def test_allow_unsupported_overrides_but_still_reports():
    fields = fields_with(SANDBOX_INCOMPAT | ondisk.INCOMPAT["REMAP_TREE"] | 1 << 40)
    verdict = sb.gate(fields, allow_unsupported=True)
    assert not verdict.refused
    assert verdict.status == "OVERRIDDEN"
    assert verdict.report_lines() == [
        "UNSUPPORTED_INCOMPAT REMAP_TREE",
        "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40",
    ]


def test_block_group_tree_and_unknown_compat_ro_do_not_refuse():
    verdict = sb.gate(fields_with(compat_ro=0xB | 1 << 20))
    assert verdict.block_group_tree
    assert verdict.unknown_compat_ro == ("UNKNOWN_BIT_20",)
    assert not verdict.refused
    assert not sb.gate(fields_with(compat_ro=0x3)).block_group_tree


def test_flag_names():
    assert ondisk.flag_names(0x361, ondisk.INCOMPAT) == [
        "MIXED_BACKREF",
        "BIG_METADATA",
        "EXTENDED_IREF",
        "SKINNY_METADATA",
        "NO_HOLES",
    ]
    assert ondisk.flag_names(1 << 15 | 1, ondisk.INCOMPAT) == ["MIXED_BACKREF", "UNKNOWN_BIT_15"]
