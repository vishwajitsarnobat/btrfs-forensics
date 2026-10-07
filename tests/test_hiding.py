"""The hiding detector's rules on synthetic input (plan.md M6d): each rule fires on the bytes it
is about and stays quiet on what mkfs.btrfs and the kernel write; hostile input never crashes.
The corpus and third-party images are in test_hiding_images.py."""

import json
import struct
from types import SimpleNamespace

import pytest

from btrfska.cli import main
from btrfska.hiding import areas, trees
from btrfska.hiding.detect import TECHNIQUES
from btrfska.hiding.findings import MAX_RUNS, Finding, nonzero_runs, preview
from btrfska.substrate import csum, ondisk, superblock
from btrfska.substrate.image import open_image
from btrfska.substrate.node import parse_items
from tests.helpers import REPO_ROOT, make_block, make_node, scratch_dir, write_sparse_image

SB = ondisk.SUPERBLOCK
INODE = ondisk.INODE_ITEM
MIB = 1 << 20
SIZE = 72 * MIB  # holds mirrors 0 and 1
# The keys README.md documents ("`btrfska hiding`").
FINDING_KEYS = {
    "record", "unsupported_format", "technique", "physical", "length", "nonzero", "where",
    "evidence", "preview", "text", "detail",
}  # fmt: skip
SUMMARY_KEYS = {
    "record", "unsupported_format", "techniques", "findings", "by_technique", "superblock",
    "trees", "device",
}  # fmt: skip
SUPERBLOCK_SUMMARY_KEYS = {"copies", "slots_without_superblock", "stale_array_tails"}
TREE_SUMMARY_KEYS = {
    "trees", "blocks", "copies", "nonzero_slack", "stale_slack", "stale_slack_blocks", "inodes",
    "log_inode_reserved", "files_checked", "subvolumes", "problems",
}  # fmt: skip
DEVICE_SUMMARY_KEYS = {
    "devid", "total_bytes", "last_extent_end", "explained_bytes", "history", "extents",
}  # fmt: skip


def dev_item(total: int, devid: int = 1) -> bytes:
    return struct.pack("<QQ", devid, total).ljust(ondisk.DEV_ITEM.size, b"\0")


def superblock_image(d, name: str, edit=None, size: int = SIZE, **overrides):
    """An image with mirrors 0 and 1 of one superblock, `edit(block)` applied to both before
    their checksums are computed."""
    blocks = {}
    for mirror in (0, 1):
        block = bytearray(make_block(mirror, dev_item=dev_item(size), **overrides))
        if edit:
            edit(block)
        csum_type = struct.unpack_from("<H", block, SB.offset("csum_type"))[0]
        block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
        block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
        blocks[ondisk.sb_offset(mirror)] = bytes(block)
    return write_sparse_image(d / name, size, blocks)


def sb_findings(path):
    """The superblock findings, with the device size of mirror 0 (valid or not)."""
    with open_image(path) as img:
        fields = SB.unpack_from(img.mmap[ondisk.SUPER_INFO_OFFSET :][: ondisk.SUPER_INFO_SIZE])
        return areas.superblock_findings(img, fields)


# ---------------------------------------------------------------------------
# Superblock copies
# ---------------------------------------------------------------------------
def test_a_clean_superblock_has_no_finding():
    with scratch_dir("test_hiding_") as d:
        found, checked = sb_findings(superblock_image(d, "clean.img"))
    assert found == [] and checked["copies"] == 2


@pytest.mark.parametrize(
    ("start", "technique", "field"),
    [
        (0x264, "superblock_reserved", "reserved"),
        (0x32A, "superblock_reserved", "reserved"),
        (0xDCB, "superblock_padding", "padding"),
        (0xFFF, "superblock_padding", "padding"),
    ],
)
def test_reserved_and_padding_bytes_are_reported_in_every_copy(start, technique, field):
    def edit(block):
        block[start] = 0x41

    with scratch_dir("test_hiding_") as d:
        found, _ = sb_findings(superblock_image(d, "planted.img", edit))
    assert [(f.technique, f.detail["field"], f.detail["mirror"]) for f in found] == [
        (technique, field, 0), (technique, field, 1)
    ]  # fmt: skip
    assert {f.detail["first_nonzero"] - ondisk.sb_offset(f.detail["mirror"]) for f in found} == {
        start
    }


@pytest.mark.parametrize(
    ("field", "flag"),
    [("metadata_uuid", "METADATA_UUID"), ("nr_global_roots", "EXTENT_TREE_V2"),
     ("remap_root", "REMAP_TREE"), ("remap_root_level", "REMAP_TREE")],
)  # fmt: skip
def test_feature_gated_fields_are_spare_only_while_their_flag_is_clear(field, flag):
    """research.md §10.13: the reserved range is a function of the feature flags."""
    offset = SB.offset(field)

    def edit(block):
        block[offset] = 0x7F

    with scratch_dir("test_hiding_") as d:
        without, _ = sb_findings(superblock_image(d, "without.img", edit))
        incompat = make_block()[SB.offset("incompat_flags") :][:8]
        flags = int.from_bytes(incompat, "little") | ondisk.INCOMPAT[flag]
        with_flag, _ = sb_findings(superblock_image(d, "with.img", edit, incompat=flags))
    assert {f.detail["field"] for f in without} == {field if field != "remap_root_level" else
                                                    "remap_root"}  # fmt: skip
    assert len(without) == 2 and with_flag == []


def test_a_copy_whose_checksum_was_not_recomputed_is_still_examined():
    with scratch_dir("test_hiding_") as d:
        path = superblock_image(d, "stale.img")
        data = bytearray(path.read_bytes()[: ondisk.sb_offset(1) + 4096])
        offset = ondisk.sb_offset(1) + 0x300
        with open(path, "r+b") as f:
            f.seek(offset)
            f.write(b"X")
        found, _ = sb_findings(path)
    assert [(f.technique, f.detail["mirror"], f.detail["csum_ok"]) for f in found] == [
        ("superblock_reserved", 1, False)
    ]
    assert data  # the clean copy was read before the write


def test_an_overwritten_slot_inside_the_device_is_reported_and_a_zero_one_is_not():
    with scratch_dir("test_hiding_") as d:
        path = superblock_image(d, "slot.img")
        with open(path, "r+b") as f:
            f.seek(ondisk.sb_offset(1))
            f.write(b"HIDDEN DATA" * 372)
        found, checked = sb_findings(path)
        zeroed = superblock_image(d, "zeroed.img")
        with open(zeroed, "r+b") as f:
            f.seek(ondisk.sb_offset(1))
            f.write(bytes(4096))
        quiet, _ = sb_findings(zeroed)
    assert [f.technique for f in found] == ["superblock_slot"]
    assert found[0].physical == ondisk.sb_offset(1) and found[0].text.startswith("HIDDEN DATA")
    assert checked["slots_without_superblock"] == 1 and quiet == []


def chunk_entry(logical: int, stripes: int = 1, devid: int = 1) -> bytes:
    key = struct.pack("<QBQ", ondisk.FIRST_CHUNK_TREE_OBJECTID, ondisk.ITEM_KEYS["CHUNK_ITEM"],
                      logical)  # fmt: skip
    chunk = struct.pack(
        "<QQQQIIIHH", 8 * MIB, 2, 1 << 16, ondisk.BLOCK_GROUP_FLAGS["SYSTEM"], 4096, 4096, 4096,
        stripes, 0,
    )  # fmt: skip
    stripe = b"".join(struct.pack("<QQ16s", devid, 22 * MIB + i * 8 * MIB, bytes(16))
                      for i in range(stripes))  # fmt: skip
    return key + chunk + stripe


def test_the_two_tails_removing_a_system_chunk_leaves_are_explained():
    live = chunk_entry(22 * MIB, stripes=2)
    array = live.ljust(ondisk.SYSTEM_CHUNK_ARRAY_SIZE, b"\0")
    size = len(live)
    # The removed entry was not the last: the memmove leaves a copy of the live array's end.
    shifted = live[-97:].ljust(ondisk.SYSTEM_CHUNK_ARRAY_SIZE - size, b"\0")
    assert areas.stale_tail(array, size, shifted, 4096) == "shifted_copy"
    # It was the last: the removed entry itself stays.
    removed = chunk_entry(1 * MIB).ljust(ondisk.SYSTEM_CHUNK_ARRAY_SIZE - size, b"\0")
    assert areas.stale_tail(array, size, removed, 4096) == "removed_entries"
    assert areas.stale_tail(array, size, bytes(len(removed)), 4096) == "zero"
    garbage = b"hidden".ljust(ondisk.SYSTEM_CHUNK_ARRAY_SIZE - size, b"\0")
    assert areas.stale_tail(array, size, garbage, 4096) is None
    # A shifted copy followed by more bytes is not a shape the kernel leaves.
    worse = live[-97:] + b"x" + bytes(ondisk.SYSTEM_CHUNK_ARRAY_SIZE - size - 98)
    assert areas.stale_tail(array, size, worse, 4096) is None


def test_sys_chunk_array_slack_is_reported_with_a_forged_array_size():
    """A size past 2048 is clamped; a size of 0 leaves the whole array as slack."""
    entry = chunk_entry(22 * MIB)

    def edit(block):
        block[SB.offset("sys_chunk_array") : SB.offset("sys_chunk_array") + len(entry)] = entry
        block[SB.offset("sys_chunk_array") + 1500 : SB.offset("sys_chunk_array") + 1506] = b"secret"

    with scratch_dir("test_hiding_") as d:
        found, _ = sb_findings(
            superblock_image(d, "array.img", edit, sys_chunk_array_size=len(entry))
        )
        forged, _ = sb_findings(superblock_image(d, "forged.img", edit, sys_chunk_array_size=9999))
    assert [f.technique for f in found] == ["sys_chunk_array_slack"] * 2
    assert found[0].text.startswith("secret") and forged == []  # nothing lies past 2048


def test_backup_root_padding_is_reserved():
    at = SB.offset("super_roots") + 2 * ondisk.ROOT_BACKUP.size + 0x9F

    def edit(block):
        block[at] = 1

    with scratch_dir("test_hiding_") as d:
        found, _ = sb_findings(superblock_image(d, "backup.img", edit))
    assert [(f.detail["field"], f.detail["slot"]) for f in found] == [
        ("backup_root_padding", 2), ("backup_root_padding", 2)
    ]  # fmt: skip


# ---------------------------------------------------------------------------
# Backup-root divergence
# ---------------------------------------------------------------------------
def backups(generation: int, slots, **overrides):
    """A Selection of one copy whose backup slots hold `slots` (slot, generation), each slot's
    tree root and the other copied fields agreeing with the superblock when it is the newest."""
    block = bytearray(make_block(generation=generation, backups=slots, **overrides))
    fields = SB.unpack_from(block)
    for slot, gen in slots:
        if gen == generation:
            base = SB.offset("super_roots") + slot * ondisk.ROOT_BACKUP.size
            for name, value in (("tree_root", fields["root"]), ("chunk_root", 0),
                                ("total_bytes", fields["total_bytes"]),
                                ("bytes_used", fields["bytes_used"]),
                                ("num_devices", fields["num_devices"])):  # fmt: skip
                struct.pack_into("<Q", block, base + ondisk.ROOT_BACKUP.offset(name), value)
    block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
    block[:4] = csum.compute(csum.CRC32C, block[ondisk.CSUM_SIZE :])
    return superblock.select([superblock.parse_copy(bytes(block), 0)])


def test_a_ring_of_consecutive_slots_ending_at_the_superblock_is_not_divergence():
    assert areas.backup_root_findings(backups(9, [(0, 8), (1, 9), (2, 6), (3, 7)])) == []
    assert areas.backup_root_findings(backups(2, [(0, 1), (1, 2)])) == []  # a young filesystem


@pytest.mark.parametrize(
    ("generation", "slots", "reason"),
    [
        (9, [(0, 8), (1, 10), (2, 6), (3, 7)], "newer than the superblock"),
        (9, [(0, 8), (1, 5), (2, 6), (3, 7)], "no slot holds the superblock's generation"),
        (9, [(0, 8), (1, 9), (2, 8), (3, 7)], "two slots hold the same generation"),
        (9, [(0, 8), (1, 9), (2, 3), (3, 7)], "not consecutive"),
    ],
)
def test_backup_root_divergence(generation, slots, reason):
    found = areas.backup_root_findings(backups(generation, slots))
    assert [f.technique for f in found] == ["backup_root_divergence"]
    assert reason in found[0].evidence


def test_the_newest_slot_must_agree_with_the_superblock():
    selection = backups(9, [(0, 8), (1, 9), (2, 6), (3, 7)])
    fields = dict(selection.selected.fields, root=12345)
    copy = superblock.SuperblockCopy(0, 65536, fields, True, True, True, True)
    found = areas.backup_root_findings(superblock.Selection([copy], copy, []))
    assert "tree_root" in found[0].evidence and "disagrees" in found[0].evidence


# ---------------------------------------------------------------------------
# Boot area and device slack
# ---------------------------------------------------------------------------
def test_boot_area_bytes_are_reported_and_a_boot_signature_is_named():
    with scratch_dir("test_hiding_") as d:
        quiet = write_sparse_image(d / "zero.img", 2 * MIB, {})
        hidden = write_sparse_image(d / "hidden.img", 2 * MIB, {0x9000: b"x", 0x20000: b"y"})
        boot = write_sparse_image(d / "boot.img", 2 * MIB, {510: b"\x55\xaa"})
        with open_image(quiet) as img:
            assert areas.boot_area_findings(img) == []
        with open_image(hidden) as img:
            found = areas.boot_area_findings(img)
        with open_image(boot) as img:
            signed = areas.boot_area_findings(img)
    assert [f.detail["first_nonzero"] for f in found] == [0x9000, 0x20000]
    assert not found[0].detail["boot_signature"] and signed[0].detail["boot_signature"]
    assert "boot loader" in signed[0].evidence


def test_device_slack_past_the_last_extent_and_past_the_device_size():
    size = 80 * MIB
    with scratch_dir("test_hiding_") as d:
        path = write_sparse_image(
            d / "dev.img", size, {60 * MIB: b"past the extents", 76 * MIB: b"past the device"}
        )
        fields = {"dev_item": dev_item(72 * MIB)}
        with open_image(path) as img:
            found, checked = areas.device_slack_findings(img, fields, [(MIB, 40 * MIB)])
            explained, more = areas.device_slack_findings(
                img, fields, [(MIB, 40 * MIB)],
                lambda: [SimpleNamespace(chunks=[SimpleNamespace(
                    length=8 * MIB, type=ondisk.BLOCK_GROUP_FLAGS["DATA"], num_stripes=1,
                    sub_stripes=0, stripes=[SimpleNamespace(devid=1, offset=56 * MIB)])])],
            )  # fmt: skip
    assert [(f.detail["area"], f.detail["runs"][0][0]) for f in found] == [
        ("past_last_extent", 60 * MIB), ("past_device_size", 76 * MIB)
    ]  # fmt: skip
    assert checked["last_extent_end"] == 41 * MIB
    assert [f.detail["area"] for f in explained] == ["past_device_size"]
    assert more["explained_bytes"] == len(b"past the extents")


def test_device_slack_skips_superblock_slots_inside_the_device():
    with scratch_dir("test_hiding_") as d:
        path = superblock_image(d, "sb.img")
        with open_image(path) as img:
            fields = superblock.read_superblock(img).selected.fields
            found, _ = areas.device_slack_findings(img, fields, [(MIB, 8 * MIB)])
    assert found == []


def test_nonzero_runs_merge_and_bound_what_they_list():
    with scratch_dir("test_hiding_") as d:
        blocks = {i * 8192: b"x" for i in range(MAX_RUNS + 5)} | {4096 * 40 + 4095: b"y"}
        path = write_sparse_image(d / "runs.img", MIB, blocks)
        with open_image(path) as img:
            runs, count, more = nonzero_runs(img, 0, MIB, window=12288)
    assert len(runs) == MAX_RUNS and runs[0] == (0, 4096)
    assert count == MAX_RUNS + 6 and more == 5


# ---------------------------------------------------------------------------
# Tree rules
# ---------------------------------------------------------------------------
def inode_item(nsec=(0, 0, 0, 0), reserved=b"", mode=0o100644, size=10) -> bytes:
    data = bytearray(INODE.size)
    struct.pack_into("<QQQQQIIIIQQQ", data, 0, 7, 7, size, 4096, 0, 1, 0, 0, mode, 0, 0, 0)
    start = INODE.offset("sequence") + 8
    data[start : start + len(reserved)] = reserved
    for name, value in zip(trees.NSEC_FIELDS, nsec, strict=True):
        struct.pack_into("<I", data, INODE.offset(name), value)
    return bytes(data)


def leaf_findings(items, log=False):
    block = make_node(4 * MIB, items=items)
    node = SimpleNamespace(items=parse_items(block, len(block))[0], logical=4 * MIB)
    census = trees.Census()
    tree = SimpleNamespace(tree_id=ondisk.TREE_LOG_OBJECTID if log else 5, log=log)
    return trees._item_findings(node, 0, tree, census), census


def test_inode_reserved_bytes_are_reported_except_in_a_log_tree():
    items = [((257, 1, 0), inode_item(reserved=b"HIDDEN")), ((258, 1, 0), inode_item())]
    found, census = leaf_findings(items)
    assert [(f.technique, f.detail["inode"]) for f in found] == [("inode_reserved", 257)]
    assert found[0].text == "HIDDEN" and census.inodes == 2
    logged, census = leaf_findings(items, log=True)
    assert logged == [] and census.log_reserved == 1


@pytest.mark.parametrize(
    ("nsec", "reported"),
    [
        ((999_999_999, 0, 5, 123_456_789), False),
        ((1_000_000_000, 0, 0, 0), True),
        ((0xFFFFFFFF, 0, 0, 0), True),
        # Four different values, each printable ASCII and below 10^9: data, not time.
        (tuple(int.from_bytes(t, "little") for t in (b"ab1 ", b"cd2!", b"ef3 ", b"gh4!")), True),
        # The same printable value four times is how the kernel writes one time into all fields.
        (tuple(int.from_bytes(b"@j_7", "little") for _ in range(4)), False),
    ],
)
def test_nanosecond_rule(nsec, reported):
    found, _ = leaf_findings([((257, 1, 0), inode_item(nsec=nsec))])
    assert [f.technique for f in found] == (["timestamp_nsec"] if reported else [])


def test_a_string_item_is_reported_anywhere():
    found, _ = leaf_findings([((257, 1, 0), inode_item()), ((257, 253, 0), b"a hidden note")])
    assert [(f.technique, f.text) for f in found] == [("string_item", "a hidden note")]


def test_hostile_items_do_not_crash_the_tree_rules():
    short = inode_item()[:100]  # truncated INODE_ITEM: not examined
    found, census = leaf_findings([((257, 1, 0), short), ((258, 84, 1), b"\xff" * 7)])
    assert found == [] and census.inodes == 0
    entries = trees._odd_entries(5, SimpleNamespace(
        key=SimpleNamespace(objectid=256), data=b"\x01" * 40, offset=0), 0)  # fmt: skip
    assert entries == []


def test_copies_that_both_validate_but_differ_are_reported():
    a = make_node(4 * MIB, items=[((257, 1, 0), inode_item())], nodesize=16384)
    b = bytearray(a)
    b[16000] = 1
    img = SimpleNamespace(mmap=a + bytes(b))
    copies = [SimpleNamespace(ok=True, physical=0, mirror=1),
              SimpleNamespace(ok=True, physical=16384, mirror=2)]  # fmt: skip
    node = SimpleNamespace(copies=copies, logical=4 * MIB, generation=7, owner=5, level=0)
    ctx = SimpleNamespace(nodesize=16384, sectorsize=4096)
    found = trees._block_findings(img, node, ctx, trees.Census())
    kinds = sorted(f.technique for f in found)
    assert "copy_divergence" in kinds
    divergence = next(f for f in found if f.technique == "copy_divergence")
    assert divergence.nonzero == 1 and divergence.detail["first_difference"] == 16000


@pytest.mark.parametrize(
    ("name", "odd"),
    [
        ("﻿", True), ("a​b", True), ("snap\x07", True), ("   ", True),
        ("\udcff\udcfe", True), ("‮exe.txt", True),
        ("snapshot-weekly", False), ("café", False), ("日本語", False), (".snapshots", False),
        ("a b", False),
    ],
)  # fmt: skip
def test_odd_names(name, odd):
    assert bool(trees._odd(name)) is odd


# ---------------------------------------------------------------------------
# Findings, records, CLI
# ---------------------------------------------------------------------------
def test_preview_shows_the_bytes_from_the_first_nonzero_one():
    assert preview(b"\0\0hi\x01") == ("686901", "hi.")
    finding = Finding("pre_superblock", 0, 1, 1, "w", "e")
    assert finding.record()["record"] == "finding" and set(finding.record()) <= FINDING_KEYS


@pytest.mark.sandbox
def test_hiding_on_sandbox_is_quiet_and_follows_the_documented_schema(sandbox_img, capsys):
    assert main(["hiding", str(sandbox_img)]) == 0
    out = capsys.readouterr().out
    assert "0 findings" in out and "finding " not in out
    assert main(["hiding", "--json", str(sandbox_img)]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["record"] for r in records] == ["hiding_summary"]
    summary = records[0]
    assert set(summary) == SUMMARY_KEYS and summary["findings"] == 0
    assert set(summary["superblock"]) == SUPERBLOCK_SUMMARY_KEYS
    assert set(summary["trees"]) == TREE_SUMMARY_KEYS
    assert set(summary["device"]) == DEVICE_SUMMARY_KEYS
    assert list(summary["by_technique"]) == list(TECHNIQUES)
    # mkfs's stale slack and system-chunk tail are counted, not reported (EXP-005).
    assert summary["trees"]["stale_slack"] > 0 and summary["superblock"]["stale_array_tails"]


def test_hiding_without_a_valid_superblock_is_refused(capsys):
    with scratch_dir("test_hiding_") as d:
        path = write_sparse_image(d / "zero.img", 2 * MIB, {})
        assert main(["hiding", str(path)]) == 2
    assert "NO_VALID_SUPERBLOCK" in capsys.readouterr().err


def test_readme_documents_every_hiding_key():
    readme = (REPO_ROOT / "README.md").read_text()
    section = readme.split("### `btrfska hiding`", 1)[1].split("\n### ", 1)[0]
    keys = (
        FINDING_KEYS | SUMMARY_KEYS | SUPERBLOCK_SUMMARY_KEYS | TREE_SUMMARY_KEYS
        | DEVICE_SUMMARY_KEYS | set(TECHNIQUES) | {"finding", "hiding_summary", "--json"}
    )  # fmt: skip
    assert {key for key in keys if f"`{key}`" not in section} == set()
