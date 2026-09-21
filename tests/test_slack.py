"""substrate/slack.py and what the catalog stores from it (plan.md M4c).

Synthetic blocks show what the parsers do with content no honest modern image has (a leaf as a
kernel older than 4.9 left it, a hidden message). Real images show what is actually there: the
prototype's finds on `sandbox.img`, mkfs remnants, and nothing at all in kernel-written blocks.
"""

import hashlib
import json
import random
import struct
import subprocess

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import u64
from btrfska.substrate import items as parsers
from btrfska.substrate import ondisk
from btrfska.substrate.image import open_image
from btrfska.substrate.slack import OTHER, STALE, ZERO, describe, slack_range
from tests.helpers import NODESIZE, REPO_ROOT, SCENARIOS, make_node, recsum, scratch_dir

K = ondisk.ITEM_KEYS
HEADER = ondisk.HEADER.size
SECTOR = 4096
SANDBOX = REPO_ROOT / "sandbox.img"
PINNED = REPO_ROOT / "corpus" / "vm" / "pinned.sh"
GOLDEN = json.loads((REPO_ROOT / "tests/ground_truth/sandbox_legacy_archaeology.json").read_text())
FILE_TREE_TYPES = (
    "INODE_ITEM",
    "INODE_REF",
    "INODE_EXTREF",
    "DIR_ITEM",
    "DIR_INDEX",
    "EXTENT_DATA",
)


def inode_ref(name: bytes) -> bytes:
    return struct.pack(ondisk.INODE_REF.format, 2, len(name)) + name


def inline(data: bytes) -> bytes:
    return struct.pack("<QQBBHB", 7, len(data), 0, 0, 0, ondisk.FILE_EXTENT_INLINE) + data


KEPT = ((256, K["INODE_ITEM"], 0), bytes(ondisk.INODE_ITEM.size))
DELETED = [
    ((257, K["INODE_ITEM"], 0), bytes(range(160))),
    ((257, K["INODE_REF"], 256), inode_ref(b"deleted-report.txt")),
    ((257, K["EXTENT_DATA"], 0), inline(b"the content of a deleted file")),
]


def old_kernel_leaf() -> bytes:
    """A leaf as a kernel before 4.9 left it after deleting inode 257: nritems drops, the item
    headers and their data stay where they were."""
    return make_node(0x100000, items=[KEPT, *DELETED], nritems=1)


# ---------------------------------------------------------------------------
# Synthetic blocks
# ---------------------------------------------------------------------------
def test_a_block_as_the_kernel_writes_it_is_zero():
    leaf = describe(make_node(0x100000, items=[KEPT, *DELETED]), NODESIZE, SECTOR)
    node = describe(make_node(0x100000, level=1, ptrs=[((256, 1, 0), 0x200000, 7)]), NODESIZE,
                    SECTOR)  # fmt: skip
    for report in (leaf, node):
        assert (report.slack_class, report.nonzero, report.items, report.key_ptrs) == (
            ZERO, 0, (), (),
        )  # fmt: skip
    assert node.start == HEADER + 33 and node.length == NODESIZE - HEADER - 33


def test_stale_items_give_back_a_deleted_files_name_and_inline_content():
    report = describe(old_kernel_leaf(), NODESIZE, SECTOR)
    assert report.slack_class == STALE
    assert [(i.slot, i.key.objectid, i.key.type, i.data_state) for i in report.items] == [
        (1, 257, K["INODE_ITEM"], "in_slack"),
        (2, 257, K["INODE_REF"], "in_slack"),
        (3, 257, K["EXTENT_DATA"], "in_slack"),
    ]
    by_type = {i.key.type: i.data for i in report.items}
    assert parsers.inode_refs(by_type[K["INODE_REF"]])[0]["name"] == "deleted-report.txt"
    extent = by_type[K["EXTENT_DATA"]]
    assert extent[ondisk.FILE_EXTENT_INLINE_DATA_START :] == b"the content of a deleted file"
    assert by_type[K["INODE_ITEM"]] == bytes(range(160))


def test_a_stale_header_whose_data_was_reused_says_so_and_keeps_no_payload():
    """Two items were deleted, then a new one was added: it took slot 1 and the data space of
    both. The header left in slot 2 now points into live data."""
    before = make_node(0x100000, items=[KEPT, *DELETED[:2]])
    after = bytearray(make_node(0x100000, items=[KEPT, ((258, K["INODE_ITEM"], 0), bytes(170))]))
    stale = slice(HEADER + 2 * 25, HEADER + 3 * 25)
    after[stale] = before[stale]
    report = describe(recsum(after), NODESIZE, SECTOR)
    assert [(i.slot, i.data_state, i.data) for i in report.items] == [(2, "overlaps_live", None)]


def test_stale_key_pointers_beyond_nritems_in_an_internal_node():
    ptrs = [((256 + n, K["INODE_ITEM"], 0), 0x200000 + n * 0x4000, 5 + n % 2) for n in range(4)]
    block = make_node(0x100000, level=1, ptrs=ptrs, nritems=1, generation=7)
    report = describe(block, NODESIZE, SECTOR)
    assert report.slack_class == STALE and report.items == ()
    assert [(p.slot, p.key.objectid, p.blockptr, p.generation) for p in report.key_ptrs] == [
        (n, 256 + n, 0x200000 + n * 0x4000, 5 + n % 2) for n in (1, 2, 3)
    ]


def test_pointers_that_cannot_be_real_are_not_reported():
    ptrs = [
        ((256, K["INODE_ITEM"], 0), 0x200000, 7),
        ((257, K["INODE_ITEM"], 0), 0x200001, 7),  # not sector-aligned
        ((258, K["INODE_ITEM"], 0), 0x204000, 9),  # newer than the block that holds it
        ((259, K["INODE_ITEM"], 0), 0x208000, 0),  # generation 0
        ((260, 99, 0), 0x20C000, 7),  # no such key type
        ((261, K["INODE_ITEM"], 0), 0, 7),  # no address
    ]
    block = make_node(0x100000, level=1, ptrs=ptrs, nritems=1, generation=7)
    assert describe(block, NODESIZE, SECTOR).key_ptrs == ()


def test_leaf_remnants_in_an_internal_node_are_found_on_the_leaf_grid():
    """A former leaf reallocated as a node with two pointers: 66 bytes are overwritten, and the
    old item headers from slot 3 on survive where they were. 66 is no multiple of 25, so a window
    that starts at the node's slack start, as the prototype's did, reads them all misaligned."""
    names = [f"file-{n}".encode() for n in range(8)]
    leaf = make_node(0x100000, items=[((300 + n, K["INODE_REF"], 256), inode_ref(name))
                                      for n, name in enumerate(names)])  # fmt: skip
    pointers = [((256, 1, 0), 0x200000, 7), ((300, 1, 0), 0x204000, 7)]
    node = make_node(0x100000, level=1, ptrs=pointers)
    reused = bytearray(leaf)
    reused[: HEADER + 66] = node[: HEADER + 66]
    report = describe(recsum(reused), NODESIZE, SECTOR)
    assert [i.slot for i in report.items] == [3, 4, 5, 6, 7]
    assert [parsers.inode_refs(i.data)[0]["name"].encode() for i in report.items] == names[3:]
    assert (HEADER + 66 - HEADER) % 25 != 0 and report.slack_class == OTHER


def test_a_hidden_message_is_other_wherever_it_is_put():
    message = b"meet at the usual place"
    for block in (
        make_node(0x100000, items=[KEPT]),
        make_node(0x100000, level=1, ptrs=[((256, 1, 0), 0x200000, 7)]),
    ):
        start, end = slack_range(block, NODESIZE)
        for offset in (0, 64, end - start - len(message)):
            hidden = bytearray(block)
            hidden[start + offset : start + offset + len(message)] = message
            report = describe(recsum(hidden), NODESIZE, SECTOR)
            assert (report.slack_class, report.nonzero) == (OTHER, len(message) - message.count(0))
            assert report.items == () and report.key_ptrs == ()


def test_hostile_blocks_never_raise_and_nothing_points_outside_the_block():
    rng = random.Random(9)
    template = old_kernel_leaf()
    for round_ in range(1500):
        block = bytearray(rng.randbytes(NODESIZE) if round_ % 3 == 0 else template)
        for _ in range(rng.randrange(1, 12)):
            block[rng.randrange(HEADER - 5, NODESIZE)] = rng.randrange(256)
        count = rng.choice([0, 1, 5, 200, 0xFFFFFFFF, rng.randrange(1 << 32)])
        struct.pack_into("<I", block, ondisk.HEADER.offset("nritems"), count)
        block[ondisk.HEADER.offset("level")] = rng.choice([0, 0, 1, 7, 255])
        report = describe(bytes(block), NODESIZE, SECTOR)
        assert 0 <= report.start <= NODESIZE and 0 <= report.length <= NODESIZE - report.start
        for item in report.items:
            assert report.start <= item.position <= NODESIZE - 25
            assert HEADER + item.data_offset + item.data_size <= NODESIZE
            assert item.data is None or len(item.data) == item.data_size
        for ptr in report.key_ptrs:
            assert report.start <= ptr.position <= NODESIZE - 33
    with pytest.raises(ValueError):
        describe(bytes(NODESIZE - 1), NODESIZE, SECTOR)


# ---------------------------------------------------------------------------
# Real images, through the catalog
# ---------------------------------------------------------------------------
def _catalog(image, directory):
    path = directory / f"{image.stem}.db"
    build_catalog(image, path, full_sweep=True)
    return db.open_readonly(path)


def _corpus(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    return path


def test_sandbox_slack_equals_what_the_prototype_saved_and_adds_the_block_it_skips():
    with scratch_dir("test_slack_") as d:
        conn = _catalog(SANDBOX, d)
        rows = conn.execute(
            "SELECT n.physical, n.generation, n.owner, c.slack_start, c.slack_len,"
            " c.slack_nonzero, c.slack_class FROM nodes n JOIN contents c USING (content_id)"
            " WHERE c.slack_nonzero > 0"
        ).fetchall()
        ours = {row["physical"]: row for row in rows}
        assert set(ours) > {slack["physical"] for slack in GOLDEN["leaf_slacks"]}
        with open_image(SANDBOX) as img:
            for slack in GOLDEN["leaf_slacks"]:
                row = ours[slack["physical"]]
                assert (row["slack_len"], row["slack_nonzero"], u64(row["generation"])) == (
                    slack["size"], slack["nonzero"], slack["generation"],
                )  # fmt: skip
                start = slack["physical"] + row["slack_start"]
                saved = bytes(img.mmap[start : start + row["slack_len"]])
                assert hashlib.sha256(saved).hexdigest() == slack["sha256"]
        # the prototype sends extent-tree leaves to a parser that never looks at slack
        skipped = [row for p, row in ours.items() if p not in
                   {slack["physical"] for slack in GOLDEN["leaf_slacks"]}]  # fmt: skip
        assert skipped and {row["owner"] for row in skipped} == {ondisk.EXTENT_TREE_OBJECTID}
        assert {row["slack_class"] for row in rows} == {STALE}

        # its counters: no orphan item of a file tree, no internal pointer, no residual
        assert GOLDEN["stats"]["orphan_items_found"] == 0
        marks = ", ".join("?" * len(FILE_TREE_TYPES))
        file_items = conn.execute(
            f"SELECT COUNT(*) FROM stale_items WHERE type_name IN ({marks})", FILE_TREE_TYPES
        ).fetchone()[0]
        assert file_items == 0 and conn.execute("SELECT COUNT(*) FROM stale_items").fetchone()[0]
        assert GOLDEN["stats"]["internal_orphan_ptrs_found"] == 0
        assert conn.execute("SELECT COUNT(*) FROM stale_key_ptrs").fetchone()[0] == 0
        conn.close()


def test_extent_back_references_carry_the_extent_address_not_the_length():
    """Prototype defect #8, the right way round and relative to the image: a data back-reference
    that names an inode and file offset belongs to the extent that inode's EXTENT_DATA names at
    that offset, in whatever generation both survive. The extent's address is the EXTENT_ITEM's
    key objectid; the prototype took the key offset, which is the length."""
    with scratch_dir("test_slack_") as d:
        conn = _catalog(SANDBOX, d)
        pairs = conn.execute(
            "SELECT r.extent_bytenr, f.disk_bytenr, e.num_bytes, f.disk_num_bytes"
            " FROM extent_backrefs r"
            " JOIN extents e ON e.content_id = r.content_id AND e.bytenr = r.extent_bytenr"
            " JOIN file_extents f ON f.objectid = r.objectid AND f.file_offset = r.file_offset"
            " JOIN content_blocks b ON b.content_id = f.content_id AND b.owner = r.root"
            " WHERE r.ref_type_name = 'EXTENT_DATA_REF' AND f.disk_bytenr > 0"
        ).fetchall()
        conn.close()
    matched = [p for p in pairs if p["extent_bytenr"] == p["disk_bytenr"]]
    assert matched  # the 5 MiB file's extent, seen from superseded extent-tree leaves
    assert all(p["num_bytes"] == p["disk_num_bytes"] for p in matched)
    assert not any(p["extent_bytenr"] == p["disk_num_bytes"] for p in pairs)


def _mkfs_generation(directory) -> int:
    if subprocess.run([str(PINNED), "mkfs.btrfs", "--version"], capture_output=True).returncode:
        pytest.skip("the pinned mkfs.btrfs is absent: run corpus/vm/fetch_vm.sh")
    control = directory / "control.img"
    subprocess.run(["truncate", "-s", "512M", str(control)], check=True)
    subprocess.run([str(PINNED), "mkfs.btrfs", "-q", "-f", "--csum", "xxhash", str(control)],
                   check=True)  # fmt: skip
    with open_image(control) as img:
        field = ondisk.SUPERBLOCK.offset("generation")
        start = ondisk.sb_offset(0) + field
        return struct.unpack("<Q", img.mmap[start : start + 8])[0]


@pytest.mark.parametrize("name", ["m3_wide", "s01_discard_none_r1", "m2_logtree", "m1_lzo"])
def test_in_the_catalog_only_mkfs_written_blocks_have_anything_beyond_nritems(name):
    """EXP-005 as a query. The generation mkfs ends at comes from a control formatted here."""
    image = _corpus(name)
    with scratch_dir("test_slack_") as d:
        mkfs_generation = _mkfs_generation(d)
        conn = _catalog(image, d)
        kernel = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(c.slack_nonzero), 0), SUM(c.slack_len) FROM contents c"
            " JOIN content_blocks b USING (content_id) WHERE b.generation > ?",
            (mkfs_generation,),
        ).fetchone()
        assert kernel[0] > 0 and kernel[1] == 0 and kernel[2] > 0
        mkfs = conn.execute(
            "SELECT c.slack_class, s.type_name FROM contents c"
            " JOIN content_blocks b USING (content_id) LEFT JOIN stale_items s USING (content_id)"
            " WHERE c.slack_nonzero > 0"
        ).fetchall()
        assert mkfs and {row["slack_class"] for row in mkfs} == {STALE}
        assert not {row["type_name"] for row in mkfs} & set(FILE_TREE_TYPES)
        # every valid content was described
        undescribed = conn.execute(
            "SELECT COUNT(*) FROM contents WHERE parsed = 1 AND slack_class IS NULL"
        ).fetchone()[0]
        assert undescribed == 0
        conn.close()


def test_the_planted_image_differs_from_m3_wide_in_exactly_the_two_planted_blocks():
    wide, planted = _corpus("m3_wide"), _corpus("m4_planted_slack")
    with scratch_dir("test_slack_") as d:
        query = (
            "SELECT b.bytenr, b.generation, b.level, b.owner, b.live, b.copies, c.sha256,"
            " c.slack_class, c.slack_nonzero FROM contents c JOIN content_blocks b"
            " USING (content_id)"
        )
        before = {(r["bytenr"], r["generation"]): r for r in _catalog(wide, d).execute(query)}
        after = {(r["bytenr"], r["generation"]): r for r in _catalog(planted, d).execute(query)}
    assert before.keys() == after.keys()  # every block still validates: checksums were redone
    changed = [key for key in before if before[key]["sha256"] != after[key]["sha256"]]
    other = [key for key, row in after.items() if row["slack_class"] == OTHER]
    assert sorted(changed) == sorted(other) and len(other) == 2
    assert not [key for key, row in before.items() if row["slack_class"] == OTHER]
    assert sorted(after[key]["level"] for key in other) == [0, 1]  # a leaf and an internal node
    for key in other:
        row = after[key]
        assert (row["owner"], row["live"], row["copies"]) == (5, 1, before[key]["copies"])
        assert before[key]["slack_class"] == ZERO and row["slack_nonzero"] > 0


def test_btrfs_check_accepts_the_planted_image():
    """What Toolan & Humphries report for every technique: the standard checker sees nothing."""
    planted = _corpus("m4_planted_slack")
    if subprocess.run([str(PINNED), "btrfs", "--version"], capture_output=True).returncode:
        pytest.skip("the pinned btrfs is absent: run corpus/vm/fetch_vm.sh")
    with scratch_dir("test_slack_") as d:
        copy = d / "copy.img"  # no foreign tool ever opens a corpus image itself
        subprocess.run(["cp", "--sparse=always", str(planted), str(copy)], check=True)
        done = subprocess.run([str(PINNED), "btrfs", "check", "--readonly", str(copy)],
                              capture_output=True, text=True)  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert "no error found" in done.stdout + done.stderr
