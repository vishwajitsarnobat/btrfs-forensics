"""corpus/mutate.py: derives damaged test images, only ever into a new file under images/."""

import hashlib
import importlib.util
import subprocess
import sys

import pytest

from btrfska.hiding.areas import _BACKUP_PADDING as BACKUP_PADDING
from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.slack import slack_range
from tests.helpers import REPO_ROOT, make_block, scratch_dir, write_sparse_image

MUTATE = REPO_ROOT / "corpus" / "mutate.py"
SIZE = ondisk.sb_offset(1) + 3 * 1024**2 + 12345  # odd tail: the copy must keep the exact size


def run(*args):
    return subprocess.run(
        [sys.executable, str(MUTATE), *map(str, args)], capture_output=True, text=True
    )


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def source():
    with scratch_dir("test_mutate_") as d:
        blocks = {
            ondisk.sb_offset(0): make_block(0, csum_type=csum.SHA256),
            ondisk.sb_offset(1): make_block(1, csum_type=csum.SHA256),
            5 * 1024**2 + 7: b"payload",
        }
        yield write_sparse_image(d / "src.img", SIZE, blocks), d


def selection(path):
    with open_image(path) as img:
        return sb.read_superblock(img)


def test_set_incompat_bit_rewrites_every_copy_with_a_valid_csum(source):
    src, d = source
    before = sha256(src)
    result = run(src, d / "unknown.img", "set-incompat-bit", 40)
    assert result.returncode == 0, result.stderr
    assert sha256(src) == before
    dst = d / "unknown.img"
    assert dst.stat().st_size == SIZE
    chosen = selection(dst)
    assert [c.valid for c in chosen.copies[:2]] == [True, True]
    assert chosen.disagreements == []
    assert chosen.selected.fields["incompat_flags"] & (1 << 40)
    assert sb.gate(chosen.selected.fields).report_lines() == ["UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40"]
    # Everything outside the two superblocks is byte-identical.
    a, b = bytearray(src.read_bytes()), bytearray(dst.read_bytes())
    for mirror in (0, 1):
        off = ondisk.sb_offset(mirror)
        a[off : off + 4096] = b[off : off + 4096] = bytes(4096)
    assert a == b


def test_zero_primary_superblock_leaves_mirror_1(source):
    src, d = source
    assert run(src, d / "damaged.img", "zero-primary-sb").returncode == 0
    chosen = selection(d / "damaged.img")
    assert chosen.selected.mirror == 1
    assert chosen.disagreements == ["mirror 0 invalid: magic mismatch, csum mismatch"]


def test_invalid_source_leaves_no_output(source):
    _, d = source
    broken = write_sparse_image(d / "broken.img", SIZE, {})  # no valid superblock at all
    result = run(broken, d / "out.img", "set-incompat-bit", 40)
    assert result.returncode != 0
    assert "not a valid superblock" in result.stderr
    assert not (d / "out.img").exists()


def test_transplant_puts_a_foreign_superblock_into_a_mirror(source):
    src, d = source
    fsid = bytes.fromhex("bb" * 16)
    donor = write_sparse_image(
        d / "donor.img",
        SIZE,
        {ondisk.sb_offset(1): make_block(1, generation=7, csum_type=csum.XXHASH, fsid=fsid)},
    )
    before = sha256(src), sha256(donor)
    result = run(src, d / "foreign.img", "transplant-sb", donor, 1, 1000)
    assert result.returncode == 0, result.stderr
    assert (sha256(src), sha256(donor)) == before
    chosen = selection(d / "foreign.img")
    mirror1 = chosen.copies[1]
    assert mirror1.valid  # csum recomputed with the donor's own type (xxhash64)
    assert mirror1.fields["generation"] == 1000
    assert mirror1.fields["fsid"] == fsid
    assert mirror1.fields["csum_type"] == csum.XXHASH
    assert chosen.selected.mirror == 0
    assert chosen.foreign == [mirror1]
    # Only the mirror-1 block changed.
    a, b = bytearray(src.read_bytes()), bytearray(d.joinpath("foreign.img").read_bytes())
    off = ondisk.sb_offset(1)
    a[off : off + 4096] = b[off : off + 4096] = bytes(4096)
    assert a == b


def test_transplant_refuses_an_invalid_donor_copy(source):
    src, d = source
    result = run(src, d / "foreign.img", "transplant-sb", src, 2, 1000)  # mirror 2 not present
    assert result.returncode != 0
    assert not (d / "foreign.img").exists()


def load_mutate():
    spec = importlib.util.spec_from_file_location("corpus_mutate", MUTATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("offset", "length"),
    [
        (5, 10),  # inside the first chunk
        (16 - 3, 8),  # straddles the chunk boundary at 16
        (16 * 2 - 1, 16 + 2),  # starts in chunk 1, covers chunk 2, ends in chunk 3
        (16 * 4 - 6, 6),  # ends exactly at the image end
    ],
)
def test_patches_straddling_chunks_apply_without_growing_them(scratch_src, offset, length):
    mutate = load_mutate()
    size = 16 * 4
    src = write_sparse_image(scratch_src / "src.bin", size, {0: bytes(range(size))})
    patch = bytes([0xEE]) * length
    out = scratch_src / "out.bin"
    with open(src, "rb") as f, open(out, "xb") as o:
        mutate.write_patched(f, o, size, {offset: patch}, chunk=16)
    expected = bytearray(range(size))
    expected[offset : offset + length] = patch
    assert out.read_bytes() == bytes(expected)


def test_patch_beyond_the_image_end_is_refused(scratch_src):
    mutate = load_mutate()
    with pytest.raises(SystemExit, match="beyond the image end"):
        mutate.check_patches(64, {60: bytes(8)})


@pytest.fixture
def scratch_src():
    with scratch_dir("test_mutate_unit_") as d:
        yield d


def test_refuses_sandbox_img_as_output(source):
    src, d = source
    result = run(src, d / "sandbox.img", "zero-primary-sb")
    assert result.returncode != 0
    assert "sandbox.img" in result.stderr
    assert not (d / "sandbox.img").exists()


@pytest.mark.parametrize(
    "outside",
    [REPO_ROOT / "mutate_test_out.img", REPO_ROOT / "images" / ".." / "mutate_test_out.img"],
)
def test_refuses_output_outside_images(source, outside):
    src, _ = source
    result = run(src, outside, "zero-primary-sb")
    assert result.returncode != 0
    assert "images/" in result.stderr
    assert not (REPO_ROOT / "mutate_test_out.img").exists()


def test_refuses_existing_output_and_in_place_mutation(source):
    src, d = source
    before = sha256(src)
    assert run(src, src, "zero-primary-sb").returncode != 0
    existing = d / "existing.img"
    existing.write_bytes(b"keep")
    assert run(src, existing, "zero-primary-sb").returncode != 0
    assert existing.read_bytes() == b"keep"
    assert sha256(src) == before


def test_refuses_output_through_a_symlink(source):
    src, d = source
    target = d / "target.img"
    target.write_bytes(b"keep")
    (d / "link.img").symlink_to(target)
    assert run(src, d / "link.img", "zero-primary-sb").returncode != 0
    assert target.read_bytes() == b"keep"


def test_flip_byte_inverts_exactly_the_given_bytes(source):
    src, d = source
    offsets = [5 * 1024**2 + 7, 5 * 1024**2 + 8, 3 * 1024**2]
    before = sha256(src)
    result = run(src, d / "flipped.img", "flip-byte", *offsets)
    assert result.returncode == 0, result.stderr
    assert sha256(src) == before
    expected = bytearray(src.read_bytes())
    for offset in offsets:
        expected[offset] ^= 0xFF
    assert (d / "flipped.img").read_bytes() == bytes(expected)


def test_flip_byte_refuses_offsets_outside_the_image(source):
    src, d = source
    for offset in (SIZE, -1):
        result = run(src, d / "out.img", "flip-byte", 100, offset)
        assert result.returncode != 0
        assert "outside the image" in result.stderr
        assert not (d / "out.img").exists()


def test_plant_slack_refuses_a_tree_without_an_internal_node_and_leaves_no_file():
    """sandbox.img's fs tree is a single leaf. The source is only read."""
    with scratch_dir("test_mutate_") as d:
        before = sha256(REPO_ROOT / "sandbox.img")
        result = run(REPO_ROOT / "sandbox.img", d / "planted.img", "plant-slack")
        assert result.returncode != 0 and "no internal node" in result.stderr
        assert not (d / "planted.img").exists()
        assert sha256(REPO_ROOT / "sandbox.img") == before


def test_plant_slack_changes_only_the_slack_and_checksum_of_the_blocks_it_names():
    src = REPO_ROOT / "images" / "scenarios" / "m3_wide.img"
    if not src.exists():
        pytest.skip("m3_wide.img absent: build it with corpus/build.py")
    with scratch_dir("test_mutate_") as d:
        result = run(src, d / "planted.img", "plant-slack", "--message", "over here")
        assert result.returncode == 0, result.stderr
        offsets = [int(word) for word in result.stdout.split("plant-slack", 1)[1].split()]
        assert len(offsets) == 4  # a node and a leaf, two DUP copies each
        a, b = src.read_bytes(), (d / "planted.img").read_bytes()
        assert len(a) == len(b)
        nodesize = 16384
        for offset in offsets:
            old, new = a[offset : offset + nodesize], b[offset : offset + nodesize]
            differing = [i for i in range(nodesize) if old[i] != new[i]]
            assert new.count(b"over here") == 1 and old.count(b"over here") == 0
            start = new.index(b"over here")
            assert all(i < ondisk.CSUM_SIZE or start <= i < start + 9 for i in differing)
            a = a[:offset] + new + a[offset + nodesize :]
        assert a == b  # nothing else in the image changed


def test_lose_root_items_refuses_a_tree_no_superseded_leaf_names_and_leaves_no_file():
    with scratch_dir("test_mutate_") as d:
        before = sha256(REPO_ROOT / "sandbox.img")
        result = run(REPO_ROOT / "sandbox.img", d / "lost.img", "lose-root-items", "999")
        assert result.returncode != 0 and "no superseded root-tree leaf" in result.stderr
        assert not (d / "lost.img").exists()
        assert sha256(REPO_ROOT / "sandbox.img") == before


def test_lose_root_items_flips_one_byte_per_copy_and_never_touches_the_current_root():
    src = REPO_ROOT / "images" / "scenarios" / "m5_delsubvol.img"
    if not src.exists():
        pytest.skip("m5_delsubvol.img absent: build it with corpus/build.py")
    with scratch_dir("test_mutate_") as d:
        result = run(src, d / "lost.img", "lose-root-items", "257")
        assert result.returncode == 0, result.stderr
        offsets = [int(word) for word in result.stdout.splitlines()[0].split()[2:]]
        with open_image(src) as old, open_image(d / "lost.img") as new:
            assert old.size == new.size and offsets
            for offset in offsets:
                assert old.mmap[offset] ^ 0xFF == new.mmap[offset]
            fields = sb.read_superblock(new).selected.fields
            assert sb.read_superblock(old).selected.fields["root"] == fields["root"]
        assert "root-tree leaves that named tree 257" in result.stdout


def test_flip_data_refuses_a_file_it_cannot_find_and_leaves_no_file():
    with scratch_dir("test_mutate_") as d:
        result = run(REPO_ROOT / "sandbox.img", d / "out.img", "flip-data", "nothing.txt", "1")
        assert result.returncode != 0 and "no file 'nothing.txt'" in result.stderr
        assert not (d / "out.img").exists()
        result = run(REPO_ROOT / "sandbox.img", d / "out.img", "flip-data", "odd")
        assert result.returncode != 0 and "pairs of NAME MIRROR" in result.stderr


def test_flip_data_inverts_one_byte_per_mirror_asked_for():
    src = REPO_ROOT / "images" / "scenarios" / "m6_datacsum.img"
    if not src.exists():
        pytest.skip("m6_datacsum.img absent: build it with corpus/build.py")
    with scratch_dir("test_mutate_") as d:
        result = run(src, d / "out.img", "flip-data", "repairable.txt", "2", "damaged.txt", "all")
        assert result.returncode == 0, result.stderr
        offsets = [int(word) for word in result.stdout.splitlines()[0].split()[2:]]
        assert len(offsets) == 3  # one mirror of one file, both of the other
        with open_image(src) as old, open_image(d / "out.img") as new:
            for offset in offsets:
                assert old.mmap[offset] ^ 0xFF == new.mmap[offset]
        assert "repairable.txt at logical" in result.stdout and "mirror 2 of 2" in result.stdout


def test_hiding_planters_refuse_what_they_cannot_plant_and_leave_no_file():
    with scratch_dir("test_mutate_") as d:
        result = run(REPO_ROOT / "sandbox.img", d / "out.img", "plant-file-slack", "nothing.txt")
        assert result.returncode != 0 and "no file 'nothing.txt'" in result.stderr
        assert not (d / "out.img").exists()
        result = run(REPO_ROOT / "sandbox.img", d / "out.img", "plant-pre-sb", "--offset", "0")
        assert result.returncode != 0 and "not inside the first 64 KiB" in result.stderr
        assert not (d / "out.img").exists()


def test_a_feature_gated_field_in_use_is_not_planted_in():
    src = REPO_ROOT / "images" / "scenarios" / "m6_fsid_m.img"
    if not src.exists():
        pytest.skip("m6_fsid_m.img absent: build it with corpus/build.py")
    with scratch_dir("test_mutate_") as d:
        result = run(src, d / "out.img", "plant-sb-reserved", "--field", "metadata_uuid")
        assert result.returncode != 0 and "METADATA_UUID is set" in result.stderr
        assert not (d / "out.img").exists()


# ---------------------------------------------------------------------------
# Where the hiding planters write (plan.md M6e): keyword arguments for EXP-021, whose defaults
# are what the subcommands do, so the corpus rows they build are unchanged.
# ---------------------------------------------------------------------------
M = load_mutate()


def corpus_image(name):
    path = REPO_ROOT / "images" / "scenarios" / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    return path


def superblock_patches(name, planter, *args, **kwargs):
    path = corpus_image(name)
    with open(path, "rb") as src:
        return planter(src, path.stat().st_size, *args, **kwargs)


def test_backup_slot_padding_fields_are_the_bytes_the_detector_examines():
    roots, size = ondisk.SUPERBLOCK.offset("super_roots"), ondisk.ROOT_BACKUP.size
    for slot in range(ondisk.NUM_BACKUP_ROOTS):
        fields = (M.SB_FIELDS[f"backup{slot}_unused_64"], M.SB_FIELDS[f"backup{slot}_unused_8"])
        assert [(a, b) for a, b, _ in fields] == [
            (roots + slot * size + a, roots + slot * size + b) for a, b in BACKUP_PADDING
        ]


def test_plant_sb_field_writes_from_byte_at_and_stops_at_the_field_end():
    patches = superblock_patches("m1_xxhash", M.plant_sb_field, "reserved", b"\xaa" * 300, at=190)
    assert len(patches) == 2
    for offset, block in patches.items():
        assert block[0x264 + 190 : 0x32B] == b"\xaa" * 9 and not any(block[0x264 : 0x264 + 190])
        assert block[0x32B] != 0xAA
        assert sb.parse_copy(block, [ondisk.sb_offset(m) for m in range(3)].index(offset)).valid
    with pytest.raises(SystemExit, match="outside reserved"):
        superblock_patches("m1_xxhash", M.plant_sb_field, "reserved", b"x", at=199)


def test_plant_chunk_array_slack_at_must_lie_behind_the_stale_tail():
    path = corpus_image("m1_xxhash")
    with open_image(path) as img:
        start = ondisk.SUPER_INFO_OFFSET
        primary = bytes(img.mmap[start : start + ondisk.SUPER_INFO_SIZE])
    free = M.chunk_array_free(primary)
    used = ondisk.SUPERBLOCK.unpack_from(primary)["sys_chunk_array_size"]
    assert used < free < ondisk.SYSTEM_CHUNK_ARRAY_SIZE  # behind the stale tail mkfs leaves
    array = ondisk.SUPERBLOCK.offset("sys_chunk_array")
    patches = superblock_patches("m1_xxhash", M.plant_chunk_array_slack, b"\x01\x02", at=free)
    assert all(block[array + free : array + free + 2] == b"\x01\x02" for block in patches.values())
    for at, message in ((free - 1, b"x"), (2047, b"xy")):
        with pytest.raises(SystemExit, match="not all free"):
            superblock_patches("m1_xxhash", M.plant_chunk_array_slack, message, at=at)


def test_plant_pre_sb_reaches_the_rest_of_the_first_mib_but_never_the_superblock():
    end = 1 << 20
    assert M.plant_pre_sb(None, end, b"x", 0x11000) == {0x11000: b"x"}
    assert M.plant_pre_sb(None, end, b"x", end - 1) == {end - 1: b"x"}
    for offset, message in ((0xFFFF, b"xy"), (0x10000, b"x"), (0x10FFF, b"x"), (end - 1, b"xy")):
        with pytest.raises(SystemExit, match="not inside the first 64 KiB"):
            M.plant_pre_sb(None, end, message, offset)


def test_plant_backup_roots_copies_the_slot_asked_for_and_never_the_newest():
    path = corpus_image("m1_blake2b")
    roots = sb.backup_roots(selection(path).selected.fields)
    newest, source = roots[-1]["slot"], roots[1]["slot"]
    patches = superblock_patches("m1_blake2b", M.plant_backup_roots, source)
    size, base = ondisk.ROOT_BACKUP.size, ondisk.SUPERBLOCK.offset("super_roots")
    for block in patches.values():
        new = block[base + newest * size : base + (newest + 1) * size]
        assert new == block[base + source * size : base + (source + 1) * size]
    with pytest.raises(SystemExit, match="not an older backup root slot"):
        superblock_patches("m1_blake2b", M.plant_backup_roots, newest)


def test_plant_inode_reserved_and_nsec_write_from_byte_at_and_keep_the_rest():
    path = corpus_image("m1_xxhash")
    with open_image(path) as img:
        node, item = M.first_file_inode(open_filesystem(img))
    at, old = ondisk.HEADER.size + item.offset, ondisk.INODE_ITEM.unpack_from(item.data)
    reserved = ondisk.INODE_ITEM.offset("sequence") + 8
    patches, _ = M.plant_inode_reserved(path, b"\xaa" * 40, at=30)
    assert len(patches) == len(node.copies)
    for block in patches.values():
        assert block[at + reserved : at + reserved + 32] == bytes(30) + b"\xaa\xaa"
        assert block[at + reserved + 32 :][:8] == item.data[reserved + 32 :][:8]
    patches, _ = M.plant_nsec(path, b"\x01\x02", at=3)
    for block in patches.values():
        new = ondisk.INODE_ITEM.unpack_from(block, at)
        assert new["atime_nsec"] == old["atime_nsec"] & 0xFFFFFF | 0x01 << 24
        assert new["ctime_nsec"] == old["ctime_nsec"] & ~0xFF | 0x02
        assert (new["mtime_nsec"], new["otime_nsec"]) == (old["mtime_nsec"], old["otime_nsec"])
        assert csum.block_csum_ok(csum.XXHASH, block)
    with pytest.raises(SystemExit, match="must fit the 16 bytes"):
        M.plant_nsec(path, b"xy", at=15)


def test_plant_slack_margin_from_end_and_leaf_only():
    path = corpus_image("m1_xxhash")  # an fs tree of one leaf
    with pytest.raises(SystemExit, match="no internal node"):
        M.plant_slack(path, b"x")
    patches = M.plant_slack(path, b"\x01\x02\x03", 0, True, True)
    assert len(patches) == 2  # metadata DUP
    with open_image(path) as img:
        for offset, block in patches.items():
            start, end = slack_range(img.mmap[offset : offset + len(block)], len(block))
            assert block[end - 3 : end] == b"\x01\x02\x03" and not any(block[start : end - 3])
            assert csum.block_csum_ok(csum.XXHASH, block)


def test_plant_file_slack_writes_at_bytes_after_the_end_of_file():
    path = corpus_image("m6_datacsum")
    patches, _ = M.plant_file_slack(path, "plain.txt", b"\x07", False, at=5)
    sectors = [(offset, data) for offset, data in patches.items() if len(data) == 4096]
    assert len(sectors) == 2  # data DUP
    with open_image(path) as img:
        for offset, data in sectors:
            old = bytes(img.mmap[offset : offset + 4096])
            end_of_file = len(old.rstrip(b"\0"))  # plain.txt is text: no zero byte in it
            assert [i for i in range(4096) if old[i] != data[i]] == [end_of_file + 5]
    with pytest.raises(SystemExit, match="bytes past the end"):
        M.plant_file_slack(path, "plain.txt", b"\x07", False, at=4096)


def test_plant_device_slack_at_refuses_bytes_outside_what_device_free_gives():
    path = corpus_image("m1_sha256_bgt")
    with open_image(path) as img:
        free, last, end = M.device_free(img, open_filesystem(img))
    assert free[0][0] == last and free[-1][1] == end
    assert M.plant_device_slack(path, b"x", last)[0] == {last: b"x"}
    assert M.plant_device_slack(path, b"x", end - 1)[0] == {end - 1: b"x"}
    for at, message in ((last - 1, b"x"), (end - 1, b"xy")):
        with pytest.raises(SystemExit, match="not all past the last device extent"):
            M.plant_device_slack(path, message, at)


def test_plant_file_slack_refuses_an_inline_file_and_reaches_files_in_subdirectories():
    path = corpus_image("m6_datacsum")
    with pytest.raises(SystemExit, match="not in an uncompressed regular extent"):
        M.plant_file_slack(path, "inline.txt", b"x", False)
    deep = corpus_image("m4_deep")
    with pytest.raises(SystemExit, match="no file 'victims' in directory 7"):
        M.plant_file_slack(deep, "victims", b"x", False, parent=7)
