"""corpus/mutate.py: derives damaged test images, only ever into a new file under images/."""

import hashlib
import importlib.util
import subprocess
import sys

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.image import open_image
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
