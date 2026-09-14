"""corpus/mutate.py: derives damaged test images, only ever into a new file under images/."""

import hashlib
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
