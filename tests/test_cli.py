import subprocess
import sys

import pytest

from btrfska import __version__
from btrfska.cli import main
from btrfska.substrate import ondisk
from conftest import SANDBOX_SHA256
from tests.helpers import SANDBOX_INCOMPAT, make_block, scratch_dir, write_sparse_image


def test_version_exits_zero_and_prints_version():
    result = subprocess.run(
        [sys.executable, "-m", "btrfska", "--version"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert result.stdout.strip() == __version__ == "0.0.1"


@pytest.mark.sandbox
def test_info_prints_sandbox_sha256(sandbox_img, capsys):
    assert main(["info", str(sandbox_img)]) == 0
    out = capsys.readouterr().out
    assert f"sha256: {SANDBOX_SHA256}" in out
    assert "size:   268435456 bytes" in out


def test_info_missing_image_fails_cleanly(capsys):
    assert main(["info", "does-not-exist.img"]) == 1
    assert "error" in capsys.readouterr().err


@pytest.mark.sandbox
def test_info_reports_superblocks_gate_and_backup_roots(sandbox_img, capsys):
    assert main(["info", str(sandbox_img)]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert "  mirror 0 @ 65536: valid, generation 14, csum crc32c eadc2eaa" in lines
    assert "  mirror 1 @ 67108864: valid, generation 14, csum crc32c 4abd0664" in lines
    assert "  mirror 2 @ 274877906944: not present (beyond image end)" in lines
    assert "selected: mirror 0 (generation 14)" in lines
    assert "disagreements: none" in lines
    assert "csum_type: 0 (crc32c, 4 bytes)" in lines
    assert (
        "compat_ro_flags: 0xb (FREE_SPACE_TREE, FREE_SPACE_TREE_VALID, BLOCK_GROUP_TREE)" in lines
    )
    assert "  block-group tree present: block groups are read from tree 11" in lines
    assert (
        "incompat_flags: 0x361 (MIXED_BACKREF, BIG_METADATA, EXTENDED_IREF, SKINNY_METADATA, "
        "NO_HOLES)" in lines
    )
    assert "gate: OK" in lines
    assert "UNSUPPORTED_INCOMPAT" not in out
    backups = [line for line in lines if line.startswith("  gen ")]
    assert [line.split()[1] for line in backups] == ["11", "12", "13", "14"]
    first = "  gen 11  slot 2  tree_root 30801920  chunk_root 22036480 (gen 8)  "
    assert backups[0].startswith(first)
    assert "fs_root 30785536 (gen 11)" in backups[0]


def _image_with(directory, name, blocks):
    size = ondisk.sb_offset(1) + 1024**2
    return str(write_sparse_image(directory / name, size, blocks))


def test_info_refuses_unknown_incompat_bit(capsys):
    with scratch_dir("test_cli_") as d:
        block = make_block(incompat=SANDBOX_INCOMPAT | 1 << 40)
        image = _image_with(d, "unknown.img", {ondisk.sb_offset(0): block})
        assert main(["info", image]) == 2
        out = capsys.readouterr().out.splitlines()
        assert "gate: REFUSED" in out
        assert "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40" in out

        assert main(["info", "--allow-unsupported", image]) == 0
        out = capsys.readouterr().out.splitlines()
        overridden = "gate: OVERRIDDEN (--allow-unsupported: derived rows are unsupported_format=1)"
        assert overridden in out
        assert "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40" in out


def test_info_refuses_experimental_feature(capsys):
    with scratch_dir("test_cli_") as d:
        block = make_block(incompat=SANDBOX_INCOMPAT | ondisk.INCOMPAT["RAID_STRIPE_TREE"])
        image = _image_with(d, "rst.img", {ondisk.sb_offset(0): block})
        assert main(["info", image]) == 2
        assert "UNSUPPORTED_INCOMPAT RAID_STRIPE_TREE" in capsys.readouterr().out.splitlines()


def test_info_selects_mirror_1_when_primary_is_damaged(capsys):
    with scratch_dir("test_cli_") as d:
        image = _image_with(d, "damaged.img", {ondisk.sb_offset(1): make_block(mirror=1)})
        assert main(["info", image]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "  mirror 0 @ 65536: INVALID (magic mismatch, csum mismatch)" in out
        assert "selected: mirror 1 (generation 7)" in out
        assert "disagreements:" in out
        assert "  mirror 0 invalid: magic mismatch, csum mismatch" in out


def test_info_without_any_valid_superblock_fails(capsys):
    with scratch_dir("test_cli_") as d:
        image = _image_with(d, "zero.img", {})
        assert main(["info", image]) == 2
        out = capsys.readouterr().out.splitlines()
        assert "selected: none" in out
        assert "NO_VALID_SUPERBLOCK" in out
