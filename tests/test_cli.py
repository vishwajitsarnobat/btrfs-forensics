import json
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
    assert not any(line.startswith("kernel would mount") for line in lines)
    assert "tree fsid: " + next(ln[6:] for ln in lines if ln.startswith("fsid: ")) in lines
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


def test_info_says_what_the_kernel_would_mount_when_it_differs(capsys):
    # The kernel mounts mirror 0 only: disk-io.c:3333 btrfs_read_disk_super(bdev, 0, false).
    with scratch_dir("test_cli_") as d:
        damaged = _image_with(d, "damaged.img", {ondisk.sb_offset(1): make_block(mirror=1)})
        assert main(["info", damaged]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "kernel would mount: mirror 0 (invalid: magic mismatch, csum mismatch)" in out

        blocks = {
            ondisk.sb_offset(0): make_block(0, generation=5),
            ondisk.sb_offset(1): make_block(1, generation=6),
        }
        assert main(["info", _image_with(d, "older.img", blocks)]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "selected: mirror 1 (generation 6)" in out
        assert "kernel would mount: mirror 0 (valid, generation 5)" in out

        # Mirror 0 is selected but carries a check the kernel rejects on.
        blocks = {ondisk.sb_offset(0): make_block(0, num_devices=0)}
        assert main(["info", _image_with(d, "warn.img", blocks)]) == 0
        out = capsys.readouterr().out.splitlines()
        assert any(
            line.startswith("  mirror 0 @ 65536: valid, generation 7, csum crc32c ")
            and line.endswith(" (warnings: num_devices is 0)")
            for line in out
        )
        assert "kernel would mount: mirror 0 (invalid: num_devices is 0)" in out

        same = {ondisk.sb_offset(m): make_block(m) for m in (0, 1)}
        assert main(["info", _image_with(d, "same.img", same)]) == 0
        assert not any(
            line.startswith("kernel would mount") for line in capsys.readouterr().out.splitlines()
        )


def test_info_marks_a_foreign_mirror(capsys):
    fsid_a, fsid_b = bytes.fromhex("aa" * 16), bytes.fromhex("bb" * 16)
    with scratch_dir("test_cli_") as d:
        blocks = {
            ondisk.sb_offset(0): make_block(0, generation=5, fsid=fsid_a),
            ondisk.sb_offset(1): make_block(1, generation=9, fsid=fsid_b),
        }
        assert main(["info", _image_with(d, "foreign.img", blocks)]) == 0
        out = capsys.readouterr().out.splitlines()
        uuid_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        assert any(
            line.startswith("  mirror 1 @ 67108864: valid, generation 9, csum crc32c ")
            and line.endswith(f" (foreign fsid {uuid_b})")
            for line in out
        )
        assert "selected: mirror 0 (generation 5)" in out
        assert f"  mirror 1 foreign superblock at 67108864 (fsid {uuid_b}, generation 9)" in out
        assert "fsid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in out
        assert not any(line.startswith("kernel would mount") for line in out)


def test_info_prints_the_tree_fsid(capsys):
    fsid, metadata_uuid = bytes.fromhex("aa" * 16), bytes.fromhex("cc" * 16)
    with scratch_dir("test_cli_") as d:
        plain = make_block(fsid=fsid, metadata_uuid=metadata_uuid)
        assert main(["info", _image_with(d, "plain.img", {ondisk.sb_offset(0): plain})]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "tree fsid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in out

        flagged = make_block(
            fsid=fsid,
            metadata_uuid=metadata_uuid,
            incompat=SANDBOX_INCOMPAT | ondisk.INCOMPAT["METADATA_UUID"],
        )
        assert main(["info", _image_with(d, "flagged.img", {ondisk.sb_offset(0): flagged})]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "fsid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in out
        assert "tree fsid: cccccccc-cccc-cccc-cccc-cccccccccccc" in out


def test_info_without_any_valid_superblock_fails(capsys):
    with scratch_dir("test_cli_") as d:
        image = _image_with(d, "zero.img", {})
        assert main(["info", image]) == 2
        out = capsys.readouterr().out.splitlines()
        assert "selected: none" in out
        assert "NO_VALID_SUPERBLOCK" in out


# ---------------------------------------------------------------------------
# btrfska walk
# ---------------------------------------------------------------------------
def _records(out: str) -> list[dict]:
    return [json.loads(line) for line in out.splitlines()]


def _physical(logical: int, stripe: int) -> int:
    """sandbox.img METADATA|DUP chunk 30408704: stripes at 38797312 and 72351744."""
    return (38797312, 72351744)[stripe] + logical - 30408704


@pytest.mark.sandbox
def test_walk_backup_fs_tree_emits_items_with_provenance(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--root", "backup:11", "--tree", "fs"]) == 0
    captured = capsys.readouterr()
    records = _records(captured.out)
    assert [r["record"] for r in records] == ["item"] * 8
    first = records[0]
    assert first["key"] == {"objectid": 256, "type": 1, "type_name": "INODE_ITEM", "offset": 0}
    assert first["root"] == {
        "source": "backup:11",
        "tree": "fs",
        "tree_id": 5,
        "bytenr": 30785536,
        "level": 0,
        "generation": 11,
        "via": "backup slot 2",
    }
    node = first["node"]
    assert (node["bytenr"], node["level"], node["generation"], node["owner"]) == (
        30785536,
        0,
        11,
        5,
    )
    assert node["valid"] is True and node["problems"] == []
    assert [
        (c["mirror"], c["devid"], c["physical"], c["used"], c["valid"]) for c in node["copies"]
    ] == [
        (1, 1, _physical(30785536, 0), True, True),
        (2, 1, _physical(30785536, 1), False, True),
    ]
    checks = node["copies"][0]["checks"]
    assert checks["csum"] is True and checks["parent_generation"] is True
    assert checks["first_key"] is None  # a root has no parent key
    assert first["slot"] == 0 and first["chunk_map"] == "current"
    assert first["unsupported_format"] is False
    assert first["summary"]["size"] == 30 and first["summary"]["mode"] == "40755"
    extent = next(r for r in records if r["key"]["type_name"] == "EXTENT_DATA")
    assert extent["summary"]["type"] == "inline" and extent["summary"]["ram_bytes"] == 31
    assert "btrfska walk: 1 nodes (0 invalid), 8 items, 0 walk problems" in captured.err


@pytest.mark.sandbox
def test_walk_current_chunk_tree_by_default_root(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--tree", "chunk"]) == 0
    records = _records(capsys.readouterr().out)
    assert [r["key"]["type_name"] for r in records] == ["DEV_ITEM"] + ["CHUNK_ITEM"] * 3
    assert records[0]["root"]["via"] == "superblock" and records[0]["root"]["source"] == "current"
    assert [r["summary"]["type"] for r in records[1:]] == [
        "DATA|single",
        "SYSTEM|DUP",
        "METADATA|DUP",
    ]


@pytest.mark.sandbox
def test_walk_subvolume_id_resolves_through_the_root_tree(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--root", "backup:13", "--tree", "5"]) == 0
    records = _records(capsys.readouterr().out)
    assert len(records) == 8
    assert records[0]["root"]["via"].startswith("ROOT_ITEM (5 132 0) in root tree 30572544 leaf ")


@pytest.mark.sandbox
def test_walk_from_a_bytenr(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--root", "bytenr:30720000"]) == 0
    records = _records(capsys.readouterr().out)
    assert len(records) == 12
    assert records[0]["root"] == {
        "source": "bytenr:30720000",
        "tree": None,
        "tree_id": None,
        "bytenr": 30720000,
        "level": None,
        "generation": None,
        "via": "bytenr",
    }
    assert main(["walk", str(sandbox_img), "--root", "bytenr:30720000", "--tree", "fs"]) == 0
    (first, *_) = _records(capsys.readouterr().out)
    assert first["node"]["copies"][0]["checks"]["owner"] is False  # a root-tree block, not fs


@pytest.mark.sandbox
def test_walk_reports_invalid_nodes_instead_of_items(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--root", "bytenr:4096"]) == 0
    captured = capsys.readouterr()
    (record,) = _records(captured.out)
    assert record["record"] == "invalid_node"
    assert record["node"]["valid"] is False and record["node"]["copies"] == []
    assert "not in any chunk" in record["node"]["problems"][0]
    assert "1 nodes (1 invalid), 0 items" in captured.err

    assert main(["walk", str(sandbox_img), "--root", "bytenr:30412800"]) == 0
    (record,) = _records(capsys.readouterr().out)
    assert record["record"] == "invalid_node"
    assert [c["valid"] for c in record["node"]["copies"]] == [False, False]
    assert all(c["used"] is False for c in record["node"]["copies"])


@pytest.mark.sandbox
def test_walk_rejects_unknown_roots_and_trees(sandbox_img, capsys):
    assert main(["walk", str(sandbox_img), "--root", "backup:99"]) == 1
    assert "no backup root with generation 99 (have 11, 12, 13, 14)" in capsys.readouterr().err
    assert main(["walk", str(sandbox_img), "--tree", "256"]) == 1
    assert "no ROOT_ITEM for tree 256" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["walk", str(sandbox_img), "--root", "slot:1"])
    assert "expected current, backup:GEN or bytenr:N" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["walk", str(sandbox_img), "--tree", "bogus"])


def test_walk_applies_the_incompat_gate(capsys):
    with scratch_dir("test_cli_") as d:
        block = make_block(incompat=SANDBOX_INCOMPAT | 1 << 40)
        image = _image_with(d, "unknown.img", {ondisk.sb_offset(0): block})
        assert main(["walk", image]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40" in captured.err.splitlines()

        # Overridden: the synthetic image has no chunk tree, so the root is an invalid node.
        assert main(["walk", "--allow-unsupported", image, "--tree", "root"]) == 0
        (record,) = _records(capsys.readouterr().out)
        assert record["record"] == "invalid_node" and record["unsupported_format"] is True


def test_walk_without_a_valid_superblock_is_refused(capsys):
    with scratch_dir("test_cli_") as d:
        assert main(["walk", _image_with(d, "zero.img", {})]) == 2
        assert "NO_VALID_SUPERBLOCK" in capsys.readouterr().err
