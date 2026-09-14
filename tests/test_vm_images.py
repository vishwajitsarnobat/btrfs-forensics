"""M1 corpus images (corpus/manifest.tsv). Skipped when an image has not been generated locally."""

import csv
import re
import shutil
import subprocess
import uuid

import pytest

from btrfska.cli import main
from btrfska.substrate import csum
from btrfska.substrate import superblock as sb
from btrfska.substrate.image import open_image
from tests.helpers import REPO_ROOT, SCENARIOS

pytestmark = pytest.mark.vm

MANIFEST = REPO_ROOT / "corpus" / "manifest.tsv"
# name -> (csum type, block-group tree expected)
HEALTHY = {
    "m1_xxhash": (csum.XXHASH, False),
    "m1_sha256_bgt": (csum.SHA256, True),
    "m1_blake2b": (csum.BLAKE2, False),
    "m1_lzo": (csum.XXHASH, False),
    "m1_zlib": (csum.XXHASH, False),
}


def image(name: str):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: regenerate it with the corpus/manifest.tsv command")
    return path


def read(name: str) -> sb.Selection:
    with open_image(image(name)) as img:
        return sb.read_superblock(img)


def manifest_rows() -> dict[str, dict]:
    with MANIFEST.open(newline="") as f:
        return {row["name"]: row for row in csv.DictReader(f, delimiter="\t")}


DERIVED = ["m1_unknown_incompat", "m1_mirror_damage", "m1_foreign_mirror"]


def test_manifest_lists_every_m1a_image():
    rows = manifest_rows()
    for name in [*HEALTHY, *DERIVED]:
        assert name in rows
        assert re.fullmatch(r"[0-9a-f]{64}", rows[name]["sha256"])
        assert rows[name]["command"]


@pytest.mark.parametrize("name", [*HEALTHY, *DERIVED])
def test_local_image_matches_manifest_sha256(name):
    path = image(name)
    with open_image(path) as img:
        assert img.sha256() == manifest_rows()[name]["sha256"]


@pytest.mark.parametrize("name", HEALTHY)
def test_superblock_csum_validates_on_every_copy(name):
    csum_type, bgt = HEALTHY[name]
    selection = read(name)
    assert [(c.present, c.valid) for c in selection.copies] == [
        (True, True),
        (True, True),
        (False, False),
    ]
    assert selection.selected.mirror == 0
    assert selection.disagreements == []
    fields = selection.selected.fields
    assert fields["csum_type"] == csum_type
    verdict = sb.gate(fields)
    assert verdict.status == "OK"
    assert verdict.block_group_tree is bgt
    assert len({r["tree_root_gen"] for r in sb.backup_roots(fields)}) == 4


@pytest.mark.parametrize("name", ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_foreign_mirror"])
def test_superblock_csums_agree_with_dump_super(name):
    """Independent oracle: btrfs-progs computes and prints the same csum with [match]."""
    if shutil.which("btrfs") is None:
        pytest.skip("btrfs-progs not installed")
    out = subprocess.run(
        ["btrfs", "inspect-internal", "dump-super", "-a", str(image(name))],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    printed = re.findall(r"^csum\s+0x([0-9a-f]+) \[match\]$", out, re.MULTILINE)
    ours = []
    for copy in read(name).copies:
        if copy.present:
            size = csum.csum_size(copy.fields["csum_type"])
            ours.append(copy.fields["csum"][:size].hex())
    assert printed == ours


def test_unknown_incompat_image_is_refused(capsys):
    path = image("m1_unknown_incompat")
    selection = read("m1_unknown_incompat")
    assert all(c.valid for c in selection.copies if c.present)
    assert selection.selected.fields["incompat_flags"] & (1 << 40)
    assert main(["info", str(path)]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert "gate: REFUSED" in lines
    assert "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40" in lines
    assert main(["info", "--allow-unsupported", str(path)]) == 0


def test_mirror_damage_image_selects_mirror_1_and_reports_it(capsys):
    path = image("m1_mirror_damage")
    selection = read("m1_mirror_damage")
    assert selection.selected.mirror == 1
    assert selection.disagreements == ["mirror 0 invalid: magic mismatch, csum mismatch"]
    assert main(["info", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    generation = selection.selected.fields["generation"]
    assert f"selected: mirror 1 (generation {generation})" in lines
    assert "  mirror 0 invalid: magic mismatch, csum mismatch" in lines
    assert "kernel would mount: mirror 0 (invalid: magic mismatch, csum mismatch)" in lines


def test_foreign_mirror_image_keeps_the_primary_and_reports_the_residue(capsys):
    """Mirror 1 holds m1_sha256_bgt's copy at generation 1000 (sha256 csum, other fsid)."""
    path = image("m1_foreign_mirror")
    selection = read("m1_foreign_mirror")
    primary, mirror1 = selection.copies[0], selection.copies[1]
    assert primary.valid and mirror1.valid
    assert mirror1.fields["generation"] == 1000 > primary.fields["generation"]
    assert mirror1.fields["csum_type"] == csum.SHA256
    assert mirror1.fields["fsid"] != primary.fields["fsid"]
    assert selection.selected is primary
    assert selection.foreign == [mirror1]
    assert main(["info", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    foreign_fsid = str(uuid.UUID(bytes=mirror1.fields["fsid"]))
    assert f"selected: mirror 0 (generation {primary.fields['generation']})" in lines
    assert (
        f"  mirror 1 foreign superblock at 67108864 (fsid {foreign_fsid}, generation 1000)" in lines
    )
    assert f"fsid: {uuid.UUID(bytes=primary.fields['fsid'])}" in lines
    assert not any(line.startswith("kernel would mount") for line in lines)
