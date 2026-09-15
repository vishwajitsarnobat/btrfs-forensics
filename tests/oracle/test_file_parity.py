"""File bytes: btrfska against dissect.btrfs streams and the guest-printed SHA-256s (plan.md §3.5).

For every root set of each image (the backup roots by generation, then the current state), every
subvolume and snapshot that set's root tree names, and every regular file of those trees:
- btrfska's bytes (extents.read_file) must be complete;
- they must equal dissect.btrfs 1.10's stream bytes. dissect reads the current root tree only, so
  for a backup root set its root tree is swapped for that set's (`Btrfs._root_tree`, test-only use
  of a private attribute) and its tree cache cleared;
- the regular files dissect lists by walking the directories must be the ones btrfska inventories;
- where the s01 guest printed a SHA-256 (keep.txt, deleted_big.txt, deleted_inline.txt) or the
  scenario script fixes the content (churn_N holds "genN\\n"), the bytes must match.
Skipped when dissect.btrfs (dev group) or an image is absent.
"""

import hashlib
import re

import pytest

pytest.importorskip("dissect.btrfs")

from dissect.btrfs import Btrfs  # noqa: E402
from dissect.btrfs.btrfs import Subvolume  # noqa: E402
from dissect.btrfs.tree import BTree  # noqa: E402

from btrfska.substrate import ondisk  # noqa: E402
from btrfska.substrate.extents import read_file  # noqa: E402
from btrfska.substrate.fs import open_filesystem  # noqa: E402
from btrfska.substrate.image import open_image  # noqa: E402
from btrfska.substrate.roots import root_sets, subvolumes  # noqa: E402
from btrfska.substrate.tree import fs_tree_inventory  # noqa: E402
from tests.helpers import REPO_ROOT, SCENARIOS  # noqa: E402

SCRIPT_CONTENT = {f"churn_{i}": b"gen%d\n" % i for i in range(1, 7)}  # s01.guest.sh


def image_path(name: str):
    return REPO_ROOT / "sandbox.img" if name == "sandbox" else SCENARIOS / f"{name}.img"


def guest_sha256s(name: str) -> dict[str, str]:
    """file name -> SHA-256 printed by the guest (`sha256sum $MNT/sv1/*.txt` in s01.guest.sh)."""
    log = SCENARIOS / f"{name}.log"
    if not log.exists():
        return {}
    pattern = re.compile(r"^([0-9a-f]{64})  /mnt/\S*?([^/\s]+)$", re.M)
    return {file: digest for digest, file in pattern.findall(log.read_text(errors="replace"))}


def _dissect_files(subvolume) -> set[int]:
    """Regular-file inode numbers reachable from the subvolume's root directory, in it only."""
    found, stack, seen = set(), [subvolume.root], set()
    while stack:
        directory = stack.pop()
        for name, node in directory.iterdir():
            if name in (".", "..") or node.subvolume.objectid != subvolume.objectid:
                continue
            if node.inum in seen:
                continue
            seen.add(node.inum)
            if node.is_dir():
                stack.append(node)
            elif node.is_file():
                found.add(node.inum)
    return found


def parity_rows(name: str) -> list[dict]:
    """One row per (root set, subvolume, regular file) with btrfska, dissect and expected hashes."""
    path = image_path(name)
    if not path.exists():
        pytest.skip(f"{path.name} absent")
    guest = guest_sha256s(name)
    rows = []
    with open_image(path) as img, open(path, "rb") as fh:
        fs = open_filesystem(img)
        no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
        for root_set in root_sets(fs.fields):
            dissect_fs = Btrfs(fh)
            dissect_fs._root_tree = BTree(dissect_fs, root_offset=root_set.trees["root"].bytenr)
            dissect_fs._open_tree.cache_clear()
            subvols, problems = subvolumes(fs.reader, root_set)
            assert problems == ()
            for subvol in subvols:
                assert subvol.root is not None, subvol
                inventory = fs_tree_inventory(fs.reader, subvol.root.bytenr, subvol.root.expect())
                files = {inode: e for inode, e in inventory.items() if e.get("kind") == "file"}
                dissect_subvol = Subvolume(dissect_fs, subvol.id)
                assert _dissect_files(dissect_subvol) == set(files), (root_set.source, subvol.id)
                for inode, entry in sorted(files.items()):
                    ours = read_file(fs.reader, subvol.root, inode, no_holes=no_holes)
                    data = b"".join(ours.chunks()) if ours.complete else None
                    theirs = dissect_subvol.inode(inode).open().read()
                    expected = guest.get(entry.get("name"))
                    if entry.get("name") in SCRIPT_CONTENT:
                        expected = hashlib.sha256(SCRIPT_CONTENT[entry["name"]]).hexdigest()
                    rows.append({
                        "root_set": root_set.source,
                        "subvolume": subvol.id,
                        "inode": inode,
                        "name": entry.get("name"),
                        "size": entry.get("size"),
                        "complete": ours.complete,
                        "errors": ours.errors + tuple(e.error_kind for e in ours.extents
                                                      if e.error_kind),
                        "compression": sorted({e.compression for e in ours.extents
                                               if e.compression}),
                        "btrfska": data and hashlib.sha256(data).hexdigest(),
                        "dissect": hashlib.sha256(theirs).hexdigest(),
                        "expected": expected,
                    })  # fmt: skip
    return rows


IMAGES = [
    pytest.param("sandbox", marks=pytest.mark.sandbox),
    pytest.param("m1_xxhash", marks=pytest.mark.vm),
    pytest.param("m1_lzo", marks=pytest.mark.vm),
    pytest.param("m1_zlib", marks=pytest.mark.vm),
]


@pytest.mark.parametrize("name", IMAGES)
def test_every_file_matches_dissect_and_ground_truth(name):
    rows = parity_rows(name)
    assert rows, "no files compared"
    failures = [
        row
        for row in rows
        if not row["complete"]
        or row["btrfska"] != row["dissect"]
        or (row["expected"] is not None and row["btrfska"] != row["expected"])
    ]
    assert failures == []


@pytest.mark.parametrize("name", IMAGES[1:])
def test_s01_deleted_files_are_read_from_snapshot_257_in_every_root_set(name):
    rows = parity_rows(name)
    guest = guest_sha256s(name)
    assert set(guest) == {"keep.txt", "deleted_big.txt", "deleted_inline.txt"}
    sets = {row["root_set"] for row in rows}
    assert len(sets) == 5  # four backup roots and the current state
    for root_set in sets:
        snapshot = {r["name"]: r["btrfska"] for r in rows if r["root_set"] == root_set
                    and r["subvolume"] == 257}  # fmt: skip
        assert snapshot == guest, root_set
        live = {r["name"] for r in rows if r["root_set"] == root_set and r["subvolume"] == 256}
        assert live == {"keep.txt", *SCRIPT_CONTENT}


@pytest.mark.sandbox
def test_sandbox_backup_generations_hold_the_deleted_files():
    rows = parity_rows("sandbox")
    assert [(r["root_set"], r["name"], r["size"]) for r in rows] == [
        ("backup:11", "target_file.txt", 31),
        ("backup:13", "large_target.txt", 5242880),
    ]
