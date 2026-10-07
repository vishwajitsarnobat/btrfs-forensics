"""Fetch the btrfs images of fkie-cad/hide-and-seek-dataset, pinned by SHA-256 (plan.md M6d).

    uv run python corpus/hide_and_seek.py          # fetch what is missing, check everything
    uv run python corpus/hide_and_seek.py --check  # check what is there, fetch nothing

The dataset of Schwietert & Hilgert 2025 hides data in btrfs by hand, independently of us, so it
tests the hiding detector against a planter we did not write (docs/research/fishy-btrfs.md §4.2).
It has **no licence**: the images may be downloaded and read but not redistributed, so they are
fetched by URL into the gitignored images/hide-and-seek/ and never committed. Each `.gz` is
checked against the SHA-256 pinned below before it is unpacked, and each image after. The images
are unpacked sparsely: all-zero 64 KiB blocks become holes, so 4.25 GiB of images take about
40 MiB of disk.

The tests that read these images skip when they are absent. Nothing here needs root.
"""

import argparse
import gzip
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "hide-and-seek"
COMMIT = "decd14bd9cb39a978a3a2ce0d2a0d472ac88b703"
BASE = f"https://raw.githubusercontent.com/fkie-cad/hide-and-seek-dataset/{COMMIT}"
BLOCK = 1 << 16
ZEROS = bytes(BLOCK)

# name: (path in the repository, SHA-256 of the .gz as published, SHA-256 of the image)
IMAGES = {
    "btrfs_superblock": (
        "scenario_6_reserved_space/btrfs_superblock/image.img.gz",
        "a0aa6234912063feff0c5dc9435b2148483ee134b0a45f41a40245511474ee79",
        "3ffb8a3501d2c032e9c0fd1fc3809da2df594db8fd0817fbe6e0b395d3b84dfa",
    ),
    "btrfs_inode_reserved": (
        "scenario_6_reserved_space/btrfs_inode_reserved/image.img.gz",
        "f3c62ae38842d51ac02f3aad4935e7370a2d44226b334bc00bff286450cc19e1",
        "5092d5cb33c3fbdb2cb8bf9bd367ab6db7d218dfeaccb1666fb7d024f8be1ab1",
    ),
    "btrfs_hidden_snapshot": (
        "scenario_7_snapshots/btrfs_hidden_snapshot/image.img.gz",
        "21f46693d87867c26903d4e68d6cdc0ee329f5faf37f3c0bdbb495cf5dd8742b",
        "fc6be98d943d0c3d323e8af1910a7d5dd0ff68b20fd219e352fe1907ab1082d7",
    ),
    "btrfs_raid1_slack_dev1": (
        "scenario_9_pooled_storage_slack/btrfs_raid1_slack/dev1.img.gz",
        "8892ca8458ce7ecfe66387eb9cc936a4c677a6580575a68a7bb1bb698b51e8a4",
        "aad4405fd3ebe5232fdc36547741198cc2be70da3ef532bd027605aef137b4dd",
    ),
    "btrfs_raid1_slack_dev2": (
        "scenario_9_pooled_storage_slack/btrfs_raid1_slack/dev2.img.gz",
        "b174cac412db0a4774da80576a64e91fd378dd9181c6ffcd810f8cbc05619778",
        "c630ffe973cf32cb832d7aadea20b77d724ba4abf3574508e34dadbd4c435a68",
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def image_path(name: str) -> Path:
    return OUT / f"{name}.img"


def fetch(name: str) -> None:
    source, gz_sha, img_sha = IMAGES[name]
    archive = OUT / f"{name}.img.gz"
    if not (archive.exists() and sha256(archive) == gz_sha):
        part = archive.with_suffix(".gz.part")
        with urllib.request.urlopen(f"{BASE}/{source}", timeout=60) as response:
            with part.open("wb") as f:
                while block := response.read(1 << 20):
                    f.write(block)
        if sha256(part) != gz_sha:
            part.unlink()
            sys.exit(f"{name}: SHA-256 of {source} does not match the pinned value")
        part.rename(archive)
    target = image_path(name)
    part = target.with_suffix(".img.part")
    with gzip.open(archive, "rb") as src, part.open("wb") as out:
        size = 0
        while block := src.read(BLOCK):
            if block != ZEROS[: len(block)]:
                out.write(block)
            else:
                out.seek(len(block), os.SEEK_CUR)
            size += len(block)
        out.truncate(size)
    if sha256(part) != img_sha:
        part.unlink()
        sys.exit(f"{name}: SHA-256 of the unpacked image does not match the pinned value")
    part.rename(target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="check the images, fetch nothing")
    args = parser.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, (_, _, img_sha) in IMAGES.items():
        path = image_path(name)
        if path.exists() and sha256(path) == img_sha:
            print(f"have   {name}")
            continue
        if args.check:
            print(f"{'BAD' if path.exists() else 'absent'} {name}")
            bad += 1
            continue
        path.unlink(missing_ok=True)
        fetch(name)
        print(f"fetched {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
