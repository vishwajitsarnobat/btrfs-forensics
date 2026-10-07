"""EXP-021: the hiding detector on planted images: detection, stability and false positives.

The hypotheses and predictions are in experiments/EXP-021.md §1, the method in §2. Every plant is
made by a corpus/mutate.py function (plan.md M6d, with the keyword arguments of M6e) on a copy of
a clean corpus image under images/scratch/, read once by `hiding.detect.detect` and deleted; the
corpus images themselves are only read.

Usage, from the repo root (the guest parts behind the heavy-job lock):
  uv run python experiments/exp021.py detect [BASE...]          # every plant on every base
  uv run python experiments/exp021.py clean                     # the kept clean images
  uv run python experiments/exp021.py stability [--runs 5]      # plant, check, mount and use
  uv run python experiments/exp021.py build [--builds 5]        # fresh guest builds, detected
  uv run python experiments/exp021.py table
All take `--out DIR` (default images/scratch/exp/EXP-021); results go to DIR/<part>.jsonl, and
`clean`, `stability` and `build` append.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import random
import re
import statistics
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from btrfska.hiding.areas import GATED
from btrfska.hiding.detect import TECHNIQUES, detect
from btrfska.scan.roots import discover_image
from btrfska.substrate import items, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import is_subvolume_tree
from btrfska.substrate.roots import find_root_set, subvolumes
from btrfska.substrate.slack import slack_range

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-021"
SCENARIOS = REPO / "images" / "scenarios"
HIDE_AND_SEEK = REPO / "images" / "hide-and-seek"
PINNED = REPO / "corpus" / "vm" / "pinned.sh"
SEED = 21
BASES = ("m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m6_datacsum", "s01_discard_none_r1",
         "m3_wide", "m4_deep")  # fmt: skip
PLANTED_ROWS = {"m4_planted_slack", "m6_hidden_snapshot"}  # and every m6_hide_* row
RECIPES = ("s01_discard_none_r1", "s01_discard_async_r1", "s01_discard_sync_r1", "m1_sha256_bgt",
           "m1_blake2b", "m2_logtree", "m3_wide", "m4_deep", "m5_delsubvol", "m5_reuse",
           "m6_datacsum", "m6_hidden_snapshot")  # fmt: skip
HEADER, ITEM = ondisk.HEADER.size, ondisk.ITEM.size
CSUM = ondisk.CSUM_SIZE
DEVICE_LARGE = 1 << 20  # the largest device-slack payload planted (capacity is reported)
NSEC_NAMES = ("atime_nsec", "ctime_nsec", "mtime_nsec", "otime_nsec")


def load_mutate():
    spec = importlib.util.spec_from_file_location("mutate", REPO / "corpus" / "mutate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load_mutate()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Plants: one technique, one payload, its patches and where the planted bytes are
# ---------------------------------------------------------------------------
@dataclass
class Plant:
    technique: str
    label: str
    patches: dict = field(default_factory=dict)
    spans: list = field(default_factory=list)  # [start, end) of the planted bytes on the image
    in_scope: bool = True  # False: the rule cannot see this payload by design (EXP-021 §1 H1)
    capacity: int | None = None  # bytes the area holds, where it is a fixed area
    area: str = ""  # which area of the technique, where it has several
    expect: dict = field(default_factory=dict)  # technique-specific location facts
    na: str = ""  # why the base cannot take this plant


def payload(base: str, technique: str, label: str, size: int) -> bytes:
    """`size` seeded bytes, none zero, so every planted byte is visible and its place known."""
    rng = random.Random(f"{SEED}:{base}:{technique}:{label}")
    return bytes(b or 1 for b in rng.randbytes(size))


def rng_for(base: str, technique: str, label: str) -> random.Random:
    return random.Random(f"{SEED}:{base}:{technique}:{label}:place")


def changed_runs(img, offset: int, data: bytes, skip: int = 0) -> list[tuple[int, int]]:
    """[start, end) image offsets of the bytes of patch (offset, data) that differ from the
    image, its first `skip` bytes (a checksum field) left out."""
    old = bytes(img.mmap[offset : offset + len(data)])
    runs, start = [], None
    for i in range(skip, len(data) + 1):
        differs = i < len(data) and old[i] != data[i]
        if differs and start is None:
            start = i
        elif not differs and start is not None:
            runs.append((offset + start, offset + i))
            start = None
    return runs


def block_spans(img, patches: dict, size: int, skip: int = CSUM) -> list[tuple[int, int]]:
    """Changed bytes of every patch of `size` bytes (tree blocks, or data sectors with
    `skip` 0), the first `skip` bytes (the checksum of a tree block) left out."""
    spans = []
    for offset, data in patches.items():
        if len(data) == size:
            spans += changed_runs(img, offset, data, skip)
    return spans


def attempt(planter, *args):
    """(patches, "") of a planter, or (None, why) when it refuses: the base cannot take it."""
    try:
        result = planter(*args)
    except SystemExit as exc:
        return None, str(exc.code)
    return (result[0] if isinstance(result, tuple) else result), ""


def sb_copies(src_path: Path) -> list[int]:
    size = src_path.stat().st_size
    offsets = [ondisk.sb_offset(m) for m in range(ondisk.SUPER_MIRROR_MAX)]
    return [o for o in offsets if o + ondisk.SUPER_INFO_SIZE < size]


def superblock_plants(base: str, path: Path, img, fs) -> list[Plant]:
    plants = []
    size = img.size
    with open(path, "rb") as src:
        for name, (start, end, _) in M.SB_FIELDS.items():
            technique = "superblock_padding" if name == "padding" else "superblock_reserved"
            n = end - start
            variants = [(1, 0), (1, n - 1), (n, 0)]
            if name in ("reserved", "padding"):
                rng = rng_for(base, technique, name)
                length = rng.randint(2, n - 1)
                variants.insert(2, (length, rng.randint(0, n - length)))
            for length, at in variants:
                label = f"{name} {length}@{at}"
                data = payload(base, technique, label, length)
                patches, why = attempt(M.plant_sb_field, src, size, name, data, at)
                plant = Plant(technique, label, capacity=n, area=name, na=why)
                if patches:
                    plant.patches = patches
                    plant.spans = [(o + start + at, o + start + at + length) for o in patches]
                plants.append(plant)
        array = ondisk.SUPERBLOCK.offset("sys_chunk_array")
        full = ondisk.SYSTEM_CHUNK_ARRAY_SIZE
        primary = ondisk.SUPER_INFO_OFFSET
        free = M.chunk_array_free(bytes(img.mmap[primary : primary + ondisk.SUPER_INFO_SIZE]))
        rng = rng_for(base, "sys_chunk_array_slack", "array")
        length = rng.randint(2, full - free - 1)
        variants = [(1, free), (1, full - 1), (length, rng.randint(free, full - length)),
                    (full - free, free)]  # fmt: skip
        for length, at in variants:
            label = f"array {length}@{at}"
            data = payload(base, "sys_chunk_array_slack", label, length)
            patches, why = attempt(M.plant_chunk_array_slack, src, size, data, at)
            plant = Plant("sys_chunk_array_slack", label, capacity=full - free, na=why)
            if patches:
                plant.patches = patches
                plant.spans = [(o + array + at, o + array + at + length) for o in patches]
            plants.append(plant)
        roots = sb.backup_roots(fs.fields)
        newest = [r["slot"] for r in roots if r["tree_root_gen"] == fs.fields["generation"]]
        base_roots, length = ondisk.SUPERBLOCK.offset("super_roots"), ondisk.ROOT_BACKUP.size
        for slot in sorted(r["slot"] for r in roots if r["slot"] not in newest):
            patches, why = attempt(M.plant_backup_roots, src, size, slot)
            plant = Plant("backup_root_divergence", f"slot {slot} over the newest", na=why)
            if patches:
                at = base_roots + newest[0] * length
                plant.patches = patches
                plant.spans = [(o + at, o + at + length) for o in patches]
            plants.append(plant)
    slot = ondisk.sb_offset(1)
    if slot + ondisk.SUPER_INFO_SIZE <= size:
        magic = ondisk.SUPERBLOCK.offset("magic")
        for length, at in ((1, magic), (72, 0), (4096, 0)):
            label = f"mirror 1 slot {length}@{at}"
            data = payload(base, "superblock_slot", label, length)
            if length == 1 and data == bytes(img.mmap[slot + at : slot + at + 1]):
                data = bytes([data[0] ^ 0x80])
            plants.append(Plant("superblock_slot", label, {slot + at: data},
                                [(slot + at, slot + at + length)], capacity=4096,
                                expect={"slot": slot}))  # fmt: skip
    return plants


def boot_plants(base: str, path: Path, img) -> list[Plant]:
    plants = []
    with open(path, "rb") as src:
        for (lo, hi), area in zip(
            M.PRE_SB_AREAS, ("first 64 KiB", "rest of the first MiB"), strict=True
        ):
            rng = rng_for(base, "pre_superblock", str(lo))
            some = rng.randint(2, 4096)
            for length, at in ((1, lo), (1, hi - 1), (some, rng.randint(lo, hi - some)),
                               (hi - lo, lo)):  # fmt: skip
                label = f"{area} {length}@{at}"
                data = payload(base, "pre_superblock", label, length)
                patches, why = attempt(M.plant_pre_sb, src, img.size, data, at)
                plant = Plant("pre_superblock", label, capacity=hi - lo, area=area, na=why)
                if patches:
                    plant.patches, plant.spans = patches, [(at, at + length)]
                plants.append(plant)
    return plants


def slack_plants(base: str, path: Path, img, fs) -> list[Plant]:
    nodesize = fs.reader.ctx.nodesize
    targets = M.slack_targets(fs)
    leaf_only = "node" not in targets
    slacks = []
    for node in targets.values():
        for copy in node.copies:
            start, end = slack_range(img.mmap[copy.physical : copy.physical + nodesize], nodesize)
            slacks.append(end - start)
    room = min(slacks)
    rng = rng_for(base, "node_slack", "slack")
    some = rng.randint(2, max(2, room - 1))
    kinds = "leaf" if leaf_only else "root node and first leaf"
    plants = []
    for length, margin, from_end in ((1, 0, False), (1, 0, True),
                                     (some, rng.randint(0, room - some), False),
                                     (room, 0, False)):  # fmt: skip
        label = f"{kinds} {length}@{'end' if from_end else margin}"
        data = payload(base, "node_slack", label, length)
        patches, why = attempt(M.plant_slack, path, data, margin, from_end, leaf_only)
        plant = Plant("node_slack", label, capacity=room, na=why)
        if patches:
            plant.patches, plant.spans = patches, block_spans(img, patches, nodesize)
        plants.append(plant)
    # A payload behind a copy of the leaf's own last item header: it reads as a stale item.
    leaf = M.slack_targets(fs, leaf_only=True)["leaf"]
    first = leaf.copies[0].physical
    block = img.mmap[first : first + nodesize]
    count = ondisk.HEADER.unpack_from(block)["nritems"]
    header = bytes(block[HEADER + (count - 1) * ITEM : HEADER + count * ITEM])
    data = header + payload(base, "node_slack", "stale header", 32)
    patches, why = attempt(M.plant_slack, path, data, 0, False, True)
    plant = Plant("node_slack", "leaf, behind a stale item header", in_scope=False, na=why)
    if patches:
        plant.patches, plant.spans = patches, block_spans(img, patches, nodesize)
    plants.append(plant)
    return plants


def nsec_rule(values: list[int]) -> bool:
    """Whether hiding/trees.py's timestamp rule reports these four values."""
    printable = all(all(0x20 <= b < 0x7F for b in v.to_bytes(4, "little")) for v in values)
    return any(v >= 10**9 for v in values) or (len(set(values)) == 4 and printable)


def inode_plants(base: str, path: Path, img, fs) -> list[Plant]:
    nodesize = fs.reader.ctx.nodesize
    node, item = M.first_file_inode(fs)
    plants = []
    rng = rng_for(base, "inode_reserved", "reserved")
    some = rng.randint(2, 31)
    for length, at in ((1, 0), (1, 31), (some, rng.randint(0, 32 - some)), (32, 0)):
        label = f"{length}@{at}"
        data = payload(base, "inode_reserved", label, length)
        patches, why = attempt(M.plant_inode_reserved, path, data, at)
        plant = Plant("inode_reserved", label, capacity=32, na=why)
        if patches:
            plant.patches, plant.spans = patches, block_spans(img, patches, nodesize)
        plants.append(plant)
    whole = plants[-1]
    if whole.patches:  # the same plant in one copy of the leaf: the copies now differ
        for physical, data in whole.patches.items():
            copy = next(c for c in node.copies if c.physical == physical)
            spans = changed_runs(img, physical, data, CSUM)
            plants.append(Plant(
                "copy_divergence", f"inode reserved 32@0 in mirror {copy.mirror} only",
                {physical: data}, spans,
                expect={"bytenr": node.logical},
            ))  # fmt: skip
    fields = ondisk.INODE_ITEM.unpack_from(item.data)
    old = b"".join(fields[name].to_bytes(4, "little") for name in NSEC_NAMES)
    rng = rng_for(base, "timestamp_nsec", "nsec")
    below = b"".join(rng.randrange(1 << 24, 10**9).to_bytes(4, "little") for _ in range(4))
    printable = b"".join(bytes(rng.randint(0x21, 0x7E) for _ in range(3)) +
                         bytes([rng.randint(0x21, 0x3A)]) for _ in range(4))  # fmt: skip
    variants = [
        ("16 random bytes", payload(base, "timestamp_nsec", "random", 16), 0),
        ("1 byte, top byte of atime_nsec, 0xF0", b"\xf0", 3),
        ("1 byte, top byte of atime_nsec, 0x01", b"\x01", 3),
        ("1 byte, low byte of atime_nsec", payload(base, "timestamp_nsec", "low", 1), 0),
        ("four values below 10^9", below, 0),
        ("four printable values below 10^9", printable, 0),
    ]
    for label, data, at in variants:
        new = bytearray(old)
        new[at : at + len(data)] = data
        values = [int.from_bytes(new[4 * i : 4 * i + 4], "little") for i in range(4)]
        patches, why = attempt(M.plant_nsec, path, data, at)
        plant = Plant("timestamp_nsec", label, in_scope=nsec_rule(values), capacity=16, na=why)
        if patches:
            plant.patches, plant.spans = patches, block_spans(img, patches, nodesize)
        plants.append(plant)
    leaf = list(M.fs_leaves(fs))[-1]
    lowest = min(i.offset for i in leaf.items)
    room = lowest - (len(leaf.items) + 1) * ITEM
    rng = rng_for(base, "string_item", "item")
    for length in (1, rng.randint(2, max(2, room - 1)), room):
        label = f"{length} bytes"
        data = payload(base, "string_item", label, length)
        patches, why = attempt(M.plant_string_item, path, data)
        plant = Plant("string_item", label, capacity=room, na=why)
        if patches:
            at = HEADER + lowest - length
            plant.patches = patches
            plant.spans = [(c.physical + at, c.physical + at + length) for c in leaf.copies]
        plants.append(plant)
    return plants


def file_slack_plants(base: str, path: Path, img, fs) -> list[Plant]:
    ss = fs.reader.ctx.sectorsize
    refs, inodes = [], {}
    for node in M.fs_leaves(fs):
        for item in node.items:
            if item.key.type == ondisk.ITEM_KEYS["INODE_REF"]:
                for ref in items.inode_refs(item.data):
                    refs.append((ref["name"], item.key.offset, item.key.objectid))
            elif item.key.type == ondisk.ITEM_KEYS["INODE_ITEM"]:
                inodes[item.key.objectid] = items.inode_item(item.data)
    name = None
    why = "no regular file in the fs tree with a tail in an uncompressed regular extent"
    for candidate, parent, objectid in sorted(refs, key=lambda r: (r[1], r[0])):
        inode = inodes.get(objectid)
        if inode and inode["mode"] & 0o170000 == 0o100000 and inode["size"] % ss:
            done, _ = attempt(M.plant_file_slack, path, candidate, b"\1", False, 0, parent)
            if done:
                name, size = candidate, inode["size"]
                break
    if name is None:
        return [Plant("file_slack", "any", na=why)]
    tail = ss - size % ss
    rng = rng_for(base, "file_slack", name)
    some = rng.randint(2, max(2, tail - 1))
    plants = []
    for length, at, keep in ((1, 0, False), (1, tail - 1, False),
                             (some, rng.randint(0, tail - some), False), (tail, 0, False),
                             (tail, 0, True)):  # fmt: skip
        label = f"{name} {length}@{at}" + (", data checksum kept" if keep else "")
        data = payload(base, "file_slack", label, length)
        made, why = attempt(M.plant_file_slack, path, name, data, keep, at, parent)
        plant = Plant("file_slack", label, capacity=tail, na=why)
        if made:
            plant.patches, plant.spans = made, block_spans(img, made, ss, skip=0)
            plant.expect = {"csum": "matches_zeroed" if keep else "covers_hidden"}
        plants.append(plant)
    return plants


def device_plants(base: str, path: Path, img, fs) -> list[Plant]:
    free, _, _ = M.device_free(img, fs)
    free = [(lo, hi) for lo, hi in free if hi > lo]
    if not free:
        return [Plant("device_slack", "any", na="nothing past the last device extent")]
    capacity = sum(hi - lo for lo, hi in free)
    lo, hi = max(free, key=lambda piece: piece[1] - piece[0])
    rng = rng_for(base, "device_slack", "device")
    some = rng.randint(2, min(1 << 16, hi - lo))
    variants = [(1, free[0][0]), (1, free[-1][1] - 1), (some, rng.randint(lo, hi - some)),
                (min(DEVICE_LARGE, hi - lo), lo)]  # fmt: skip
    plants = []
    for length, at in variants:
        label = f"{length}@{at}"
        data = payload(base, "device_slack", label, length)
        made, why = attempt(M.plant_device_slack, path, data, at)
        plant = Plant("device_slack", label, capacity=capacity, na=why)
        if made:
            plant.patches, plant.spans = made, [(at, at + length)]
        plants.append(plant)
    return plants


def plants_for(base: str, path: Path) -> list[Plant]:
    with open_image(path) as img:
        fs = open_filesystem(img)
        plants = superblock_plants(base, path, img, fs) + boot_plants(base, path, img)
        plants += slack_plants(base, path, img, fs) + inode_plants(base, path, img, fs)
        return plants + file_slack_plants(base, path, img, fs) + device_plants(base, path, img, fs)


# ---------------------------------------------------------------------------
# Running the detector, and judging a plant
# ---------------------------------------------------------------------------
def run_detector(path: Path):
    with open_image(path) as img:
        fs = open_filesystem(img, allow_unsupported=True)

        def history():
            return [entry.chunk_map for entry in discover_image(img, fs).discovery.chunk_maps]

        found, summary = detect(img, fs, history)
        return found, summary, units(img, fs, summary)


def planted_copy(base: Path, patches: dict, work: Path) -> Path:
    """A copy of `base` (a reflink where the filesystem has them) with `patches` written into
    it. Only the copy is written; it lies under images/scratch/."""
    work.mkdir(parents=True, exist_ok=True)
    target = work / "planted.img"
    if target.resolve() == base.resolve() or target.name == "sandbox.img":
        raise SystemExit("refusing to write over the base image")
    target.unlink(missing_ok=True)
    subprocess.run(["cp", "--reflink=auto", "--", str(base), str(target)], check=True)
    with open(target, "r+b") as f:
        for offset, data in patches.items():
            os.pwrite(f.fileno(), data, offset)
    return target


def covers(finding, plant: Plant) -> bool:
    starts = [lo for lo, _ in plant.spans]
    if finding.technique == "copy_divergence":  # the copies differ first in their checksums
        return finding.detail["bytenr"] == plant.expect["bytenr"]
    if finding.technique == "device_slack":
        return any(a <= s < b for a, b in finding.detail["runs"] for s in starts)
    return any(finding.physical <= s < finding.physical + finding.length for s in starts)


def exact(finding, plant: Plant) -> bool | None:
    """Does the finding point at the planted bytes and no others? None: not a byte-area rule."""
    inside = [(lo, hi) for lo, hi in plant.spans
              if finding.physical <= lo < finding.physical + finding.length]  # fmt: skip
    planted = sum(hi - lo for lo, hi in inside)
    if finding.technique == "string_item":
        return [(finding.physical, finding.physical + finding.length)] == inside
    if finding.technique == "device_slack":
        return finding.nonzero == planted
    if finding.technique == "superblock_slot":
        return finding.nonzero == planted  # the rest of the overwritten superblock counts too
    if "first_nonzero" not in finding.detail:
        return None
    return finding.detail["first_nonzero"] == min(lo for lo, _ in inside) and (
        finding.nonzero == planted)  # fmt: skip


def judge(plant: Plant, found: list) -> dict:
    mine = [f for f in found if f.technique == plant.technique]
    covering = [f for f in mine if covers(f, plant)]
    exacts = [exact(f, plant) for f in covering]
    verdict = {
        "detected": bool(mine),
        "covers": bool(covering),
        "exact": None if not covering or None in exacts else all(exacts),
        "findings": len(mine),
        "covering": len(covering),
        "others": dict(Counter(f.technique for f in found if f.technique != plant.technique)),
    }
    if plant.technique == "file_slack" and covering:
        verdict["csum"] = covering[0].detail["csum"]
    return verdict


def detect_part(args) -> None:
    out = args.out / "detect.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for base in args.bases or BASES:
            path = SCENARIOS / f"{base}.img"
            before = sha256(path)
            with open_image(path) as img:
                csum_type = open_filesystem(img).fields["csum_type"]
            clean, _, _ = run_detector(path)
            plants = plants_for(base, path)
            counts = Counter()
            for plant in plants:
                record = {"base": base, "csum_type": csum_type, "technique": plant.technique,
                          "label": plant.label, "in_scope": plant.in_scope,
                          "capacity": plant.capacity, "area": plant.area,
                          "bytes": sum(len(d) for d in plant.patches.values()),
                          "planted": sum(hi - lo for lo, hi in plant.spans)}  # fmt: skip
                if plant.na:
                    record["na"] = plant.na
                else:
                    work = args.out / "work"
                    copy = planted_copy(path, plant.patches, work)
                    try:
                        found, _, _ = run_detector(copy)
                    finally:
                        copy.unlink()
                    record |= judge(plant, found)
                    if plant.expect.get("csum"):
                        record["csum_expected"] = plant.expect["csum"]
                    counts[record["detected"]] += 1
                f.write(json.dumps(record) + "\n")
            after = sha256(path)
            f.write(
                json.dumps(
                    {
                        "base": base,
                        "record": "base",
                        "clean_findings": len(clean),
                        "sha256_before": before,
                        "unchanged": before == after,
                    }
                )
                + "\n"
            )
            f.flush()
            print(base, f"{len(plants)} plants", dict(counts), "unchanged", before == after)


# ---------------------------------------------------------------------------
# What a rule examined, per technique (the denominator of the false-positive rate)
# ---------------------------------------------------------------------------
def dir_entries(fs) -> int:
    root_set = find_root_set(fs.fields, "current")
    subvols, _ = subvolumes(fs.reader, root_set)
    count = 0
    for sv in subvols:
        if not is_subvolume_tree(sv.id) or not sv.root:
            continue
        for node in M.fs_leaves(fs, sv.id):
            count += sum(i.key.type == ondisk.ITEM_KEYS["DIR_INDEX"] for i in node.items)
    return count


def units(img, fs, summary: dict) -> dict:
    copies = summary["superblock"]["copies"]
    fields = fs.fields
    gated = sum(end - start for _, start, end, flag in GATED
                if not fields["incompat_flags"] & ondisk.INCOMPAT[flag])  # fmt: skip
    t, device = summary["trees"], summary["device"]
    total = min(device["total_bytes"], img.size)
    return {
        "superblock_reserved": copies * (199 + gated + 4 * 42),
        "superblock_padding": copies * 565,
        "sys_chunk_array_slack": copies * (2048 - fields["sys_chunk_array_size"]),
        "superblock_slot": sum(ondisk.sb_offset(m) + 4096 <= total for m in range(3)),
        "pre_superblock": min(img.size, 1 << 20) - 4096,
        "backup_root_divergence": 1,
        "node_slack": t["copies"],
        "copy_divergence": t["copies"] - t["blocks"],
        "inode_reserved": t["inodes"],
        "timestamp_nsec": t["inodes"],
        "string_item": t["blocks"],
        "file_slack": t["files_checked"],
        "device_slack": max(0, total - device["last_extent_end"]) + img.size - total,
        "hidden_name": dir_entries(fs),
    }


UNIT_NAMES = {
    "superblock_reserved": "bytes", "superblock_padding": "bytes", "sys_chunk_array_slack": "bytes",
    "superblock_slot": "slots", "pre_superblock": "bytes", "backup_root_divergence": "superblocks",
    "node_slack": "block copies", "copy_divergence": "extra copies", "inode_reserved": "inodes",
    "timestamp_nsec": "inodes", "string_item": "blocks", "file_slack": "file tails",
    "device_slack": "bytes", "hidden_name": "directory entries",
}  # fmt: skip


def finding_record(f) -> dict:
    return {"technique": f.technique, "where": f.where, "nonzero": f.nonzero,
            "evidence": f.evidence[:300]}  # fmt: skip


def kept_clean() -> list[Path]:
    with (REPO / "corpus" / "manifest.tsv").open() as f:
        names = [row["name"] for row in csv.DictReader(f, delimiter="\t")]
    names = [n for n in names if not n.startswith("m6_hide_") and n not in PLANTED_ROWS]
    return [SCENARIOS / f"{n}.img" for n in names if (SCENARIOS / f"{n}.img").exists()]


def clean_part(args) -> None:
    images = [*kept_clean(), REPO / "sandbox.img", HIDE_AND_SEEK / "btrfs_raid1_slack_dev1.img"]
    planted = [SCENARIOS / "m6_hidden_snapshot.img",
               *(HIDE_AND_SEEK / f"{n}.img" for n in ("btrfs_superblock", "btrfs_inode_reserved",
                                                       "btrfs_hidden_snapshot",
                                                       "btrfs_raid1_slack_dev2"))]  # fmt: skip
    out = args.out / "clean.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a") as f:
        for kind, group in (("kept", images), ("planted", planted)):
            for path in group:
                if not path.exists():
                    print("absent", path)
                    continue
                before = sha256(path)
                found, summary, examined = run_detector(path)
                record = {"kind": kind, "image": path.stem, "findings": [finding_record(x)
                          for x in found], "units": examined,
                          "unchanged": before == sha256(path)}  # fmt: skip
                f.write(json.dumps(record) + "\n")
                f.flush()
                print(kind, path.stem, Counter(x.technique for x in found))


# ---------------------------------------------------------------------------
# Fresh guest builds (false positives on images nobody planted in)
# ---------------------------------------------------------------------------
def manifest_command(name: str) -> str:
    with (REPO / "corpus" / "manifest.tsv").open() as f:
        return next(r["command"] for r in csv.DictReader(f, delimiter="\t") if r["name"] == name)


def build_part(args) -> None:
    builds = args.out / "builds"
    builds.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                   stdout=subprocess.DEVNULL)  # fmt: skip
    out = args.out / "build.jsonl"
    with out.open("a") as f:
        for recipe in args.recipes or RECIPES:
            for n in range(1, args.builds + 1):
                name = f"exp021_{recipe}_b{n}"
                command = manifest_command(recipe).replace(recipe, name)
                started = time.monotonic()
                subprocess.run(["sh", "-c", command], cwd=REPO, check=True,
                               env=os.environ | {"OUT_DIR": str(builds)},
                               stdout=subprocess.DEVNULL)  # fmt: skip
                image, log = builds / f"{name}.img", builds / f"{name}.log"
                try:
                    found, summary, examined = run_detector(image)
                    text = log.read_text(errors="replace") if log.exists() else ""
                    hidden = re.search(r"=== HIDDEN-ID (\d+)", text)
                    record = {"recipe": recipe, "build": n, "image_sha256": sha256(image),
                              "seconds": round(time.monotonic() - started),
                              "findings": [finding_record(x) | {"subvolume": x.detail.get(
                                  "subvolume")} for x in found], "units": examined,
                              "hidden_id": int(hidden[1]) if hidden else None}  # fmt: skip
                finally:
                    image.unlink(missing_ok=True)
                    log.unlink(missing_ok=True)
                f.write(json.dumps(record) + "\n")
                f.flush()
                print(
                    name,
                    record["seconds"],
                    "s",
                    Counter(x["technique"] for x in record["findings"]),
                )


# ---------------------------------------------------------------------------
# Stability: plant, check, mount and use in the guest, check and detect again
# ---------------------------------------------------------------------------
SLOT_MESSAGE = M.HIDDEN * 2  # long enough to cover the magic at 0x40


def stability_subjects() -> list[tuple[str, str, object, bytes | None]]:
    """(subject, base, planter, payload searched for afterwards); planter(path, src, size)."""
    hidden = M.HIDDEN

    def newest_padding(src, size):
        fields = ondisk.SUPERBLOCK.unpack_from(os.pread(src.fileno(), 4096, 65536))
        slot = next(r["slot"] for r in sb.backup_roots(fields)
                    if r["tree_root_gen"] == fields["generation"])  # fmt: skip
        return M.plant_sb_field(src, size, f"backup{slot}_unused_64", hidden)

    def one_copy(path, src, size):
        patches = M.plant_inode_reserved(path, hidden)[0]
        second = sorted(patches)[-1]
        return {second: patches[second]}

    return [
        ("superblock_reserved", "m1_sha256_bgt",
         lambda p, s, z: M.plant_sb_field(s, z, "reserved", hidden), hidden),
        ("superblock_reserved, gated field", "m1_blake2b",
         lambda p, s, z: M.plant_sb_field(s, z, "nr_global_roots", hidden), hidden[:8]),
        ("superblock_reserved, backup slot padding", "m1_xxhash",
         lambda p, s, z: newest_padding(s, z), hidden[:32]),
        ("superblock_padding", "m1_xxhash",
         lambda p, s, z: M.plant_sb_field(s, z, "padding", hidden), hidden),
        ("sys_chunk_array_slack", "m6_datacsum",
         lambda p, s, z: M.plant_chunk_array_slack(s, z, hidden), hidden),
        ("superblock_slot", "m1_xxhash",
         lambda p, s, z: {ondisk.sb_offset(1): SLOT_MESSAGE}, SLOT_MESSAGE),
        ("pre_superblock", "m1_sha256_bgt",
         lambda p, s, z: M.plant_pre_sb(s, z, hidden, 0x8000), hidden),
        ("backup_root_divergence", "m1_blake2b", lambda p, s, z: M.plant_backup_roots(s, z), None),
        ("node_slack", "m3_wide", lambda p, s, z: M.plant_slack(p, M.MESSAGE.encode()),
         M.MESSAGE.encode()),
        ("copy_divergence", "m1_blake2b", one_copy, hidden[:32]),
        ("inode_reserved", "m1_blake2b", lambda p, s, z: M.plant_inode_reserved(p, hidden)[0],
         hidden[:32]),
        ("timestamp_nsec", "m1_xxhash", lambda p, s, z: M.plant_nsec(p, M.NSEC_MESSAGE)[0], None),
        ("string_item", "m6_datacsum", lambda p, s, z: M.plant_string_item(p, hidden)[0], hidden),
        ("file_slack", "m6_datacsum",
         lambda p, s, z: M.plant_file_slack(p, "plain.txt", hidden, False)[0], hidden),
        ("file_slack, data checksum kept", "m6_datacsum",
         lambda p, s, z: M.plant_file_slack(p, "plain.txt", hidden, True)[0], hidden),
        ("device_slack", "m1_sha256_bgt", lambda p, s, z: M.plant_device_slack(p, hidden)[0],
         hidden),
        ("hidden_name", "m6_hidden_snapshot", lambda p, s, z: {}, None),
    ]  # fmt: skip


def technique_of(subject: str) -> str:
    return subject.split(",")[0]


def btrfs_check(path: Path) -> dict:
    """The pinned btrfs check, read-only, in both modes: exit status and the lines that report
    a problem."""
    found = {}
    for mode, extra in (("readonly", []), ("data_csum", ["--check-data-csum"])):
        done = subprocess.run([str(PINNED), "btrfs", "check", "--readonly", *extra, str(path)],
                              capture_output=True, text=True, timeout=600)  # fmt: skip
        text = done.stdout + done.stderr
        problems = [line for line in text.splitlines()
                    if re.search(r"error|mismatch|corrupt|bad |invalid|wrong|fail", line, re.I)
                    and not re.search(r"found 0 errors|no error found", line, re.I)]  # fmt: skip
        found[mode] = {"status": done.returncode, "problems": problems[:20]}
    return found


DMESG_PROBLEM = re.compile(r"BTRFS (critical|error|warning|alert|emerg)")


def guest_log(text: str) -> dict:
    """What a stability run's serial log says: mount, scrub, unreadable files, kernel errors and
    warnings, the balance result."""
    dmesg = re.findall(r"=== DMESG (.*)", text)
    scrub = [line.strip() for line in re.findall(r"=== SCRUB (.*)", text)]
    return {
        "mounted": "=== MOUNTED" in text,
        "mount_fail": "=== MOUNT-FAIL" in text,
        "done": "=== SCENARIO-DONE" in text,
        "scrub": [line for line in scrub if re.match(r"(Error summary|Status|ERROR)", line)],
        "read_errors": re.findall(r"=== READ-ERROR (.*)", text)[:10],
        "dmesg_problems": [line for line in dmesg if DMESG_PROBLEM.search(line)][:20],
        "balance": re.findall(r"=== BALANCE (.*)", text),
    }


def guest_run(image: Path, scenario: str, log: Path) -> dict:
    env = os.environ | {"SCENARIO": scenario, "MOUNT_OPTS": "commit=5"}
    with log.open("w") as out:
        done = subprocess.run([str(REPO / "corpus" / "vm" / "run_scenario.sh"), str(image)],
                              env=env, stdout=out, stderr=subprocess.STDOUT)  # fmt: skip
    return {"status": done.returncode} | guest_log(log.read_text(errors="replace"))


def on_image(path: Path, data: bytes | None) -> bool | None:
    if data is None:
        return None
    with open_image(path) as img:
        return img.mmap.find(data) >= 0


def stability_part(args) -> None:
    out = args.out / "stability.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    work = args.out / "stability"
    work.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                   stdout=subprocess.DEVNULL)  # fmt: skip
    subjects = [s for s in stability_subjects() if not args.subjects or s[0] in args.subjects]
    with out.open("a") as f:
        for subject, base, plant, data in subjects:
            technique = technique_of(subject)
            path = SCENARIOS / f"{base}.img"
            with open(path, "rb") as src:
                patches = plant(path, src, os.fstat(src.fileno()).st_size)
            planted = planted_copy(path, patches, work / "subject")
            found, _, _ = run_detector(planted)
            record = {"subject": subject, "technique": technique, "base": base, "run": 0,
                      "reported": sum(x.technique == technique for x in found),
                      "others": dict(Counter(x.technique for x in found
                                             if x.technique != technique)),
                      "on_image": on_image(planted, data),
                      "check": btrfs_check(planted)}  # fmt: skip
            f.write(json.dumps(record) + "\n")
            f.flush()
            print(subject, "planted", record["reported"], record["check"])
            for workload in ("use", "balance"):
                for n in range(1, args.runs + 1):
                    image = work / f"run_{workload}_{n}.img"
                    image.unlink(missing_ok=True)
                    subprocess.run(["cp", "--reflink=auto", "--", str(planted), str(image)],
                                   check=True)  # fmt: skip
                    log = work / "logs" / f"{len(subject)}_{technique}_{workload}_{n}.log"
                    log.parent.mkdir(exist_ok=True)
                    guest = guest_run(image, f"stability_{workload}", log)
                    found, _, _ = run_detector(image)
                    record = {"subject": subject, "technique": technique, "base": base,
                              "workload": workload, "run": n, "guest": guest,
                              "reported": sum(x.technique == technique for x in found),
                              "found": [finding_record(x) for x in found
                                        if x.technique == technique][:4],
                              "others": dict(Counter(x.technique for x in found
                                                     if x.technique != technique)),
                              "on_image": on_image(image, data),
                              "check": btrfs_check(image)}  # fmt: skip
                    image.unlink()
                    f.write(json.dumps(record) + "\n")
                    f.flush()
                    print(
                        subject,
                        workload,
                        n,
                        "reported",
                        record["reported"],
                        "on image",
                        record["on_image"],
                        "mounted",
                        guest["mounted"],
                    )
            planted.unlink()


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
def spread(values) -> str:
    values = list(values)
    if not values:
        return "–"
    return f"{statistics.median(values):g} ({min(values):g}–{max(values):g})"


def read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def scrub_errors(record: dict) -> bool:
    """Whether the read-only scrub found an error: from the kernel's own scrub messages, since
    the guest's btrfs-progs cannot print its summary (it aborts: libgcc_s is not in the
    initramfs), and from that summary where it is printed."""
    guest = record["guest"]
    return any("scrub" in line for line in guest["dmesg_problems"]) or any(
        line.startswith("Error summary") and "no errors" not in line for line in guest["scrub"]
    )


def table(args) -> None:
    rows = read(args.out / "detect.jsonl")
    plants = [r for r in rows if r.get("record") != "base"]
    print("## Detection\n")
    print("| technique | plants | not applicable | in scope: detected | covers | exact |"
          " out of scope: detected | collateral | bases | csum types |")  # fmt: skip
    print("|---|---|---|---|---|---|---|---|---|---|")
    for technique in TECHNIQUES:
        group = [r for r in plants if r["technique"] == technique]
        if not group:
            continue
        done = [r for r in group if "na" not in r]
        scope = [r for r in done if r["in_scope"]]
        out = [r for r in done if not r["in_scope"]]
        exacts = [r["exact"] for r in scope if r["exact"] is not None]
        collateral = Counter(k for r in done for k in r["others"])
        print(
            f"| `{technique}` | {len(group)} | {len(group) - len(done)} | "
            f"{sum(r['detected'] for r in scope)}/{len(scope)} | "
            f"{sum(r['covers'] for r in scope)}/{len(scope)} | "
            f"{f'{sum(exacts)}/{len(exacts)}' if exacts else 'n/a'} | "
            f"{f'{sum(r["detected"] for r in out)}/{len(out)}' if out else '–'} | "
            f"{dict(collateral) or '–'} | {len({r['base'] for r in done})} | "
            f"{sorted({r['csum_type'] for r in done})} |"
        )
    print()
    for r in plants:
        if "na" not in r and (r["in_scope"] != r["detected"] or not r.get("covers", True)
                              or r.get("exact") is False):  # fmt: skip
            print(
                f"- {r['base']} {r['technique']} {r['label']}: detected {r['detected']}, "
                f"covers {r['covers']}, exact {r['exact']}, others {r['others']}"
                + (f", csum {r.get('csum')}" if "csum" in r else "")
            )
    print()
    for r in plants:
        if "na" in r:
            print(f"- not applicable: {r['base']} {r['technique']} {r['label']}: {r['na']}")
    print()
    for r in plants:
        if r["technique"] == "file_slack" and "csum" in r:
            print(
                f"- file_slack {r['base']} {r['label']}: csum {r['csum']} "
                f"(expected {r.get('csum_expected')})"
            )
    bases = [r for r in rows if r.get("record") == "base"]
    print(
        f"\nbases unchanged: {sum(r['unchanged'] for r in bases)}/{len(bases)}; findings on "
        f"the clean bases: {sum(r['clean_findings'] for r in bases)}"
    )
    capacity = {}
    for r in plants:
        if r.get("capacity") is not None:
            key = f"{r['technique']} {r['area']}".strip()
            capacity.setdefault(key, {})[r["base"]] = r["capacity"]
    print("\ncapacity (bytes) per base:")
    for key, values in capacity.items():
        print(f"- {key}: {', '.join(f'{b} {v:,}' for b, v in values.items())}")

    print("\n## Stability\n")
    stab = read(args.out / "stability.jsonl")
    print("| subject | base | planted: reported, check ro, check csum | workload | N | "
          "mounted | scrub errors, unreadable files | kernel errors or warnings | reported | "
          "payload on image | check ro / csum clean |")  # fmt: skip
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for subject in dict.fromkeys(r["subject"] for r in stab):
        zero = next(r for r in stab if r["subject"] == subject and r["run"] == 0)
        head = (f"{zero['reported']}, {zero['check']['readonly']['status']}, "
                f"{zero['check']['data_csum']['status']}")  # fmt: skip
        for workload in ("use", "balance"):
            runs = [r for r in stab if r["subject"] == subject and r.get("workload") == workload]
            if not runs:
                continue
            errors = (f"{sum(scrub_errors(r) for r in runs)}, "
                      f"{sum(bool(r['guest']['read_errors']) for r in runs)}")  # fmt: skip
            balanced = sum(any(x.startswith("Done") for x in r["guest"]["balance"]) for r in runs)
            print(
                f"| {subject} | `{zero['base']}` | {head} | {workload} | {len(runs)} | "
                f"{sum(r['guest']['mounted'] for r in runs)}"
                f"{f' (balance done {balanced})' if workload == 'balance' else ''} | {errors} | "
                f"{sum(bool(r['guest']['dmesg_problems']) for r in runs)} | "
                f"{sum(r['reported'] > 0 for r in runs)} | "
                f"{
                    sum(bool(r['on_image']) for r in runs)
                    if runs[0]['on_image'] is not None
                    else 'n/a'
                } | "
                f"{sum(r['check']['readonly']['status'] == 0 for r in runs)} / "
                f"{sum(r['check']['data_csum']['status'] == 0 for r in runs)} |"
            )
    for r in stab:
        if r["run"] == 0 and any(r["check"][m]["problems"] for m in r["check"]):
            print(f"- planted {r['subject']}: check {json.dumps(r['check'])}")
        if r["run"] and (r["guest"]["dmesg_problems"] or r["guest"]["read_errors"]):
            print(
                f"- {r['subject']} {r['workload']} {r['run']}: dmesg "
                f"{r['guest']['dmesg_problems'][:3]} read errors {r['guest']['read_errors'][:2]}"
                f" scrub {r['guest']['scrub']}"
            )
        if r["run"] and r["others"]:
            print(f"- {r['subject']} {r['workload']} {r['run']}: other findings {r['others']}")

    print("\n## False positives\n")
    clean = read(args.out / "clean.jsonl")
    builds = read(args.out / "build.jsonl")
    kept = [r for r in clean if r["kind"] == "kept"]
    explained = {"m6_reformat_geometry": "device_slack"}
    print("| technique | images | kept: findings | fresh builds | fresh: findings | units examined"
          " (kept + fresh) | false positives |")  # fmt: skip
    print("|---|---|---|---|---|---|---|")
    fresh = [b for b in builds if b["recipe"] != "m6_hidden_snapshot"]
    hidden = [b for b in builds if b["recipe"] == "m6_hidden_snapshot"]
    for technique in TECHNIQUES:
        kept_found = sum(x["technique"] == technique for r in kept for x in r["findings"])
        fresh_found = sum(x["technique"] == technique for r in builds for x in r["findings"]
                          if not (r["recipe"] == "m6_hidden_snapshot" and technique ==
                                  "hidden_name" and x["subvolume"] == r["hidden_id"]))  # fmt: skip
        why = sum(x["technique"] == technique and explained.get(r["image"]) == technique
                  for r in kept for x in r["findings"])  # fmt: skip
        examined = sum(r["units"][technique] for r in kept + builds)
        print(
            f"| `{technique}` | {len(kept) + len(builds)} | {kept_found} | {len(builds)} | "
            f"{fresh_found} | {examined:,} {UNIT_NAMES[technique]} | "
            f"{kept_found + fresh_found - why} |"
        )
    print()
    for r in kept:
        if r["findings"]:
            print(f"- kept {r['image']}: {[(x['technique'], x['where']) for x in r['findings']]}")
    for r in builds:
        unexpected = [
            x
            for x in r["findings"]
            if not (
                r["recipe"] == "m6_hidden_snapshot"
                and x["technique"] == "hidden_name"
                and x["subvolume"] == r["hidden_id"]
            )
        ]
        if unexpected:
            print(
                f"- build {r['recipe']} {r['build']}: "
                f"{[(x['technique'], x['where']) for x in unexpected]}"
            )
    by_recipe = {}
    for r in fresh:
        by_recipe.setdefault(r["recipe"], []).append(r)
    for recipe, group in by_recipe.items():
        print(
            f"- {recipe}: N = {len(group)}, findings {spread(len(r['findings']) for r in group)}"
            f", build seconds {spread(r['seconds'] for r in group)}, distinct images "
            f"{len({r['image_sha256'] for r in group})}"
        )
    if hidden:
        right = sum(
            len(r["findings"]) > 0
            and all(
                x["technique"] == "hidden_name" and x["subvolume"] == r["hidden_id"]
                for x in r["findings"]
            )
            for r in hidden
        )
        print(
            f"- m6_hidden_snapshot: N = {len(hidden)}, the hidden snapshot and nothing else "
            f"in {right}; findings {spread(len(r['findings']) for r in hidden)}"
        )
    print(f"\nkept images unchanged: {sum(r['unchanged'] for r in clean)}/{len(clean)}")
    for r in clean:
        if r["kind"] == "planted":
            print(
                f"- planted {r['image']}: {[(x['technique'], x['where']) for x in r['findings']]}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT)
    sub = parser.add_subparsers(dest="command", required=True)
    part = sub.add_parser("detect")
    part.add_argument("bases", nargs="*")
    sub.add_parser("clean")
    part = sub.add_parser("stability")
    part.add_argument("--runs", type=int, default=5)
    part.add_argument("--subjects", nargs="*")
    part = sub.add_parser("build")
    part.add_argument("--builds", type=int, default=5)
    part.add_argument("--recipes", nargs="*")
    sub.add_parser("table")
    args = parser.parse_args()
    parts = {"detect": detect_part, "clean": clean_part, "stability": stability_part,
             "build": build_part, "table": table}  # fmt: skip
    parts[args.command](args)


if __name__ == "__main__":
    main()
