"""EXP-017: a superblock copy of another filesystem at a mirror offset is reported, not selected.

The hypothesis is in experiments/EXP-017.md §1. For every image, every superblock mirror slot is
read (superblock.read_copies) and three selection rules are applied to the valid copies:
- btrfska's (superblock.select): the lowest-offset valid copy anchors the filesystem identity, as
  btrfs-progs recover mode does (kernel-shared/disk-io.c:2022-2064 at v7.1); only copies of that
  filesystem compete on generation, the others are listed as foreign;
- generation alone: the valid copy with the highest generation, whatever its fsid (what
  `select()` did before the M1a review fix);
- the kernel's: mirror 0 only (fs/btrfs/disk-io.c:3333 at v7.0).
When generation alone picks a different copy than btrfska, the first two steps of opening the
filesystem (fs.open_filesystem: the bootstrap map from that copy's sys_chunk_array, then its chunk
root) are replayed with that copy's fields, to show what the wrong pick would read. The other
corpus images are the control: there the rules must agree and no copy is foreign.

The images are fixed files, not guest runs: one run is deterministic for a given image hash.

Usage, from the repo root:
  uv run python experiments/exp017.py [IMAGE...] [--json OUT]
  (default: m1_foreign_mirror, then sandbox.img and every other manifest image as controls)
"""

import argparse
import csv
import hashlib
import json
import uuid
from pathlib import Path

from btrfska.substrate import chunks, ondisk, superblock
from btrfska.substrate.chunks import ChunkMap
from btrfska.substrate.fs import chunk_root_expect
from btrfska.substrate.image import open_image
from btrfska.substrate.node import NodeContext, NodeReader

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "corpus" / "manifest.tsv"
SCENARIOS = REPO / "images" / "scenarios"
TARGET = SCENARIOS / "m1_foreign_mirror.img"


def default_images() -> list[Path]:
    with MANIFEST.open(newline="") as f:
        names = [row["name"] for row in csv.DictReader(f, delimiter="\t")]
    controls = [SCENARIOS / f"{name}.img" for name in names if name != TARGET.stem]
    return [TARGET, REPO / "sandbox.img", *controls]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def describe(copy: superblock.SuperblockCopy | None) -> dict | None:
    if copy is None:
        return None
    row = {"mirror": copy.mirror, "offset": copy.offset, "present": copy.present,
           "valid": copy.valid}  # fmt: skip
    if copy.present and copy.magic_ok:
        f = copy.fields
        row |= {"fsid": str(uuid.UUID(bytes=f["fsid"])), "generation": f["generation"],
                "csum_type": f["csum_type"], "problems": list(copy.problems)}  # fmt: skip
    return row


def by_generation(copies) -> superblock.SuperblockCopy | None:
    """The rule before the M1a fix: the highest generation of the valid copies, any fsid."""
    valid = [c for c in copies if c.valid]
    return max(valid, key=lambda c: (c.fields["generation"], -c.mirror), default=None)


def replay_chunk_root(img, fields: dict) -> dict:
    """fs.open_filesystem steps 2 and 3 with `fields`: what a reader that trusted it would get."""
    device = ondisk.DEV_ITEM.unpack_from(fields["dev_item"])
    sys_chunks, sys_problems = chunks.parse_sys_chunk_array(fields)
    bootstrap = ChunkMap("sys_chunk_array", sys_chunks, {device["devid"]: device["uuid"]})
    try:
        node = NodeReader(img, bootstrap, NodeContext.from_superblock(fields)).read(
            fields["chunk_root"], chunk_root_expect(fields)
        )
    except Exception as exc:  # noqa: BLE001 - a failed read is the result being measured
        return {"chunk_root": fields["chunk_root"], "valid": False,
                "problems": [f"{type(exc).__name__}: {exc}"]}  # fmt: skip
    return {"chunk_root": fields["chunk_root"], "valid": node.valid,
            "problems": [*sys_problems, *node.problems]}  # fmt: skip


def measure(path: Path) -> dict:
    before = sha256(path)
    with open_image(path) as img:
        copies = superblock.read_copies(img)
        selection = superblock.select(copies)
        generation_pick = by_generation(copies)
        result = {
            "image": path.name,
            "copies": [describe(c) for c in copies],
            "selected": describe(selection.selected),
            "foreign": [describe(c) for c in selection.foreign],
            "foreign_lines": [d for d in selection.disagreements if "foreign" in d],
            "generation_only": describe(generation_pick),
            "kernel": describe(copies[0]),
        }
        result["rules_agree"] = generation_pick is selection.selected
        if not result["rules_agree"] and generation_pick is not None:
            result["generation_only_chunk_root"] = replay_chunk_root(img, generation_pick.fields)
            if selection.selected is not None:
                result["selected_chunk_root"] = replay_chunk_root(img, selection.selected.fields)
    result["sha256"], result["unchanged"] = before, sha256(path) == before
    return result


def _pick(row: dict | None) -> str:
    if row is None:
        return "none"
    if not row.get("valid"):
        return f"mirror {row['mirror']} (invalid)"
    return f"mirror {row['mirror']} (gen {row['generation']}, fsid {row['fsid'][:8]}…)"


def report(results: list[dict]) -> str:
    lines = ["| Image | Valid copies | btrfska selects | Foreign copies reported "
             "| Generation alone picks | Kernel mounts | Rules agree |",
             "|---|---|---|---|---|---|---|"]  # fmt: skip
    for r in results:
        valid = sum(1 for c in r["copies"] if c["valid"])
        lines.append(
            f"| `{r['image']}` | {valid} | {_pick(r['selected'])} | {len(r['foreign'])} "
            f"| {_pick(r['generation_only'])} | {_pick(r['kernel'])} "
            f"| {'yes' if r['rules_agree'] else 'no'} |"
        )
    for r in results:
        if r["rules_agree"]:
            continue
        lines += ["", f"{r['image']}:"]
        lines += [f"  copy {c}" for c in r["copies"]]
        lines += [f"  reported: {line}" for line in r["foreign_lines"]]
        for key in ("generation_only_chunk_root", "selected_chunk_root"):
            if key in r:
                lines.append(f"  {key}: {r[key]}")
    lines.append("")
    lines.append(f"every image unchanged: {all(r['unchanged'] for r in results)}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("images", nargs="*", type=Path)
    parser.add_argument("--json", type=Path, help="also write the results as JSON (under images/)")
    args = parser.parse_args(argv)
    results = [measure(path) for path in (args.images or default_images()) if path.exists()]
    print(report(results))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
