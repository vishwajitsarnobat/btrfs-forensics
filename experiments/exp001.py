"""EXP-001: checksum-type coverage, legacy prototype vs btrfska (plan.md §5 M1 task 11, §7).

Regenerates every number in experiments/EXP-001.md. From the repo root, with the dev group
installed (dissect.btrfs is the sandbox reference) and the images of corpus/manifest.tsv present:

    uv run python experiments/exp001.py [--runs 2]

Raw outputs go to images/scratch/exp/EXP-001/: legacy output directories, results.json and
table.md. The counts are deterministic parses of fixed images; `--runs N` repeats the whole
measurement and fails unless every run gives identical results.

Metrics per image and tool:
- tree blocks accepted and rejected. Legacy scans the image: it accepts a block whose fsid matches
  and whose crc32c validates, counting orphans (generation below the superblock's) and
  current-generation leaves (current internal nodes are not counted), and rejects fsid-matching
  blocks whose crc32c fails. btrfska walks anchored trees: every tree of every root set (the
  backup roots and the current state; slot trees and every ROOT_ITEM of each root tree). It
  accepts a distinct tree block with a copy that passes every check and rejects one without.
  The two discovery methods differ, so only acceptance versus rejection is compared;
- files listed per generation: legacy, distinct file names among its recovered files per
  generation; btrfska, regular files in every subvolume of that generation's root set;
- files byte-identical to ground truth: distinct files (legacy: name and generation; btrfska:
  subvolume, inode and name) whose bytes equal the ground truth every time they are listed, out
  of the distinct files listed. Ground truth is
  the guest-printed SHA-256 (keep.txt, deleted_big.txt, deleted_inline.txt) or the scenario
  script's content (churn_N holds "genN\\n") for the s01 images. sandbox.img has no scenario log,
  so its reference is dissect.btrfs 1.10's stream bytes for the same generation (an oracle, not
  independent ground truth).
"""

import argparse
import collections
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))  # experiments/prototype.py, whether run as a script or imported

from btrfska.substrate import items, ondisk  # noqa: E402
from btrfska.substrate.extents import read_file  # noqa: E402
from btrfska.substrate.fs import open_filesystem  # noqa: E402
from btrfska.substrate.image import open_image  # noqa: E402
from btrfska.substrate.roots import TreeRoot, root_sets, subvolumes  # noqa: E402
from btrfska.substrate.tree import fs_tree_inventory, leaf_items, walk  # noqa: E402
from experiments import prototype  # noqa: E402

OUT = REPO / "images" / "scratch" / "exp" / "EXP-001"
SCENARIOS = REPO / "images" / "scenarios"
IMAGES = [
    ("sandbox", "crc32c", REPO / "sandbox.img"),
    ("m1_xxhash", "xxhash64", SCENARIOS / "m1_xxhash.img"),
    ("m1_sha256_bgt", "sha256", SCENARIOS / "m1_sha256_bgt.img"),
    ("m1_blake2b", "blake2b", SCENARIOS / "m1_blake2b.img"),
]
SCRIPT_CONTENT = {f"churn_{i}": b"gen%d\n" % i for i in range(1, 7)}  # corpus/vm s01.guest.sh
K = ondisk.ITEM_KEYS


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def image_sha256(path: Path) -> str:
    with open_image(path) as img:
        return img.sha256()


def guest_truth(name: str) -> dict[str, str] | None:
    """file name -> expected SHA-256 for an s01 image; None when the image has no scenario log."""
    log = SCENARIOS / f"{name}.log"
    if not log.exists():
        return None
    pattern = re.compile(r"^([0-9a-f]{64})  /mnt/\S*?([^/\s]+)$", re.M)
    truth = {file: digest for digest, file in pattern.findall(log.read_text(errors="replace"))}
    return truth | {file: sha256(content) for file, content in SCRIPT_CONTENT.items()}


def dissect_reference(path: Path, tree_root_bytenr: int, subvolume: int, inode: int) -> str:
    """dissect.btrfs stream bytes of an inode, reading the root tree at `tree_root_bytenr`."""
    from dissect.btrfs import Btrfs
    from dissect.btrfs.btrfs import Subvolume
    from dissect.btrfs.tree import BTree

    with open(path, "rb") as fh:
        fs = Btrfs(fh)
        fs._root_tree = BTree(fs, root_offset=tree_root_bytenr)
        fs._open_tree.cache_clear()
        return sha256(Subvolume(fs, subvolume).inode(inode).open().read())


# ---------------------------------------------------------------------------
# btrfska
# ---------------------------------------------------------------------------
def trees_of(reader, root_set) -> list[TreeRoot]:
    trees = {("slot", name): root for name, root in root_set.trees.items()}
    root = root_set.trees["root"]
    for visit, item in leaf_items(walk(reader, root.bytenr, root.expect())):
        if item.key.type == K["ROOT_ITEM"]:
            fields = items.root_item(item.data)
            via = f"ROOT_ITEM {item.key} in leaf {visit.node.logical}"
            trees[(item.key.objectid, item.key.offset)] = TreeRoot(
                item.key.objectid, fields["bytenr"], fields["level"], fields["generation"], via
            )
    return list(trees.values())


def measure_btrfska(name: str, path: Path) -> dict:
    truth = guest_truth(name)
    blocks: dict[int, bool] = {}
    per_generation = {}
    listed, mismatched = set(), set()
    with open_image(path) as img:
        fs = open_filesystem(img)
        no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
        for root_set in root_sets(fs.fields):
            for tree in trees_of(fs.reader, root_set):
                for visit in walk(fs.reader, tree.bytenr, tree.expect()):
                    node = visit.node
                    blocks[node.logical] = blocks.get(node.logical, True) and node.valid
            count = 0
            subvols, _ = subvolumes(fs.reader, root_set)
            for subvol in subvols:
                if subvol.root is None:
                    continue
                inventory = fs_tree_inventory(fs.reader, subvol.root.bytenr, subvol.root.expect())
                for inode, entry in sorted(inventory.items()):
                    if entry.get("kind") != "file":
                        continue
                    count += 1
                    key = (subvol.id, inode, entry.get("name"))
                    listed.add(key)
                    result = read_file(fs.reader, subvol.root, inode, no_holes=no_holes)
                    if not result.complete:
                        mismatched.add(key)
                        continue
                    digest = sha256(b"".join(result.chunks()))
                    if truth is None:
                        expected = dissect_reference(
                            path, root_set.trees["root"].bytenr, subvol.id, inode
                        )
                    else:
                        expected = truth.get(entry.get("name"))
                    if digest != expected:
                        mismatched.add(key)
            per_generation[root_set.source] = count
    return {
        "tree_blocks_accepted": sum(blocks.values()),
        "tree_blocks_rejected": len(blocks) - sum(blocks.values()),
        "files_listed_per_generation": per_generation,
        "distinct_files_listed": len(listed),
        "distinct_files_identical": len(listed - mismatched),
    }


# ---------------------------------------------------------------------------
# legacy prototype
# ---------------------------------------------------------------------------
LEGACY_COMMAND = "uv run --python 3.14 python {prototype}/main.py {image} -o {out}"


def legacy_reference(name: str, path: Path, filename: str, generation: int) -> str | None:
    truth = guest_truth(name)
    if truth is not None:
        return truth.get(filename)
    with open_image(path) as img:  # sandbox: dissect.btrfs bytes at that backup generation
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            if root_set.generation != generation or root_set.source == "current":
                continue
            subvols, _ = subvolumes(fs.reader, root_set)
            for subvol in subvols:
                inventory = fs_tree_inventory(fs.reader, subvol.root.bytenr, subvol.root.expect())
                for inode, entry in inventory.items():
                    if entry.get("kind") == "file" and entry.get("name") == filename:
                        return dissect_reference(
                            path, root_set.trees["root"].bytenr, subvol.id, inode
                        )
    return None


def measure_legacy(name: str, path: Path) -> dict:
    out = OUT / "legacy" / name
    if out.exists():
        shutil.rmtree(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    command = LEGACY_COMMAND.format(
        prototype=prototype.checkout().relative_to(REPO), image=path.relative_to(REPO),
        out=out.relative_to(REPO),
    )  # fmt: skip
    log = subprocess.run(command.split(), cwd=REPO, capture_output=True, text=True, check=True)
    (OUT / "legacy" / f"{name}.log").write_text(log.stdout + log.stderr)
    report = json.loads((out / "recovery_report.json").read_text())
    stats = report["stats"]
    per_generation = collections.defaultdict(set)
    mismatched = set()
    for entry in report["recovered_files"]:
        key = (entry["filename"], entry["generation"])
        per_generation[entry["generation"]].add(entry["filename"])
        if entry["output_path"] == "(duplicate)":  # legacy dedup: the bytes were written once
            continue
        output = REPO / entry["output_path"]
        expected = legacy_reference(name, path, *key)
        if not output.exists() or expected is None or sha256(output.read_bytes()) != expected:
            mismatched.add(key)
    return {
        "tree_blocks_accepted": stats["orphan_nodes_found"] + stats["current_nodes_scanned"],
        "tree_blocks_rejected": stats["checksum_failures"],
        "files_listed_per_generation": {
            f"gen {gen}": len(names) for gen, names in sorted(per_generation.items())
        },
        "distinct_files_listed": sum(len(names) for names in per_generation.values()),
        "distinct_files_identical": sum(
            (name_, gen) not in mismatched
            for gen, names in per_generation.items()
            for name_ in names
        ),
    }


# ---------------------------------------------------------------------------
def measure() -> dict:
    results = {}
    for name, csum_name, path in IMAGES:
        if not path.exists():
            raise SystemExit(f"{path} is missing: generate it with its corpus/manifest.tsv command")
        before = image_sha256(path)
        results[name] = {
            "csum": csum_name,
            "image_sha256_before": before,
            "legacy": measure_legacy(name, path),
            "btrfska": measure_btrfska(name, path),
            "image_sha256_after": image_sha256(path),
        }
        assert results[name]["image_sha256_after"] == before, f"{name} changed"
    return results


def table(results: dict) -> str:
    def generations(counts: dict) -> str:
        return ", ".join(f"{gen}: {n}" for gen, n in counts.items()) or "none"

    lines = [
        "| Image | csum | Tool | Tree blocks accepted | Tree blocks rejected "
        "| Files listed per generation | Distinct files byte-identical / listed |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, result in results.items():
        for tool in ("legacy", "btrfska"):
            row = result[tool]
            lines.append(
                f"| `{name}` | {result['csum']} | {tool} "
                f"| {row['tree_blocks_accepted']} | {row['tree_blocks_rejected']} "
                f"| {generations(row['files_listed_per_generation'])} "
                f"| {row['distinct_files_identical']} / {row['distinct_files_listed']} |"
            )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="EXP-001: checksum-type coverage")
    parser.add_argument("--runs", type=int, default=1, help="repeat and require identical results")
    args = parser.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    runs = [measure() for _ in range(args.runs)]
    if any(run != runs[0] for run in runs[1:]):
        (OUT / "runs.json").write_text(json.dumps(runs, indent=1))
        raise SystemExit("runs differ; see runs.json")
    (OUT / "results.json").write_text(json.dumps(runs[0], indent=1))
    rendered = table(runs[0])
    (OUT / "table.md").write_text(rendered + "\n")
    print(rendered)
    print(f"\nruns: {args.runs}, identical: yes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
