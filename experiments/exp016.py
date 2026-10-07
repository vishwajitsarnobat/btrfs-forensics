"""EXP-016: btrfska's file reads against dissect.btrfs, per image and per compression codec.

The hypothesis is in experiments/EXP-016.md §1. This is the measurement behind the paper's
"152 oracle file reads" (tests/oracle/test_file_parity.py asserts it on four images), run over the
whole corpus and reported instead of asserted.

For every image, every root set (the backup roots by generation, then the current state), every
subvolume and snapshot that set's root tree names, and every regular file btrfska inventories in
it, one read is compared:
- btrfska's bytes (`extents.read_file`), which count only when the read is complete;
- dissect.btrfs's stream bytes. dissect reads the current root tree only, so for a backup root set
  its root tree is swapped for that set's (`Btrfs._root_tree`, a private attribute, as in the
  test) and its tree cache cleared;
- the guest-printed SHA-256 or the content the scenario script fixes, on the images built by the
  s01 scenario (the only ones whose log names files unambiguously).
A file's codec is the set of compression types of its extents (`none` when no extent is
compressed). The images are fixed files, not guest runs: one run is deterministic for a given
image hash and dissect version.

Usage, from the repo root:
  uv run python experiments/exp016.py run [IMAGE...]   # default: sandbox.img + every manifest image
  uv run python experiments/exp016.py table
Both take `--results PATH` (default images/scratch/exp/EXP-016/results.jsonl).
"""

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from dissect.btrfs import Btrfs
from dissect.btrfs.btrfs import Subvolume
from dissect.btrfs.tree import BTree

from btrfska.substrate import ondisk
from btrfska.substrate.extents import read_file
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.roots import root_sets, subvolumes
from btrfska.substrate.tree import IncompleteTree, fs_tree_inventory

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-016"
RESULTS = OUT / "results.jsonl"
MANIFEST = REPO / "corpus" / "manifest.tsv"
SCENARIOS = REPO / "images" / "scenarios"
# The four images of the paper's "152 oracle reads" (tests/oracle/test_file_parity.py IMAGES).
CLAIMED = ("sandbox", "m1_xxhash", "m1_lzo", "m1_zlib")
SCRIPT_CONTENT = {f"churn_{i}": b"gen%d\n" % i for i in range(1, 7)}  # s01.guest.sh
GUEST_LINE = re.compile(r"^([0-9a-f]{64})  /mnt/\S*?([^/\s]+)$", re.M)


def manifest() -> dict[str, str]:
    with MANIFEST.open(newline="") as f:
        return {row["name"]: row["command"] for row in csv.DictReader(f, delimiter="\t")}


def default_images() -> list[Path]:
    return [REPO / "sandbox.img", *(SCENARIOS / f"{name}.img" for name in manifest())]


def s01_built(name: str) -> bool:
    """Built by the s01 scenario in the guest: a make_image.sh row without SCENARIO, or a
    discard_*.sh row. Mutated copies have no log of their own."""
    command = manifest().get(name, "")
    return ("make_image.sh" in command and "SCENARIO=" not in command) or (
        "scenarios/discard_" in command
    )


def expected_hashes(name: str) -> dict[str, str]:
    """file name -> SHA-256 the s01 guest printed or the s01 script fixes; empty elsewhere."""
    log = SCENARIOS / f"{name}.log"
    if not s01_built(name) or not log.exists():
        return {}
    found = {file: digest for digest, file in GUEST_LINE.findall(log.read_text(errors="replace"))}
    found.update({file: hashlib.sha256(data).hexdigest() for file, data in SCRIPT_CONTENT.items()})
    return found


def dissect_files(subvolume) -> set[int]:
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


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def measure(path: Path) -> dict:
    """One line: the image's reads, or why it could not be read at all."""
    name = path.stem
    line = {"image": name, "path": str(path), "reads": [], "listing": [], "problems": []}
    expected = expected_hashes(name)
    with open_image(path) as img, path.open("rb") as fh:
        try:
            fs = open_filesystem(img)
        except (NoValidSuperblock, UnsupportedFormat) as exc:
            line["refused"] = _error(exc)
            return line
        no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
        for root_set in root_sets(fs.fields):
            try:
                dissect_fs = Btrfs(fh)
                dissect_fs._root_tree = BTree(dissect_fs, root_offset=root_set.trees["root"].bytenr)
                dissect_fs._open_tree.cache_clear()
            except Exception as exc:  # noqa: BLE001 - the oracle failing is a result, not a crash
                line["problems"].append({"root_set": root_set.source, "dissect": _error(exc)})
                dissect_fs = None
            subvols, problems = subvolumes(fs.reader, root_set)
            line["problems"] += [{"root_set": root_set.source, "btrfska": str(p)} for p in problems]
            for subvol in subvols:
                if subvol.root is None:
                    continue
                try:
                    inventory = fs_tree_inventory(
                        fs.reader, subvol.root.bytenr, subvol.root.expect()
                    )
                except IncompleteTree as exc:
                    line["problems"].append(
                        {"root_set": root_set.source, "subvolume": subvol.id,
                         "btrfska": _error(exc)}
                    )  # fmt: skip
                    continue
                files = {inode: e for inode, e in inventory.items() if e.get("kind") == "file"}
                dissect_subvol = listed = None
                if dissect_fs is not None:
                    try:
                        dissect_subvol = Subvolume(dissect_fs, subvol.id)
                        listed = dissect_files(dissect_subvol)
                    except Exception as exc:  # noqa: BLE001
                        line["problems"].append(
                            {"root_set": root_set.source, "subvolume": subvol.id,
                             "dissect": _error(exc)}
                        )  # fmt: skip
                line["listing"].append({
                    "root_set": root_set.source,
                    "subvolume": subvol.id,
                    "btrfska_only": sorted(set(files) - (listed or set())),
                    "dissect_only": sorted((listed or set()) - set(files)),
                    "dissect_listed": listed is not None,
                })  # fmt: skip
                for inode, entry in sorted(files.items()):
                    line["reads"].append(
                        read_one(fs, subvol, inode, entry, dissect_subvol, no_holes, expected)
                        | {"root_set": root_set.source, "subvolume": subvol.id}
                    )
    return line


def read_one(fs, subvol, inode, entry, dissect_subvol, no_holes, expected) -> dict:
    row = {"inode": inode, "name": entry.get("name"), "size": entry.get("size")}
    try:
        ours = read_file(fs.reader, subvol.root, inode, no_holes=no_holes)
        data = b"".join(ours.chunks()) if ours.complete else None
        row["complete"] = ours.complete
        row["codec"] = "+".join(sorted({e.compression for e in ours.extents if e.compression}))
        row["btrfska"] = data and hashlib.sha256(data).hexdigest()
    except Exception as exc:  # noqa: BLE001
        row |= {"complete": False, "codec": "", "btrfska": None, "btrfska_error": _error(exc)}
    row["codec"] = row["codec"] or "none"
    row["dissect"] = None
    if dissect_subvol is not None:
        try:
            row["dissect"] = hashlib.sha256(dissect_subvol.inode(inode).open().read()).hexdigest()
        except Exception as exc:  # noqa: BLE001
            row["dissect_error"] = _error(exc)
    row["expected"] = expected.get(row["name"])
    return row


def classify(row: dict) -> str:
    if not row["complete"]:
        return "btrfska_incomplete"
    if row["dissect"] is None:
        return "dissect_failed"
    if row["btrfska"] != row["dissect"]:
        return "differ"
    return "equal"


def run(args) -> int:
    args.results.parent.mkdir(parents=True, exist_ok=True)
    images = args.images or default_images()
    with args.results.open("w") as out:
        for path in images:
            if not path.exists():
                print(f"{path.name}: absent, skipped")
                continue
            line = measure(path)
            out.write(json.dumps(line) + "\n")
            out.flush()
            counts = Counter(classify(r) for r in line["reads"])
            print(f"{line['image']}: {len(line['reads'])} reads {dict(counts)}"
                  + (f" refused ({line['refused']})" if "refused" in line else ""))  # fmt: skip
    return 0


def table(args) -> int:
    lines = [json.loads(text) for text in args.results.read_text().splitlines()]
    print("| Image | Codec | Root sets | File reads (distinct files) | btrfska complete "
          "| Equal to dissect.btrfs | Differ | dissect failed | With expected SHA-256 "
          "| Equal to expected |")  # fmt: skip
    print("|---|---|---|---|---|---|---|---|---|---|")
    totals, notes = defaultdict(Counter), []
    for line in lines:
        if "refused" in line:
            print(f"| `{line['image']}` | refused: {line['refused']} | | | | | | | | |")
            continue
        sets = len({r["root_set"] for r in line["listing"]})
        by_codec = defaultdict(list)
        for row in line["reads"]:
            by_codec[row["codec"]].append(row)
        for codec, rows in sorted(by_codec.items()):
            n = Counter(classify(r) for r in rows)
            with_truth = [r for r in rows if r["expected"] is not None]
            truth_equal = sum(r["btrfska"] == r["expected"] for r in with_truth)
            distinct = len({(r["subvolume"], r["inode"], r["btrfska"]) for r in rows})
            print(
                f"| `{line['image']}` | {codec} | {sets} | {len(rows)} ({distinct}) "
                f"| {sum(r['complete'] for r in rows)} | {n['equal']} | {n['differ']} "
                f"| {n['dissect_failed']} | {len(with_truth)} | {truth_equal} |"
            )
            group = "claimed" if line["image"] in CLAIMED else "rest"
            totals[group].update(n)
            totals[group]["reads"] += len(rows)
            totals[group]["truth"] += len(with_truth)
            totals[group]["truth_equal"] += truth_equal
        mismatched = [
            x
            for x in line["listing"]
            if x["dissect_listed"] and (x["btrfska_only"] or x["dissect_only"])
        ]
        unlisted = [x for x in line["listing"] if not x["dissect_listed"]]
        if mismatched or unlisted or line["problems"]:
            notes.append(
                f"{line['image']}: dissect's directory walk differs in {len(mismatched)} "
                f"subvolume(s) and could not list {len(unlisted)}; {len(line['problems'])} "
                f"problem(s), first: {str(line['problems'][:1])[:300]}"
            )
    print()
    for note in notes:
        print(note)
    print()
    for group, n in totals.items():
        print(
            f"{group}: {n['reads']} reads, {n['equal']} equal, {n['differ']} differ, "
            f"{n['btrfska_incomplete']} btrfska incomplete, {n['dissect_failed']} dissect failed; "
            f"{n['truth_equal']} of {n['truth']} equal to the expected SHA-256"
        )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="compare every file read of the images")
    run_parser.add_argument("images", nargs="*", type=Path)
    table_parser = sub.add_parser("table", help="print the table of EXP-016.md §6")
    for p in (run_parser, table_parser):
        p.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args(argv)
    return run(args) if args.command == "run" else table(args)


if __name__ == "__main__":
    raise SystemExit(main())
