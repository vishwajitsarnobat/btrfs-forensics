"""EXP-004: btrfska's old-root discovery against btrfs-find-root, per image and per generation.

The hypothesis and the three registered predictions are in experiments/EXP-004.md §1; read them
first. In short: find-root scans the metadata block groups of the *current* chunk map, so it should
print exactly the root-tree blocks btrfska indexes inside that map (P1), nothing outside it (P2),
and every btrfska state inside it (P3).

For every image:
1. a sparse copy is made under images/scratch/exp/EXP-004/copies/ and hashed; `btrfs-find-root -a`
   (the pinned btrfs-progs 6.6.3, corpus/vm/pinned.sh) runs on the copy; the copy is hashed again
   and deleted. No foreign tool ever opens the original, sandbox.img included;
2. btrfska runs `discover_image(..., full_sweep=True)` on the original, read-only as always;
3. the root-tree (owner 1) blocks of btrfska's index are compared with the blocks find-root prints.

Usage, from the repo root:
  uv run python experiments/exp004.py run [IMAGE...]   # default: every manifest image + sandbox.img
  uv run python experiments/exp004.py table            # the tables of EXP-004.md §6
Both take `--results PATH` (default images/scratch/exp/EXP-004/results.jsonl).
"""

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from btrfska.scan.roots import MAX_STATES, discover_image
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import BG, MappingError, type_name
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-004"
RESULTS = OUT / "results.jsonl"
PINNED = REPO / "corpus" / "vm" / "pinned.sh"
MANIFEST = REPO / "corpus" / "manifest.tsv"
SCENARIOS = REPO / "images" / "scenarios"

WELL = re.compile(r"Well block (\d+)\(gen: (\d+) level: (\d+)\)")
FOUND = re.compile(r"Found tree root at (\d+) gen (\d+) level (\d+)")


def default_images() -> list[Path]:
    with MANIFEST.open(newline="") as f:
        names = [row["name"] for row in csv.DictReader(f, delimiter="\t")]
    return [*(SCENARIOS / f"{name}.img" for name in names), REPO / "sandbox.img"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def run_find_root(path: Path) -> dict:
    """`btrfs-find-root -a` on a sparse copy of `path`; the copy is removed afterwards."""
    copies = OUT / "copies"
    copies.mkdir(parents=True, exist_ok=True)
    copy = copies / path.name
    subprocess.run(["cp", "--sparse=always", str(path), str(copy)], check=True)
    try:
        before = sha256(copy)
        done = subprocess.run(
            [str(PINNED), "btrfs-find-root", "-a", str(copy)], capture_output=True, text=True
        )
        after = sha256(copy)
    finally:
        copy.unlink(missing_ok=True)
    text_dir = OUT / "findroot"
    text_dir.mkdir(parents=True, exist_ok=True)
    (text_dir / f"{path.stem}.txt").write_text(
        f"# exit {done.returncode}\n# stdout\n{done.stdout}# stderr\n{done.stderr}"
    )
    blocks = {tuple(map(int, m.groups())) for m in WELL.finditer(done.stdout)}
    blocks |= {tuple(map(int, m.groups())) for m in FOUND.finditer(done.stdout)}
    return {
        "exit": done.returncode,
        "opened": "open ctree failed" not in done.stderr and "open ctree failed" not in done.stdout,
        "blocks": sorted(blocks),
        "copy_unchanged": before == after,
        # paths relative to the repository, so a record never carries a local directory
        "stderr_tail": done.stderr.replace(f"{REPO}/", "").strip().splitlines()[-3:],
    }


def btrfska_root_tree_blocks(path: Path, max_states: int = MAX_STATES) -> dict:
    """Every owner-1 block btrfska indexes, with its placement under the current chunk map."""
    with open_image(path) as img:
        try:
            fs = open_filesystem(img)
        except UnsupportedFormat as exc:
            return {"refused": f"feature gate: {exc}"}
        except NoValidSuperblock as exc:
            return {"refused": f"no valid superblock: {exc}"}
        nodesize = fs.reader.ctx.nodesize
        scan = discover_image(img, fs, full_sweep=True, max_states=max_states)
        states = {(s.bytenr, s.generation, s.level): s for s in scan.discovery.states}
        rows = []
        for i in range(scan.index.nodes):
            bytenr, generation, level, owner = scan.index.node(i)
            if owner != ondisk.ROOT_TREE_OBJECTID:
                continue
            scanned_at = set(scan.index.copies(i))
            inside, chunk_type, aligned = False, None, None
            try:
                chunk = fs.chunk_map.chunk_for(bytenr)
                mapped = {c.physical for c in fs.chunk_map.copies(bytenr, nodesize)}
            except MappingError:
                pass
            else:
                inside = bool(mapped & scanned_at)
                chunk_type = type_name(chunk.type)
                aligned = (bytenr - chunk.logical) % nodesize == 0
                metadata = bool(chunk.type & BG["METADATA"])
                inside = inside and metadata
            state = states.get((bytenr, generation, level))
            rows.append(
                {
                    "bytenr": bytenr,
                    "generation": generation,
                    "level": level,
                    "copies": sorted(scanned_at),
                    "inside_map": inside,
                    "chunk_type": chunk_type,
                    "aligned": aligned,
                    "state": state is not None,
                    "known_as": list(state.known_as) if state else [],
                    "completeness": state.completeness if state else None,
                }
            )
        return {
            "superblock_generation": fs.fields["generation"],
            "nodesize": nodesize,
            "states_evaluated": len(scan.discovery.states),
            "root_tree_candidates": scan.discovery.root_tree_candidates,
            "blocks": rows,
        }


def predicted_find_root(rows: list[dict]) -> set[tuple[int, int, int]]:
    """P1: inside the current chunk map, nodesize-aligned, highest level of its generation."""
    visible = [r for r in rows if r["inside_map"] and r["aligned"]]
    top: dict[int, int] = {}
    for r in visible:
        top[r["generation"]] = max(top.get(r["generation"], 0), r["level"])
    return {
        (r["bytenr"], r["generation"], r["level"])
        for r in visible
        if r["level"] == top[r["generation"]]
    }


def measure(path: Path, max_states: int = MAX_STATES) -> dict:
    result = {"image": path.name, "sha256": sha256(path)}
    result["find_root"] = run_find_root(path)
    result["btrfska"] = ours = btrfska_root_tree_blocks(path, max_states)
    if "refused" in ours or not result["find_root"]["opened"]:
        return result
    printed = {tuple(b) for b in result["find_root"]["blocks"]}
    predicted = predicted_find_root(ours["blocks"])
    indexed = {(r["bytenr"], r["generation"], r["level"]) for r in ours["blocks"]}
    states = [r for r in ours["blocks"] if r["state"]]
    key = lambda r: (r["bytenr"], r["generation"], r["level"])  # noqa: E731
    result["comparison"] = {
        "p1_equal": printed == predicted,
        "printed_not_predicted": sorted(printed - predicted),
        "predicted_not_printed": sorted(predicted - printed),
        "printed_not_indexed": sorted(printed - indexed),
        "p2_outside_printed": sorted(
            key(r) for r in ours["blocks"] if not r["inside_map"] and key(r) in printed
        ),
        "p3_inside_states_missed": sorted(
            key(r) for r in states if r["inside_map"] and key(r) not in printed
        ),
        "states_inside": sum(r["inside_map"] for r in states),
        "states_outside": sum(not r["inside_map"] for r in states),
        "states_inside_printed": sum(r["inside_map"] and key(r) in printed for r in states),
        "states_outside_printed": sum(not r["inside_map"] and key(r) in printed for r in states),
        "outside_generations": sorted({r["generation"] for r in states if not r["inside_map"]}),
        "inside_generations": sorted({r["generation"] for r in states if r["inside_map"]}),
    }
    return result


def run(paths: list[Path], results: Path, max_states: int = MAX_STATES) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as out:
        for path in paths:
            if not path.exists():
                print(f"skip   {path.name}: absent", file=sys.stderr)
                continue
            record = measure(path, max_states)
            out.write(json.dumps(record) + "\n")
            out.flush()
            cmp_ = record.get("comparison")
            note = (
                f"P1 {'holds' if cmp_['p1_equal'] else 'FAILS'}; states inside "
                f"{cmp_['states_inside_printed']}/{cmp_['states_inside']}, outside "
                f"{cmp_['states_outside_printed']}/{cmp_['states_outside']} printed by find-root"
                if cmp_
                else record["btrfska"].get("refused")
                or f"find-root could not open it (exit {record['find_root']['exit']})"
            )
            print(f"done   {path.name}: {note}")
    shutil.rmtree(OUT / "copies", ignore_errors=True)


def _span(generations: list[int]) -> str:
    if not generations:
        return "–"
    return f"{generations[0]}–{generations[-1]} ({len(generations)})"


def table(results: Path) -> None:
    records = {}
    for line in results.read_text().splitlines():
        record = json.loads(line)
        records[record["image"]] = record  # the last measurement of an image wins
    print(
        "| Image | sb gen | find-root printed | btrfska owner-1 indexed | P1 "
        "| States inside the map, printed by find-root "
        "| States outside the map, printed by find-root | Outside generations |"
    )
    print("|---|---|---|---|---|---|---|---|")
    totals = {"inside": 0, "inside_printed": 0, "outside": 0, "outside_printed": 0, "p1": 0, "n": 0}
    for name, record in records.items():
        cmp_ = record.get("comparison")
        if not cmp_:
            reason = record["btrfska"].get("refused") or (
                f"find-root could not open it (exit {record['find_root']['exit']})"
            )
            print(f"| `{name}` | – | – | – | not compared: {reason} | – | – | – |")
            continue
        ours = record["btrfska"]
        totals["n"] += 1
        totals["p1"] += cmp_["p1_equal"]
        for k in ("inside", "outside"):
            totals[k] += cmp_[f"states_{k}"]
            totals[f"{k}_printed"] += cmp_[f"states_{k}_printed"]
        print(
            f"| `{name}` | {ours['superblock_generation']} | {len(record['find_root']['blocks'])} "
            f"| {len(ours['blocks'])} | {'holds' if cmp_['p1_equal'] else 'FAILS'} "
            f"| {cmp_['states_inside_printed']}/{cmp_['states_inside']} "
            f"| {cmp_['states_outside_printed']}/{cmp_['states_outside']} "
            f"| {_span(cmp_['outside_generations'])} |"
        )
    print(
        f"\nP1 holds on {totals['p1']} of {totals['n']} compared images. States inside the map: "
        f"{totals['inside_printed']} of {totals['inside']} printed by find-root. States outside: "
        f"{totals['outside_printed']} of {totals['outside']}."
    )
    unchanged = [r["find_root"]["copy_unchanged"] for r in records.values()]
    print(f"find-root left its copy unchanged on {sum(unchanged)} of {len(unchanged)} images.")
    for name, record in records.items():
        cmp_ = record.get("comparison")
        if cmp_ and not cmp_["p1_equal"]:
            print(f"\n{name}: printed, not predicted: {cmp_['printed_not_predicted']}")
            print(f"{name}: predicted, not printed: {cmp_['predicted_not_printed']}")
            print(f"{name}: printed, not indexed by btrfska: {cmp_['printed_not_indexed']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="measure images and append to the results")
    run_cmd.add_argument("images", nargs="*", type=Path)
    run_cmd.add_argument(
        "--max-states",
        type=int,
        default=MAX_STATES,
        help="root trees btrfska evaluates as states (added for §6.8: m4_deep has more "
        f"candidates than the default {MAX_STATES})",
    )
    table_cmd = commands.add_parser("table", help="print the tables of EXP-004.md")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.images or default_images(), args.results, args.max_states)
    else:
        table(args.results)


if __name__ == "__main__":
    main()
