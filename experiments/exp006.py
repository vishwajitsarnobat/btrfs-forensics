"""EXP-006: which recovery source gives back which file, on a history deeper than the backup roots.

The hypothesis and predictions are in experiments/EXP-006.md §1. Scenario `deep` (the recipe of
corpus image `m4_deep`) logs the SHA-256 of every file it later deletes: 24 victims, each
committed in exactly one generation; 8 flash files, fsynced and deleted within one transaction;
one file unlinked while open at the last commit.

For every build: catalog with a full sweep, then `recover --root all --orphans --tree all`. A
logged file counts for a source when an artifact of that source is `complete` and has its hash.
Sources, in the order a tool would reach for them:
  backup     the current root and the four backup roots (what superblock-anchored tools see)
  beyond     cataloged states that no superblock slot names
  orphan     leaves that no root tree leads to, dropped log trees included
  item       inodes the last committed tree lists under ORPHAN_ITEM

Usage, from the repo root:
  uv run python experiments/exp006.py run [--builds 5]   # builds, measures, deletes the builds
  uv run python experiments/exp006.py run --image images/scenarios/m4_deep.img   # one built image
  uv run python experiments/exp006.py table
Both take `--results PATH` (default images/scratch/exp/EXP-006/results.jsonl).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
from pathlib import Path

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-006"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
TRUTH = re.compile(r"=== (VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})")
BUILD_ENV = {
    "CSUM": "xxhash",
    "SCENARIO": "deep",
    "MOUNT_OPTS": "commit=300",
    "DONE_MARKER": "=== DEEP-POWEROFF",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def truth_of(log: Path) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {"VICTIM": {}, "FLASH": {}, "ORPHAN": {}}
    for kind, name, digest in TRUTH.findall(log.read_text()):
        found[kind][name] = digest
    return found


def classify(rows: list[dict], named_states: set[int], digest: str) -> list[str]:
    """The sources that give back, complete, the file with this hash."""
    sources = set()
    for row in rows:
        if row["status"] != "complete" or row["sha256"] != digest:
            continue
        if row["source_kind"] == "anchored_root":
            sources.add("backup" if row["state_id"] in named_states else "beyond")
        else:
            sources.add("orphan" if row["source_kind"] == "orphan_node" else "item")
    return sorted(sources)


def measure(image: Path) -> dict:
    truth = truth_of(image.with_suffix(".log"))
    work = OUT / "work" / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    try:
        build_catalog(image, work / "evidence.db", full_sweep=True)
        done = recover(image, work / "evidence.db", work / "out", roots=("all",), tree_id=None,
                       orphans=True)  # fmt: skip
        conn = db.open_readonly(work / "evidence.db")
        query = "SELECT source_kind, state_id, status, sha256 FROM artifacts WHERE kind = 'file'"
        rows = [dict(r) for r in conn.execute(query)]
        states = conn.execute("SELECT state_id, generation, known_as FROM states").fetchall()
        scan = conn.execute("SELECT generation FROM scan_runs").fetchone()
        capped = conn.execute("SELECT COUNT(*) FROM problems WHERE source = 'roots'").fetchone()[0]
        conn.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    named = {s["state_id"] for s in states if json.loads(s["known_as"])}
    files = {
        kind: {name: classify(rows, named, digest) for name, digest in entries.items()}
        for kind, entries in truth.items()
    }
    return {
        "image": image.name,
        "sha256": before,
        "unchanged": sha256(image) == before,
        "superblock_generation": scan[0],
        "states": len(states),
        "states_named_by_the_superblock": len(named),
        "state_bound_hit": bool(capped),
        "orphan_leaves": done.orphan_leaves,
        "artifacts": done.counts,
        "files": files,
    }


def build(name: str) -> Path:
    subprocess.run(
        [str(REPO / "corpus" / "vm" / "make_image.sh"), name],
        env=os.environ | BUILD_ENV, check=True, stdout=subprocess.DEVNULL,
    )  # fmt: skip
    return SCENARIOS / f"{name}.img"


def run(results: Path, builds: int, image: Path | None) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as out:
        if image is not None:
            out.write(json.dumps(measure(image)) + "\n")
            return
        subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                       stdout=subprocess.DEVNULL)  # fmt: skip
        for number in range(1, builds + 1):
            path = build(f"exp006_r{number}")
            try:
                record = measure(path)
            finally:
                path.unlink(missing_ok=True)
                path.with_suffix(".log").unlink(missing_ok=True)
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(
                f"done   {record['image']}: generation {record['superblock_generation']}, "
                f"{record['states']} states, {record['orphan_leaves']} orphan leaves"
            )


def summary(record: dict) -> dict[str, int]:
    victims, flash = record["files"]["VICTIM"], record["files"]["FLASH"]
    (orphan,) = record["files"]["ORPHAN"].values()
    return {
        "superblock generation": record["superblock_generation"],
        "states": record["states"],
        "of them named by the superblock": record["states_named_by_the_superblock"],
        "orphan leaves": record["orphan_leaves"],
        "victims": len(victims),
        "victims from the current or a backup root": sum("backup" in s for s in victims.values()),
        "victims only from states beyond them": sum(
            "beyond" in s and "backup" not in s for s in victims.values()
        ),
        "victims only from an orphan leaf": sum(s == ["orphan"] for s in victims.values()),
        "victims not recovered": sum(not s for s in victims.values()),
        "flash files": len(flash),
        "flash files from any root": sum(
            bool({"backup", "beyond"} & set(s)) for s in flash.values()
        ),
        "flash files only from an orphan leaf": sum(s == ["orphan"] for s in flash.values()),
        "flash files not recovered": sum(not s for s in flash.values()),
        "open-unlinked file as orphan_item": int("item" in orphan),
    }


def table(results: Path) -> None:
    records = [json.loads(line) for line in results.read_text().splitlines()]
    rows = [summary(r) for r in records]
    print(f"N = {len(rows)} builds; images unchanged by the measurement: "
          f"{sum(r['unchanged'] for r in records)}; state bound hit: "
          f"{sum(r['state_bound_hit'] for r in records)}\n")  # fmt: skip
    print("| Quantity | Median | Range |")
    print("|---|---|---|")
    for key in rows[0]:
        values = [row[key] for row in rows]
        print(f"| {key} | {statistics.median(values):g} | {min(values)}–{max(values)} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="build, measure and append to the results")
    run_cmd.add_argument("--builds", type=int, default=5)
    run_cmd.add_argument("--image", type=Path, help="measure this built image instead")
    table_cmd = commands.add_parser("table", help="print the table of EXP-006.md §6")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.results, args.builds, args.image)
    else:
        table(args.results)


if __name__ == "__main__":
    main()
