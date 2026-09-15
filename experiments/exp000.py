"""EXP-000: the research.md §10.4 discard table, regenerated N times (plan.md §7 backfill).

Each run calls `corpus/vm/discard_table.sh` with RUN=<n>. It builds
`images/scenarios/s01_discard_{none,async,sync}_r<n>.img` (and `.log`) in a rootless QEMU/KVM
guest, one mode after the other, and prints one `probe_stale_metadata.py` row per mode. Runs are
strictly sequential. Raw results accumulate in `images/scratch/exp/EXP-000/runs.jsonl`, one line
per image, so an interrupted series resumes where it stopped.

Usage, from the repo root:
  uv run python experiments/exp000.py run --runs 5     # runs 1..5, skipping runs already recorded
  uv run python experiments/exp000.py table            # per mode and column: median (min-max)
  uv run python experiments/exp000.py keep             # the representative run of each mode
  uv run python experiments/exp000.py clean            # delete every image and log but those

The representative run of a mode is the one whose four columns lie closest to that mode's
per-column medians (sum of absolute deviations; ties go to the lower run number).
"""

import argparse
import hashlib
import json
import os
import statistics
import struct
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-000"
RUNS = OUT / "runs.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
MODES = ("none", "async", "sync")
COLUMNS = ("fsid_blocks", "stale_blocks", "needle_copies", "nonzero_blocks")
# research.md §10.4 as of M2a (single run; the jitter note cites 365/353/16/828 for one rerun).
PRIOR = {"none": (367, 355, 18, 832), "async": (367, 355, 18, 832), "sync": (43, 31, 2, 107)}


def image_path(mode: str, run: int) -> Path:
    return SCENARIOS / f"s01_discard_{mode}_r{run}.img"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:  # read-only
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def load() -> list[dict]:
    if not RUNS.exists():
        return []
    return [json.loads(line) for line in RUNS.read_text().splitlines() if line.strip()]


def mounted(log: Path) -> str:
    lines = [line for line in log.read_text().splitlines() if line.startswith("=== MOUNTED")]
    return lines[0] if lines else ""


def run(runs: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    done = {row["run"] for row in load()}
    for number in range(1, runs + 1):
        if number in done:
            print(f"run {number}: already recorded")
            continue
        started = time.monotonic()
        env = os.environ | {"RUN": str(number)}
        output = subprocess.run(
            [str(REPO / "corpus" / "vm" / "discard_table.sh")],
            env=env, capture_output=True, text=True, check=True, cwd=REPO,
        ).stdout  # fmt: skip
        wall = round(time.monotonic() - started, 2)
        rows = {}
        for line in output.splitlines():
            mode, *values = line.split()
            rows[mode] = [int(v) for v in values]
        with RUNS.open("a") as f:
            for mode in MODES:
                path = image_path(mode, number)
                with open(path, "rb") as image:  # read-only
                    image.seek(0x10000 + 0x48)
                    generation = struct.unpack("<Q", image.read(8))[0]
                record = {
                    "run": number, "mode": mode, "name": path.stem,
                    **dict(zip(COLUMNS, rows[mode], strict=True)),
                    "superblock_generation": generation, "sha256": sha256(path),
                    "mounted": mounted(path.with_suffix(".log")), "table_wall_s": wall,
                }  # fmt: skip
                f.write(json.dumps(record) + "\n")
        print(f"run {number}: {output.strip().replace(chr(10), ' | ')} ({wall} s)")


def summary() -> dict:
    rows = load()
    result = {}
    for mode in MODES:
        mine = [row for row in rows if row["mode"] == mode]
        result[mode] = {
            "n": len(mine),
            **{
                column: (
                    statistics.median(row[column] for row in mine),
                    min(row[column] for row in mine),
                    max(row[column] for row in mine),
                )
                for column in COLUMNS
            },
        }
    return result


def representatives() -> dict[str, int]:
    rows, medians = load(), summary()
    chosen = {}
    for mode in MODES:
        mine = sorted((row for row in rows if row["mode"] == mode), key=lambda r: r["run"])
        chosen[mode] = min(
            mine,
            key=lambda r: (sum(abs(r[c] - medians[mode][c][0]) for c in COLUMNS), r["run"]),
        )["run"]
    return chosen


def table() -> None:
    result = summary()
    print("| Mode | N | " + " | ".join(COLUMNS) + " |")
    print("|---|---|" + "---|" * len(COLUMNS))
    for mode in MODES:
        cells = [
            f"{median:g} ({low}–{high})" for median, low, high in (result[mode][c] for c in COLUMNS)
        ]
        print(f"| {mode} | {result[mode]['n']} | " + " | ".join(cells) + " |")
    print()
    print("| Mode | research.md §10.4 before | medians now | differs |")
    print("|---|---|---|---|")
    for mode in MODES:
        now = tuple(result[mode][c][0] for c in COLUMNS)
        before = PRIOR[mode]
        differs = [c for c, b, m in zip(COLUMNS, before, now, strict=True) if b != m]
        print(f"| {mode} | {'/'.join(map(str, before))} | {'/'.join(f'{m:g}' for m in now)} | "
              f"{', '.join(differs) or 'no'} |")  # fmt: skip
    print()
    for row in load():
        print(
            f"run {row['run']} {row['mode']}: "
            + " ".join(str(row[c]) for c in COLUMNS)
            + f"  generation {row['superblock_generation']}  {row['sha256'][:16]}"
        )


def clean() -> None:
    keep = representatives()
    for row in load():
        if keep[row["mode"]] == row["run"]:
            print(f"keep {row['name']} ({row['sha256']})")
            continue
        for suffix in (".img", ".log"):
            path = (SCENARIOS / row["name"]).with_suffix(suffix)
            if path.exists():
                path.unlink()
                print(f"deleted {path.relative_to(REPO)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("--runs", type=int, default=5)
    sub.add_parser("table")
    sub.add_parser("keep")
    sub.add_parser("clean")
    args = parser.parse_args()
    if args.command == "run":
        run(args.runs)
    elif args.command == "table":
        table()
    elif args.command == "keep":
        print(json.dumps(representatives()))
    else:
        clean()


if __name__ == "__main__":
    main()
