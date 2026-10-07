"""EXP-018: what of an earlier filesystem survives a reformat or an fsid change, and whether the
foreign-FSID scan (plan.md M6f) finds, validates and identifies it.

The hypothesis and predictions are in experiments/EXP-018.md §1. Every build regenerates the four
M6f corpus rows (corpus/manifest.tsv: m6_reformat, m6_reformat_geometry, m6_fsid_u, m6_fsid_m)
with their own scenario drivers into images/scratch/exp/EXP-018/builds/, reads each serial log
for the fsid, device uuid and geometry of each life, and runs `foreign_scan` over the targeted
scan plan. `control` runs the same scan over every image of images/scenarios/ that is not an M6f
row, and sandbox.img.

Usage, from the repo root:
  uv run python experiments/exp018.py run [--builds 5]
  uv run python experiments/exp018.py control
  uv run python experiments/exp018.py table
All take `--results DIR` (default images/scratch/exp/EXP-018). Builds are deleted after measuring.
Set VM_DIR to build with a private copy of the guest tooling.
"""

import argparse
import json
import os
import re
import statistics
import subprocess
from pathlib import Path

from btrfska.scan.foreign import foreign_scan
from btrfska.scan.regions import plan_scan
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-018"
SCENARIOS = REPO / "images" / "scenarios"
LIFE = re.compile(
    r"=== FS fsid (\S+) metadata_uuid (\S+) dev_uuid (\S+) nodesize (\d+) csum_type (\d+)"
)
# The manifest rows' environment, without NAME (corpus/manifest.tsv).
ROWS = {
    "m6_reformat": ("reformat.sh", {"NEW_LIFE": "0"}),
    "m6_reformat_geometry": (
        "reformat.sh",
        {"OLD_CSUM": "crc32c", "OLD_MKFS_ARGS": "-n 32768", "NEW_MKFS_ARGS": "--mixed -b 60M"},
    ),
    "m6_fsid_u": ("fsid_change.sh", {"TUNE": "-u"}),
    "m6_fsid_m": ("fsid_change.sh", {"TUNE": "-m"}),
}


def lives(log: Path) -> list[dict]:
    keys = ("fsid", "metadata_uuid", "dev_uuid", "nodesize", "csum_type")
    return [dict(zip(keys, match, strict=True)) for match in LIFE.findall(log.read_text())]


def measure(path: Path, log: Path | None) -> dict:
    """The foreign summary of one image, reduced to what EXP-018.md §1 names."""
    with open_image(path) as img:
        before = img.sha256()
        fs = open_filesystem(img)
        plan = plan_scan(fs, img.size)
        summary = foreign_scan(img, fs, plan.regions)
        generation = fs.fields["generation"]
        after = img.sha256()
    first = lives(log)[0] if log else None
    result = {
        "image": path.name,
        "generation": generation,
        "unchanged": before == after,
        "metadata_uuid_change": summary["metadata_uuid_change"],
        "old_fsid": first and first["fsid"],
        "old_geometry": first and [int(first["nodesize"]), int(first["csum_type"])],
        "filesystems": [],
    }
    for found in summary["filesystems"]:
        context = found["context"]
        result["filesystems"].append(
            {key: found[key] for key in ("fsid", "kind", "candidates", "valid", "invalid",
                                          "generations", "device_uuids", "census_blocks")}
            | {"source": context["source"],
               "geometry": [context["nodesize"], context["csum_type"]],
               "is_old_fsid": found["fsid"] == (first and first["fsid"])}
        )  # fmt: skip
    return result


def build(row: str, index: int, directory: Path) -> Path:
    script, env = ROWS[row]
    name = f"exp018_{row}_{index}"
    environment = os.environ | env | {"NAME": name, "OUT_DIR": str(directory)}
    subprocess.run(
        [str(REPO / "corpus" / "vm" / "scenarios" / script)],
        env=environment, cwd=REPO, check=True, stdout=subprocess.DEVNULL,
    )  # fmt: skip
    return directory / f"{name}.img"


def cmd_run(args) -> None:
    builds = args.results / "builds"
    builds.mkdir(parents=True, exist_ok=True)
    with (args.results / "results.jsonl").open("a") as out:
        for index in range(1, args.builds + 1):
            for row in ROWS:
                image = build(row, index, builds)
                result = {"row": row, "build": index} | measure(image, image.with_suffix(".log"))
                out.write(json.dumps(result) + "\n")
                out.flush()
                image.unlink()
                print(row, index, json.dumps(result["filesystems"])[:200], flush=True)


def cmd_control(args) -> None:
    args.results.mkdir(parents=True, exist_ok=True)
    images = [REPO / "sandbox.img"] + sorted(
        p for p in SCENARIOS.glob("*.img") if not p.stem.startswith(tuple(ROWS))
    )
    with (args.results / "control.jsonl").open("w") as out:
        for image in images:
            try:
                result = measure(image, None)
            except Exception as exc:  # a refused image (unknown incompat bit) is reported
                result = {"image": image.name, "refused": str(exc)}
            out.write(json.dumps(result) + "\n")
            print(image.name, json.dumps(result.get("filesystems", result))[:200], flush=True)


def spread(values: list[int]) -> str:
    return f"{statistics.median(values):g} ({min(values)}-{max(values)})"


def cmd_table(args) -> None:
    rows = [json.loads(line) for line in (args.results / "results.jsonl").open()]
    print("| Row | N | kind (all builds) | context | old-fsid valid | old-fsid invalid |")
    print("|---|---|---|---|---|---|")
    for row in ROWS:
        runs = [r for r in rows if r["row"] == row]
        olds = [next((f for f in r["filesystems"] if f["is_old_fsid"]), None) for r in runs]
        if all(f is None for f in olds):
            changes = sum(r["metadata_uuid_change"] is not None for r in runs)
            others = sum(len(r["filesystems"]) for r in runs)
            print(f"| `{row}` | {len(runs)} | none found ({others} other); metadata_uuid change in "
                  f"{changes} | - | - | - |")  # fmt: skip
            continue
        kinds = sorted({f["kind"] if f else "missed" for f in olds})
        contexts = sorted({f"{f['source']} {f['geometry']}" for f in olds if f})
        valid = [f["valid"] if f else 0 for f in olds]
        invalid = [f["invalid"] if f else 0 for f in olds]
        print(f"| `{row}` | {len(runs)} | {', '.join(kinds)} | {'; '.join(contexts)} | "
              f"{spread(valid)} | {spread(invalid)} |")  # fmt: skip
    extra = sum(len([f for f in r["filesystems"] if not f["is_old_fsid"]]) for r in rows)
    changed = sum(not r["unchanged"] for r in rows)
    print(f"\nforeign filesystems other than the old fsid: {extra}; images changed: {changed}")
    control = args.results / "control.jsonl"
    if control.exists():
        found = [json.loads(line) for line in control.open()]
        flagged = [r["image"] for r in found if r.get("filesystems")]
        print(f"control: {len(found)} images, foreign filesystem reported on: {flagged}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("run", "control", "table"))
    parser.add_argument("--builds", type=int, default=5)
    parser.add_argument("--results", type=Path, default=OUT)
    args = parser.parse_args()
    {"run": cmd_run, "control": cmd_control, "table": cmd_table}[args.command](args)


if __name__ == "__main__":
    main()
