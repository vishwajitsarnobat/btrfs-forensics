"""EXP-015: the reachability classes against the generation-defined orphans, block by block.

The hypothesis is in experiments/EXP-015.md §1. Every candidate tree block of one scan is counted
under both definitions:
- reachability (scan/classify.py): `live`, `backup_reachable`, `unreferenced` (the last two are
  the orphans) or `invalid`;
- the prototype's (`legacy_orphan`, legacy/utils/btree.py:472-517): a nodesize-aligned block whose
  checksum validates and whose generation is below the superblock's.
The cross table shows where the two agree; every block in a cell where they disagree (a legacy
orphan that is live or invalid, a reachability orphan that is not a legacy orphan) is listed with
its addresses, generation and owner. The scan is targeted and, as a check, a full sweep; both must
give the same table.

The images are fixed files, not guest runs: one run is deterministic for a given image hash.

Usage, from the repo root:
  uv run python experiments/exp015.py [IMAGE...] [--json OUT]   # default: sandbox.img
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from btrfska.scan.classify import STATUSES, scan_image
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image

REPO = Path(__file__).resolve().parents[1]
ORPHAN = ("backup_reachable", "unreferenced")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def signed(objectid: int) -> int:
    """Tree objectids above 2^63 are negative in the kernel's headers (e.g. -9, data reloc)."""
    return objectid - (1 << 64) if objectid >= 1 << 63 else objectid


def disagrees(legacy: bool, status: str) -> bool:
    """A legacy orphan that reachability does not call an orphan, or the reverse."""
    return legacy != (status in ORPHAN)


def measure(path: Path, full_sweep: bool = False) -> dict:
    with open_image(path) as img:
        fs = open_filesystem(img)
        scan = scan_image(img, fs, full_sweep=full_sweep)
        cells, blocks = Counter(), []
        for c in scan.classified:
            key = (c.legacy_orphan, c.status, c.outside_map)
            cells[key] += 1
            if disagrees(c.legacy_orphan, c.status):
                r = c.record
                blocks.append({
                    "legacy_orphan": c.legacy_orphan, "status": c.status,
                    "outside_map": c.outside_map, "physical": r.physical, "bytenr": r.bytenr,
                    "generation": r.generation, "owner": signed(r.owner), "level": r.level,
                    "failed": [check.name for check in r.checks if check.ok is False],
                })  # fmt: skip
        summary = scan.summary
        return {
            "image": path.name,
            "full_sweep": full_sweep,
            "superblock_generation": fs.fields["generation"],
            "candidates": summary["candidates"],
            "cells": [
                {"legacy_orphan": k[0], "status": k[1], "outside_map": k[2], "blocks": n}
                for k, n in sorted(cells.items())
            ],
            "disagreements": blocks,
        }


def report(result: dict) -> str:
    cells = Counter()
    outside = Counter()
    for cell in result["cells"]:
        cells[cell["legacy_orphan"], cell["status"]] += cell["blocks"]
        if cell["outside_map"]:
            outside[cell["legacy_orphan"], cell["status"]] += cell["blocks"]
    mode = "full sweep" if result["full_sweep"] else "targeted"
    lines = [
        f"{result['image']} ({mode}): {result['candidates']} candidates, superblock generation "
        f"{result['superblock_generation']}",
        "",
        "| Class | Legacy orphan (outside map) | Not a legacy orphan (outside map) | Total |",
        "|---|---|---|---|",
    ]
    for status in STATUSES:
        yes, no = cells[True, status], cells[False, status]
        lines.append(
            f"| `{status}` | {yes} ({outside[True, status]}) | {no} ({outside[False, status]}) "
            f"| {yes + no} |"
        )
    legacy = sum(n for (flag, _), n in cells.items() if flag)
    orphans = sum(n for (_, status), n in cells.items() if status in ORPHAN)
    lines.append(f"| **Total** | {legacy} | {result['candidates'] - legacy} | "
                 f"{result['candidates']} |")  # fmt: skip
    lines += ["", f"legacy orphans: {legacy}; reachability orphans: {orphans}; blocks where the "
              f"definitions disagree: {len(result['disagreements'])}", ""]  # fmt: skip
    lines.append("| Legacy orphan | Class | Physical | Bytenr | Generation | Owner | Level "
                 "| Outside map | Failed checks |")  # fmt: skip
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for b in result["disagreements"]:
        lines.append(
            f"| {'yes' if b['legacy_orphan'] else 'no'} | `{b['status']}` | {b['physical']} "
            f"| {b['bytenr']} | {b['generation']} | {b['owner']} | {b['level']} "
            f"| {'yes' if b['outside_map'] else 'no'} | {', '.join(b['failed']) or '-'} |"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("images", nargs="*", type=Path, default=[REPO / "sandbox.img"])
    parser.add_argument("--json", type=Path, help="also write the results as JSON (under images/)")
    args = parser.parse_args(argv)
    results = []
    for path in args.images:
        before = sha256(path)
        targeted, full = measure(path), measure(path, full_sweep=True)
        after = sha256(path)
        same = {k: targeted[k] for k in ("cells", "disagreements")} == {
            k: full[k] for k in ("cells", "disagreements")
        }
        print(report(targeted))
        print(f"\nfull sweep gives the same table and blocks: {same}")
        print(f"image sha256 before {before}, after {after}\n")
        results.append({"targeted": targeted, "full": full, "sha256": before, "unchanged":
                        before == after, "full_equals_targeted": same})  # fmt: skip
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
