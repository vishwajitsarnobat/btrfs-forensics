"""EXP-002: btrfska on the discard trio: agreement with the probe, reachability classes and
old-root discovery.

For every image given:
1. `corpus/vm/probe_stale_metadata.py`, run unchanged as a subprocess, prints fsid_blocks,
   stale_blocks, needle_copies and nonzero_blocks.
2. `probe_compat` recomputes the first two columns from btrfska's full-sweep scan candidates under
   the probe's own rules (below). The per-image DoD is exact equality.
3. btrfska's own classes (`scan_image`, full sweep) and old-root discovery (`discover_image`, full
   sweep).
Results go to `images/scratch/exp/EXP-002/results.jsonl`, one line per image.

**Probe rules against btrfska** (`probe_stale_metadata.py`; `scan/regions.py`, `kernel_numpy.py`):
- Both probe 4 KiB-aligned offsets and count one whose 16 bytes at +0x20 equal the fsid.
- Skipped offsets. The probe skips exactly the 4 KiB blocks at 0x10000, 64 MiB and 256 GiB.
  btrfska's full sweep skips the `reserved` range [0, 0x11000) (the first 64 KiB and the primary
  superblock) and each other superblock copy inside the image, [64 MiB, 64 MiB + 4 KiB) and
  [256 GiB, 256 GiB + 4 KiB). So blocks 0-15 (bytes 0-0xFFFF) are probed by the probe only, and no
  block by btrfska only. `probe_compat` derives both sets from the plan rather than assuming them,
  reads the probe-only blocks with the probe's rule and adds their hits.
- fsid. The probe compares with the primary superblock's `fsid`; btrfska with the tree fsid
  (`metadata_uuid` when METADATA_UUID is set). Recorded as `fsid_equal`.
- Generation. The probe compares with the primary superblock's generation; btrfska's scan with
  the selected copy's. Recorded as `generation_equal`; the compat count uses the primary's.
- Validity. The probe checks nothing else. btrfska records every prefilter hit, invalid ones
  included, so the compat count takes every candidate and compares its header generation.
- A block cut by the image end: both read the header when it lies inside the image; on these
  512 MiB images every block is whole.

Usage, from the repo root:
  uv run python experiments/exp002.py run IMAGE...   # append one JSON line per image
  uv run python experiments/exp002.py table          # agreement, classes and discovery per mode
"""

import argparse
import json
import re
import statistics
import struct
import subprocess
import sys
from pathlib import Path

from btrfska.scan.classify import scan_image
from btrfska.scan.kernel_numpy import iter_candidate_nodes
from btrfska.scan.regions import plan_scan
from btrfska.scan.roots import discover_image
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-002"
RESULTS = OUT / "results.jsonl"
PROBE = REPO / "corpus" / "vm" / "probe_stale_metadata.py"
BLOCK = 4096
PROBE_SKIP = (0x10000, 0x4000000, 0x4000000000)  # probe_stale_metadata.SB_OFFSETS
COLUMNS = ("fsid_blocks", "stale_blocks", "needle_copies", "nonzero_blocks")
MODES = ("none", "async", "sync")
CLASSES = (
    "candidates", "valid", "invalid", "live", "backup_reachable", "unreferenced",
    "outside_map_orphans", "legacy_orphans",
)  # fmt: skip
NAME = re.compile(r"s01_discard_(none|async|sync)(?:_r(\d+))?")


def probe_columns(path: Path) -> list[int]:
    output = subprocess.run(
        [sys.executable, str(PROBE), str(path)], capture_output=True, text=True, check=True
    ).stdout
    return [int(value) for value in output.split()]


def _ranges(blocks: list[int]) -> list[list[int]]:
    """Consecutive block numbers as [first, last] pairs."""
    ranges = []
    for block in blocks:
        if ranges and block == ranges[-1][1] + 1:
            ranges[-1][1] = block
        else:
            ranges.append([block, block])
    return ranges


def probe_compat(path: Path) -> dict:
    """The probe's fsid_blocks and stale_blocks, computed from btrfska's full-sweep candidates."""
    with open_image(path) as img:
        primary = bytes(img.mmap[0x10000 : 0x10000 + BLOCK])
        fsid = primary[0x20:0x30]
        sb_generation = struct.unpack_from("<Q", primary, 0x48)[0]
        fs = open_filesystem(img)
        ctx = fs.reader.ctx
        plan = plan_scan(fs, img.size, full_sweep=True)
        blocks = img.size // BLOCK
        probe_skip = {offset // BLOCK for offset in PROBE_SKIP if offset // BLOCK < blocks}

        def scanned(block: int) -> bool:
            return any(r.start <= block * BLOCK < r.end for r in plan.regions)

        probe_only = sorted(
            block
            for r in plan.skipped
            for block in range(-(-r.start // BLOCK), -(-r.end // BLOCK))
            if block < blocks and block not in probe_skip
        )
        btrfska_only = sorted(block for block in probe_skip if scanned(block))
        hits = stale = btrfska_only_hits = 0
        for record in iter_candidate_nodes(img, plan.regions, ctx, fs.chunk_map):
            old = record.generation is not None and record.generation < sb_generation
            if record.physical // BLOCK in btrfska_only:
                btrfska_only_hits += 1
                continue
            hits, stale = hits + 1, stale + old
        supplement_hits = supplement_stale = 0
        for block in probe_only:
            data = img.mmap[block * BLOCK : (block + 1) * BLOCK]
            if data[0x20:0x30] == fsid:
                supplement_hits += 1
                supplement_stale += struct.unpack_from("<Q", data, 0x50)[0] < sb_generation
        return {
            "fsid_blocks": hits + supplement_hits,
            "stale_blocks": stale + supplement_stale,
            "btrfska_candidates_compared": hits,
            "btrfska_stale_compared": stale,
            "probe_only_blocks": _ranges(probe_only),
            "probe_only_hits": supplement_hits,
            "btrfska_only_blocks": _ranges(btrfska_only),
            "btrfska_only_hits": btrfska_only_hits,
            "skipped_by_btrfska": [[r.kind, r.start, r.end] for r in plan.skipped],
            "fsid_equal": fsid == ctx.fsid,
            "generation_equal": sb_generation == ctx.generation,
            "sectorsize": ctx.sectorsize,
        }


def measure(path: Path) -> dict:
    match = NAME.fullmatch(path.stem)
    probe = probe_columns(path)
    compat = probe_compat(path)
    with open_image(path) as img:
        digest = img.sha256()
        fs = open_filesystem(img)
        scan = scan_image(img, fs, full_sweep=True)
        for _ in scan.classified:
            pass
        summary = scan.summary
        found = discover_image(img, fs, full_sweep=True).discovery
    states = [
        {
            "generation": s.generation, "bytenr": s.bytenr, "known_as": list(s.known_as),
            "found": s.found, "referenced": s.referenced, "completeness": s.completeness,
            "missing": s.missing, "trees": len(s.trees),
            "chunk_root_source": None if s.chunk_root is None else s.chunk_root.source,
        }
        for s in found.states
    ]  # fmt: skip
    backup_roots = [r for r in found.rediscovered if r.root.tree == "root"]
    return {
        "image": path.name,
        "mode": match[1] if match else None,
        "run": int(match[2]) if match and match[2] else None,
        "sha256": digest,
        "probe": dict(zip(COLUMNS, probe, strict=True)),
        "compat": compat,
        "agree": probe[:2] == [compat["fsid_blocks"], compat["stale_blocks"]],
        "classes": {name: summary[name] for name in CLASSES},
        "walk_failures": summary["walk_failures"],
        "discovery": {
            "indexed_copies": found.stats["indexed_copies"],
            "root_tree_candidates": found.root_tree_candidates,
            "states_evaluated": len(states),
            "known_roots": len(found.rediscovered),
            "known_roots_indexed": sum(r.indexed for r in found.rediscovered),
            "known_roots_candidates": sum(r.candidate for r in found.rediscovered),
            "root_tree_roots": [[r.root.source, r.indexed, r.candidate] for r in backup_roots],
            "beyond": sum(not s["known_as"] for s in states),
            "beyond_complete": sum(not s["known_as"] and s["completeness"] == 1 for s in states),
            "states": states,
        },
    }


def run(paths: list[Path]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a") as f:
        for path in paths:
            result = measure(path)
            f.write(json.dumps(result) + "\n")
            print(
                f"{path.name}: probe {result['probe']['fsid_blocks']} "
                f"{result['probe']['stale_blocks']}, compat {result['compat']['fsid_blocks']} "
                f"{result['compat']['stale_blocks']}, agree {result['agree']}"
            )


def cell(values: list[float]) -> str:
    if not values:
        return "—"
    median = statistics.median(values)
    text = (
        f"{median:.3f}" if isinstance(median, float) and not median.is_integer() else f"{median:g}"
    )
    return f"{text} ({min(values):g}–{max(values):g})"


def table() -> None:
    rows = [json.loads(line) for line in RESULTS.read_text().splitlines() if line.strip()]
    latest = {}
    for row in rows:  # the last measurement of each image wins
        latest[row["image"]] = row
    rows = sorted(latest.values(), key=lambda r: (MODES.index(r["mode"]), r["run"] or 0))
    print("| Image | probe fsid/stale | compat fsid/stale | agree |")
    print("|---|---|---|---|")
    for row in rows:
        p, c = row["probe"], row["compat"]
        print(f"| {row['image']} | {p['fsid_blocks']}/{p['stale_blocks']} | "
              f"{c['fsid_blocks']}/{c['stale_blocks']} | {row['agree']} |")  # fmt: skip
    runs = [row for row in rows if row["run"] is not None]
    print()
    print("| Mode | N | " + " | ".join(CLASSES) + " |")
    print("|---|---|" + "---|" * len(CLASSES))
    for mode in MODES:
        mine = [row for row in runs if row["mode"] == mode]
        cells = [cell([row["classes"][name] for row in mine]) for name in CLASSES]
        print(f"| {mode} | {len(mine)} | " + " | ".join(cells) + " |")
    print()
    keys = ("root_tree_candidates", "known_roots_indexed", "known_roots_candidates", "beyond",
            "beyond_complete")  # fmt: skip
    print("| Mode | N | " + " | ".join(keys) + " | backup-state completeness |")
    print("|---|---|" + "---|" * (len(keys) + 1))
    for mode in MODES:
        mine = [row for row in runs if row["mode"] == mode]
        cells = [cell([row["discovery"][key] for row in mine]) for key in keys]
        backup = [
            s["completeness"]
            for row in mine
            for s in row["discovery"]["states"]
            if any(k.startswith("backup:") for k in s["known_as"])
        ]
        print(f"| {mode} | {len(mine)} | " + " | ".join(cells) + f" | {cell(backup)} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("images", nargs="+", type=Path)
    sub.add_parser("table")
    args = parser.parse_args()
    if args.command == "run":
        run(args.images)
    else:
        table()


if __name__ == "__main__":
    main()
