"""EXP-007: reading a pre-balance state through the chunk map of its own time.

The hypothesis and predictions are in experiments/EXP-007.md §1. Scenario `s01` (the recipe of the
corpus images `s01_discard_{none,async,sync}_r1`) logs the SHA-256 of three files, snapshots them,
deletes two and then balances: every chunk gets a new address and the old chunks are removed.

For every build: catalog with a full sweep, then `recover --root all --tree all` twice, with
`--maps current` (the current chunk map only) and with `--maps own` (each root's own map first).
Measured: the files the current map leaves `partial` with `unmapped` ranges, and what becomes of
them; the valid tree blocks outside the current map, and which maps place them where they lie
(recomputed here from `chunks` and `stripes`); the stripes a DEV_EXTENT confirms; and the map
built from DEV_EXTENTs alone against the CHUNK_ITEM maps.

Usage, from the repo root:
  uv run python experiments/exp007.py run [--builds 5] [--modes none async sync]
  uv run python experiments/exp007.py run --image images/scenarios/s01_discard_none_r1.img
  uv run python experiments/exp007.py table
Both take `--results PATH` (default images/scratch/exp/EXP-007/results.jsonl).
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
from btrfska.catalog.schema import u64
from btrfska.recover.engine import recover
from btrfska.substrate.chunks import Chunk, ChunkMap, MappingError, Stripe

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-007"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
TRUTH = re.compile(r"([0-9a-f]{64})\s+/mnt/sv1/(\S+)")
EMPTY = hashlib.sha256(b"").hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def stored_map(conn, map_id: int) -> ChunkMap:
    chunks = []
    for row in conn.execute("SELECT * FROM chunks WHERE map_id = ? AND accepted", (map_id,)):
        stripes = tuple(
            Stripe(u64(s["devid"]), u64(s["physical"]), bytes.fromhex(s["dev_uuid"]))
            for s in conn.execute(
                "SELECT * FROM stripes WHERE chunk_id = ? ORDER BY stripe_index", (row["chunk_id"],)
            )
        )
        chunks.append(
            Chunk(u64(row["logical"]), u64(row["length"]), u64(row["type"]), stripes,
                  row["sub_stripes"])
        )  # fmt: skip
    devices = {s.devid: s.dev_uuid for c in chunks for s in c.stripes}
    return ChunkMap(str(map_id), chunks, devices)


def files_of(conn, recovery_id: int) -> dict[tuple, dict]:
    rows = conn.execute(
        "SELECT * FROM artifacts WHERE recovery_id = ? AND kind = 'file'", (recovery_id,)
    ).fetchall()
    return {
        (r["state_id"], r["tree_id"], r["objectid"], r["inode_generation"]): dict(r) for r in rows
    }


def resolved(conn, row: dict) -> dict:
    """The artifact that holds the content: a duplicate points at the copy written first."""
    if row["status"] != "duplicate":
        return row
    found = conn.execute(
        "SELECT * FROM artifacts WHERE artifact_id = ?", (row["duplicate_of"],)
    ).fetchone()
    return dict(found)


def files(conn, runs: dict[str, int], truth: dict[str, str]) -> dict:
    before, after = files_of(conn, runs["current"]), files_of(conn, runs["own"])
    unmapped = [
        key
        for key, row in before.items()
        if row["status"] == "partial"
        and any(reason == "unmapped" for _, _, reason in json.loads(row["missing"]))
    ]
    gained = [k for k in unmapped if resolved(conn, after[k])["status"] == "complete"]
    exact = [
        k
        for k in gained
        if truth.get(after[k]["path"].rsplit("/", 1)[-1]) == resolved(conn, after[k])["sha256"]
    ]
    wrong, empty = [], 0
    for row in after.values():
        name, content = row["path"].rsplit("/", 1)[-1], resolved(conn, row)
        if content["status"] != "complete" or name not in truth:
            continue
        if content["sha256"] == EMPTY and content["size"] == 0:
            empty += 1  # an early version of size 0: read through no map at all
        elif content["sha256"] != truth[name]:
            wrong.append(row["path"])
    others = [k for k in before if k not in unmapped]
    same = sum(
        (before[k]["status"], before[k]["sha256"]) == (after[k]["status"], after[k]["sha256"])
        for k in others
    )
    return {
        "states_with_another_chunk_root": conn.execute(
            "SELECT COUNT(*) FROM states WHERE chunk_root_differs"
        ).fetchone()[0],
        "partial_unmapped_under_current": len(unmapped),
        "of_them_complete_under_own": len(gained),
        "of_them_with_the_logged_hash": len(exact),
        "distinct_logged_files_gained": len({after[k]["path"].rsplit("/", 1)[-1] for k in exact}),
        "still_partial_under_own": sum(
            resolved(conn, r)["status"] == "partial" for r in after.values()
        ),
        "complete_with_a_wrong_hash": len(wrong),
        "empty_early_versions": empty,
        "other_files": len(others),
        "other_files_unchanged": same,
    }


def blocks(conn) -> dict:
    nodesize = conn.execute("SELECT nodesize FROM scan_runs").fetchone()[0]
    maps = [
        (r["map_id"], r["kind"], u64(r["root_generation"]), stored_map(conn, r["map_id"]))
        for r in conn.execute("SELECT * FROM chunk_maps WHERE kind != 'current'")
    ]
    historical = sorted((m for m in maps if m[1] == "historical"), key=lambda m: m[2])
    outside = conn.execute("SELECT * FROM nodes WHERE valid AND NOT maps_here").fetchall()
    stored = {tuple(r) for r in conn.execute("SELECT node_id, map_id FROM node_maps")}
    placed_any = placed_own = placed_by_dev_extents = disagree = 0

    def places(chunk_map: ChunkMap, node) -> bool:
        try:
            copies = chunk_map.copies(u64(node["bytenr"]), nodesize)
        except MappingError:
            return False
        return any(copy.physical == node["physical"] for copy in copies)

    for node in outside:
        found = {map_id for map_id, _, _, chunk_map in maps if places(chunk_map, node)}
        disagree += found != {m for n, m in stored if n == node["node_id"]}
        placed_any += bool(found & {m[0] for m in historical})
        placed_by_dev_extents += bool(found & {m[0] for m in maps if m[1] == "dev_extents"})
        older = [m for m in historical if m[2] <= u64(node["generation"])]
        placed_own += bool(older) and older[-1][0] in found
    return {
        "historical_maps": len(historical),
        "valid_blocks_outside_the_current_map": len(outside),
        "placed_by_some_historical_map": placed_any,
        "placed_by_the_map_of_their_own_time": placed_own,
        "placed_by_the_dev_extents_map": placed_by_dev_extents,
        "blocks_where_node_maps_differs_from_the_recount": disagree,
    }


def second_witness(conn) -> dict:
    stripes = conn.execute(
        "SELECT s.dev_extents FROM stripes s JOIN chunks c USING (chunk_id)"
        " JOIN chunk_maps m USING (map_id) WHERE m.kind = 'historical' AND c.accepted"
    ).fetchall()
    known: dict[int, set] = {}
    alone: dict[int, tuple] = {}
    for row in conn.execute("SELECT map_id, kind FROM chunk_maps"):
        for chunk in stored_map(conn, row["map_id"]).chunks:
            placement = (chunk.length, tuple(sorted((s.devid, s.offset) for s in chunk.stripes)))
            if row["kind"] == "dev_extents":
                alone[chunk.logical] = placement
            else:
                known.setdefault(chunk.logical, set()).add(placement)
    rejected = conn.execute(
        "SELECT COUNT(*) FROM chunks JOIN chunk_maps USING (map_id)"
        " WHERE kind = 'dev_extents' AND NOT accepted"
    ).fetchone()[0]
    both = set(alone) & set(known)
    return {
        "historical_stripes": len(stripes),
        "of_them_confirmed_by_a_dev_extent": sum(bool(r[0]) for r in stripes),
        "chunks_known_both_ways": len(both),
        "of_them_agreeing": sum(known[k] == {alone[k]} for k in both),
        "chunks_only_from_dev_extents": len(set(alone) - set(known)),
        "chunks_only_from_chunk_items": len(set(known) - set(alone)),
        "dev_extent_chunks_rejected": rejected,
    }


def measure(image: Path, mode: str) -> dict:
    truth = {name: digest for digest, name in TRUTH.findall(image.with_suffix(".log").read_text())}
    work = OUT / "work" / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    try:
        build_catalog(image, work / "evidence.db", full_sweep=True)
        runs = {
            maps: recover(image, work / "evidence.db", work / f"out_{maps}", roots=("all",),
                          tree_id=None, maps=maps).recovery_id
            for maps in ("current", "own")
        }  # fmt: skip
        conn = db.open_readonly(work / "evidence.db")
        record = {
            "image": image.name,
            "mode": mode,
            "sha256": before,
            "superblock_generation": conn.execute("SELECT generation FROM scan_runs").fetchone()[0],
            "states": conn.execute("SELECT COUNT(*) FROM states").fetchone()[0],
            "bounds_hit": [
                r[0] for r in conn.execute(
                    "SELECT source FROM problems WHERE source IN ('roots', 'chunk_maps')"
                )
            ],
            "logged_files": len(truth),
            "files": files(conn, runs, truth),
            "blocks": blocks(conn),
            "witness": second_witness(conn),
        }  # fmt: skip
        conn.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record["unchanged"] = sha256(image) == before
    return record


def build(name: str, mode: str) -> Path:
    subprocess.run(
        [str(REPO / "corpus" / "vm" / "scenarios" / f"discard_{mode}.sh")],
        env=os.environ | {"NAME": name}, check=True, stdout=subprocess.DEVNULL,
    )  # fmt: skip
    return SCENARIOS / f"{name}.img"


def mode_of(image: Path) -> str:
    return next((m for m in ("none", "async", "sync") if f"_{m}" in image.stem), "unknown")


def run(results: Path, builds: int, modes: list[str], image: Path | None) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as out:
        if image is not None:
            out.write(json.dumps(measure(image, mode_of(image))) + "\n")
            return
        subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                       stdout=subprocess.DEVNULL)  # fmt: skip
        for mode in modes:
            for number in range(1, builds + 1):
                path = build(f"exp007_{mode}_r{number}", mode)
                try:
                    record = measure(path, mode)
                finally:
                    path.unlink(missing_ok=True)
                    path.with_suffix(".log").unlink(missing_ok=True)
                out.write(json.dumps(record) + "\n")
                out.flush()
                f = record["files"]
                print(
                    f"done   {record['image']}: {f['partial_unmapped_under_current']} unmapped, "
                    f"{f['of_them_with_the_logged_hash']} hash-exact under their own map"
                )


def table(results: Path) -> None:
    records = [json.loads(line) for line in results.read_text().splitlines()]
    for mode in dict.fromkeys(r["mode"] for r in records):
        fresh = [r for r in records if r["mode"] == mode and r["image"].startswith("exp007_")]
        kept = [r for r in records if r["mode"] == mode and r not in fresh]
        for label, group in ((f"{mode}: fresh builds", fresh), (f"{mode}: corpus image", kept)):
            if not group:
                continue
            print(f"\n### {label} (N = {len(group)}); unchanged by the measurement: "
                  f"{sum(r['unchanged'] for r in group)}; bounds hit: "
                  f"{sum(bool(r['bounds_hit']) for r in group)}\n")  # fmt: skip
            print("| Quantity | Median | Range |")
            print("|---|---|---|")
            rows = [
                {"superblock generation": r["superblock_generation"], "states": r["states"]}
                | {k.replace("_", " "): v for part in ("files", "blocks", "witness")
                   for k, v in r[part].items()}
                for r in group
            ]  # fmt: skip
            for key in rows[0]:
                values = [row[key] for row in rows]
                print(f"| {key} | {statistics.median(values):g} | {min(values)}–{max(values)} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="build, measure and append to the results")
    run_cmd.add_argument("--builds", type=int, default=5)
    run_cmd.add_argument("--modes", nargs="+", default=["none", "async", "sync"],
                         choices=["none", "async", "sync"])  # fmt: skip
    run_cmd.add_argument("--image", type=Path, help="measure this built image instead")
    table_cmd = commands.add_parser("table", help="print the tables of EXP-007.md §6")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.results, args.builds, args.modes, args.image)
    else:
        table(args.results)


if __name__ == "__main__":
    main()
