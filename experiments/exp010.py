"""EXP-010: logical-range reuse, per-generation chunk maps against one merged map.

The hypothesis and predictions are in experiments/EXP-010.md §1. Scenario `reuse` (corpus image
`m5_reuse`) makes a new data chunk start at the logical address of a removed one, on other
physical bytes; scenario `reuse_same` (`m5_reuse_same`) the same on the removed chunk's own bytes.
Both log the SHA-256 of every file.

For every build: catalog with a full sweep, then `recover --root all --tree all` three times:
`--maps own` (btrfska's reading: each state through the map of its own time), `--maps current`,
and through one merged map. **The merged map is an emulation** of the design research.md §12
describes for mbkn-btrfs-rescue, built here from btrfska's catalog: the accepted chunks of every
historical map and of the current map, the chunk of the newest map winning per chunk start, and
a lookup that bisects on chunk start. It is not that tool's code and not a `recover` option
(plan.md M5f, decision 2).

Usage, from the repo root:
  uv run python experiments/exp010.py run [--builds 5] [--scenarios reuse reuse_same]
  uv run python experiments/exp010.py run --image images/scenarios/m5_reuse.img
  uv run python experiments/exp010.py table
Both take `--results PATH` (default images/scratch/exp/EXP-010/results.jsonl). Builds go through
corpus/vm/make_image.sh into images/scenarios/exp010_*, and are deleted after measuring; set
VM_DIR to build with a private copy of the guest tooling.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from btrfska import __version__
from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import u64
from btrfska.recover.engine import recover, recover_roots, resolve_all
from btrfska.recover.output import OutputTree
from btrfska.substrate import ondisk
from btrfska.substrate.chunks import BG, Chunk, ChunkMap, Stripe
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import NodeReader

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-010"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
TRUTH = re.compile(r"([0-9a-f]{64})\s+/mnt/(\S+)")
FREE = re.compile(r"=== FREE-PIECES (\d+)")
PIECE = 4 << 20
MERGED = "merged (emulation)"
REUSE_NOTE = "places this address in a different chunk"
REALLOC_NOTE = "the space was allocated again"
# The pieces each scenario writes per file (corpus/vm/scenarios/*.guest.sh); c.bin's count is in
# the log, and keep.txt is `seq 1 20000`.
PIECES = {
    "reuse": {"a.bin": 16, "z.bin": 32, "w.bin": 32, "b.bin": 10},
    "reuse_same": {"z.bin": 20, "w.bin": 5, "b.bin": 14},
}
KEEP_SIZE = len("".join(f"{n}\n" for n in range(1, 20001)))
READINGS = ("own", "current", "merged")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def stored_chunks(conn, map_id: int) -> list[Chunk]:
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
                  row["sub_stripes"], row["origin"])
        )  # fmt: skip
    return chunks


def dated_maps(conn) -> list[tuple[str, int, list[Chunk]]]:
    """(name, generation, chunks) of every historical map and the current one, oldest first.
    The current map is the newest even when its chunk root's generation is not recorded."""
    rows = conn.execute(
        "SELECT map_id, name, kind, root_generation FROM chunk_maps"
        " WHERE kind IN ('historical', 'current')"
    ).fetchall()
    maps = [
        (r["name"], 1 << 64 if r["kind"] == "current" else u64(r["root_generation"]),
         stored_chunks(conn, r["map_id"]))
        for r in rows
    ]  # fmt: skip
    return sorted(maps, key=lambda m: (m[1], m[0]))


class MergedMap(ChunkMap):
    """EMULATION of a merged newest-wins chunk map (research.md §12; not btrfska's reading).

    One chunk per start: of all the chunk records, the one from the newest map. A lookup takes
    the chunk with the greatest start not above the address, as a bisection on chunk start does,
    so chunks of different starts that overlap are all kept (ChunkMap would drop the later one).
    """

    def __init__(self, maps: list[tuple[str, int, list[Chunk]]], devices: dict[int, bytes]):
        newest: dict[int, Chunk] = {}
        for _, _, chunks in maps:  # oldest first: a newer record replaces an older one
            for chunk in chunks:
                newest[chunk.logical] = chunk
        super().__init__(MERGED, newest.values(), devices)
        self.chunks = tuple(sorted(newest.values(), key=lambda c: c.logical))
        self._starts = [chunk.logical for chunk in self.chunks]


class MergedReaders:
    """Every root read through the one merged map (the duck type of recover/maps.py's Readers)."""

    def __init__(self, current: NodeReader, merged: ChunkMap) -> None:
        self.current = current
        self.merged = NodeReader(current.img, merged, current.ctx)

    def reader(self, root) -> NodeReader:
        return self.merged


def recover_merged(image: Path, database: Path, output_dir: Path) -> int:
    """`recover --root all --tree all` with every state read through the merged map: the
    engine's own `recover_roots`, given MergedReaders. Returns the recovery id."""
    conn = db.open_for_recovery(database)
    try:
        roots = resolve_all(conn, ("all",), None, lambda line: None)
        with open_image(image) as img:
            fs = open_filesystem(img)
            no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
            merged = MergedMap(dated_maps(conn), fs.reader.chunk_map.devices)
            with OutputTree(output_dir) as out:
                options = {"roots": ["all"], "tree_id": "all", "maps": MERGED}
                recovery_id = conn.execute(
                    "INSERT INTO recovery_runs (tool_version, started_utc, image_path,"
                    " image_checked, output_dir, options) VALUES (?, ?, ?, 0, ?, ?)",
                    (__version__, datetime.now(UTC).isoformat(), os.fspath(image),
                     os.fspath(output_dir), json.dumps(options)),
                ).lastrowid  # fmt: skip
                recover_roots(conn, MergedReaders(fs.reader, merged), out, recovery_id, roots,
                              no_holes=no_holes)  # fmt: skip
                conn.commit()
        return recovery_id
    finally:
        conn.close()


def layout(conn, scenario: str) -> dict:
    """EXP-010.md §1: is there a data chunk R of the current map whose logical start a data chunk
    B of an older map had, on other bytes (`reuse`) or on the same bytes with a map in between
    that does not place the address (`reuse_same`)?"""
    maps = dated_maps(conn)
    data = [(name, gen, [c for c in chunks if c.type & BG["DATA"]]) for name, gen, chunks in maps]
    current = data[-1][2]
    placement = lambda c: (c.length, tuple((s.devid, s.offset) for s in c.stripes))  # noqa: E731
    found = []
    for r in current:
        older = [(name, gen, c) for name, gen, chunks in data[:-1] for c in chunks
                 if c.logical == r.logical]  # fmt: skip
        for name, gen, b in older:
            gap = any(
                g > gen and not any(c.logical <= r.logical < c.end for c in chunks)
                for _, g, chunks in maps[:-1]
            )
            same = placement(b) == placement(r)
            b_free = all(
                s.devid != t.devid or s.offset + b.length <= t.offset or t.offset + c.length
                <= s.offset for s in b.stripes for c in maps[-1][2] for t in c.stripes
            )  # fmt: skip
            if (scenario == "reuse" and not same and b_free) or (
                scenario == "reuse_same" and same and gap
            ):
                found.append(
                    {"logical": r.logical, "older_map": name,
                     "b_physical": [s.offset for s in b.stripes],
                     "r_physical": [s.offset for s in r.stripes]}
                )  # fmt: skip
                break
    return {"holds": bool(found), "pairs": found[:1]}


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
    return dict(
        conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (row["duplicate_of"],))
        .fetchone()
    )  # fmt: skip


def prefix_digests(path: Path, sizes: set[int]) -> dict[int, str]:
    """SHA-256 of the first `size` bytes of `path`, for each of `sizes`."""
    digest, found, done = hashlib.sha256(), {}, 0
    with path.open("rb") as f:
        for size in sorted(sizes):
            while done < size and (block := f.read(min(1 << 20, size - done))):
                digest.update(block)
                done += len(block)
            if done == size:
                found[size] = digest.copy().hexdigest()
    return found


def files(conn, runs: dict[str, int], outs: dict[str, Path], truth: dict, sizes: dict) -> dict:
    by = {reading: files_of(conn, runs[reading]) for reading in READINGS}
    keys = set(by["own"])
    content = {r: {k: resolved(conn, row) for k, row in by[r].items()} for r in READINGS}
    name_of = {k: by["own"][k]["path"].rsplit("/", 1)[-1] for k in keys}
    record = {}
    for name in sorted(truth):
        mine = [k for k in keys if name_of[k] == name]
        full = [k for k in mine if by["own"][k]["size"] == sizes[name]]
        prefix = [k for k in mine if by["own"][k]["size"] not in (None, sizes[name])]
        stats = {"full_versions": len(full), "prefix_versions": len(prefix)}
        for reading in READINGS:
            rows = [content[reading][k] for k in full if k in content[reading]]
            stats[f"{reading}_exact"] = sum(
                r["status"] == "complete" and r["sha256"] == truth[name] for r in rows
            )
            stats[f"{reading}_complete_other_hash"] = sum(
                r["status"] == "complete" and r["sha256"] != truth[name] for r in rows
            )
            stats[f"{reading}_partial"] = sum(r["status"] == "partial" for r in rows)
        # the notes of the read that gave the content; a duplicate row does not repeat them
        for label, rows in (("", content["own"]), ("_on_the_row_itself", by["own"])):
            notes = [json.loads(rows[k]["problems"]) for k in full]
            stats[f"own_reuse_note{label}"] = sum(any(REUSE_NOTE in p for p in n) for n in notes)
            stats[f"own_realloc_note{label}"] = sum(
                any(REALLOC_NOTE in p for p in n) for n in notes
            )
        # prefix versions against the full version read under own, when that one is exact
        exact = next((content["own"][k] for k in full if content["own"][k]["sha256"] ==
                      truth[name] and content["own"][k]["output_path"]), None)  # fmt: skip
        if exact is not None and prefix:
            wanted = {by["own"][k]["size"] for k in prefix}
            digests = prefix_digests(outs["own"] / exact["output_path"], wanted)
            for reading in ("own", "merged"):
                stats[f"prefix_{reading}_right"] = sum(
                    content[reading][k]["status"] == "complete"
                    and content[reading][k]["sha256"] == digests.get(by["own"][k]["size"])
                    for k in prefix
                )
        record[name] = stats
    others = [k for k in keys if name_of[k] != "b.bin"]
    record["other_artifacts"] = len(others)
    record["other_artifacts_differing_own_merged"] = sum(
        (content["own"][k]["status"], content["own"][k]["sha256"])
        != (content["merged"][k]["status"], content["merged"][k]["sha256"])
        for k in others
    )
    record["artifacts_differing_own_merged"] = sum(
        (content["own"][k]["status"], content["own"][k]["sha256"])
        != (content["merged"][k]["status"], content["merged"][k]["sha256"])
        for k in keys
    )
    return record


def measure(image: Path, scenario: str) -> dict:
    log = image.with_suffix(".log").read_text()
    truth = {name: digest for digest, name in TRUTH.findall(log)}
    sizes = {name: count * PIECE for name, count in PIECES[scenario].items()}
    sizes |= {"keep.txt": KEEP_SIZE, "c.bin": (int(FREE.search(log).group(1)) + 4) * PIECE}
    work = OUT / "work" / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    try:
        database = work / "evidence.db"
        build_catalog(image, database, full_sweep=True)
        outs = {reading: work / f"out_{reading}" for reading in READINGS}
        runs = {
            maps: recover(image, database, outs[maps], roots=("all",), tree_id=None,
                          maps=maps).recovery_id
            for maps in ("own", "current")
        }  # fmt: skip
        runs["merged"] = recover_merged(image, database, outs["merged"])
        conn = db.open_readonly(database)
        record = {
            "image": image.name,
            "scenario": scenario,
            "sha256": before,
            "superblock_generation": conn.execute("SELECT generation FROM scan_runs").fetchone()[0],
            "states": conn.execute("SELECT COUNT(*) FROM states").fetchone()[0],
            "historical_maps": conn.execute(
                "SELECT COUNT(*) FROM chunk_maps WHERE kind = 'historical'"
            ).fetchone()[0],
            "dev_extent_chunks_rejected": conn.execute(
                "SELECT COUNT(*) FROM chunks JOIN chunk_maps USING (map_id)"
                " WHERE kind = 'dev_extents' AND NOT accepted"
            ).fetchone()[0],
            "bounds_hit": [
                r[0] for r in conn.execute(
                    "SELECT source FROM problems WHERE source IN ('roots', 'chunk_maps')"
                )
            ],
            "layout": layout(conn, scenario),
            "files": files(conn, runs, outs, truth, sizes),
        }  # fmt: skip
        conn.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record["unchanged"] = sha256(image) == before
    return record


def build(name: str, scenario: str) -> Path:
    subprocess.run(
        [str(REPO / "corpus" / "vm" / "make_image.sh"), name],
        env=os.environ | {"CSUM": "xxhash", "SCENARIO": scenario,
                          "MOUNT_OPTS": "commit=5,nodiscard"},
        check=True, stdout=subprocess.DEVNULL,
    )  # fmt: skip
    return SCENARIOS / f"{name}.img"


def scenario_of(image: Path) -> str:
    return "reuse_same" if "reuse_same" in image.stem else "reuse"


def run(results: Path, builds: int, scenarios: list[str], image: Path | None) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as out:
        if image is not None:
            out.write(json.dumps(measure(image, scenario_of(image))) + "\n")
            return
        subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                       stdout=subprocess.DEVNULL)  # fmt: skip
        for scenario in scenarios:
            for number in range(1, builds + 1):
                path = build(f"exp010_{scenario}_r{number}", scenario)
                try:
                    record = measure(path, scenario)
                finally:
                    path.unlink(missing_ok=True)
                    path.with_suffix(".log").unlink(missing_ok=True)
                out.write(json.dumps(record) + "\n")
                out.flush()
                b = record["files"]["b.bin"]
                print(
                    f"done   {record['image']}: layout {record['layout']['holds']}, b.bin full "
                    f"versions {b['full_versions']}, exact own {b['own_exact']} merged "
                    f"{b['merged_exact']}"
                )


def flat(record: dict) -> dict:
    row = {
        "layout holds": int(record["layout"]["holds"]),
        "superblock generation": record["superblock_generation"],
        "states": record["states"],
        "historical maps": record["historical_maps"],
        "dev_extents chunks rejected": record["dev_extent_chunks_rejected"],
    }
    for name, stats in record["files"].items():
        if isinstance(stats, dict):
            row |= {f"{name} {key.replace('_', ' ')}": value for key, value in stats.items()}
        else:
            row[name.replace("_", " ")] = stats
    return row


def table(results: Path) -> None:
    records = [json.loads(line) for line in results.read_text().splitlines()]
    for scenario in dict.fromkeys(r["scenario"] for r in records):
        fresh = [
            r for r in records if r["scenario"] == scenario and r["image"].startswith("exp010_")
        ]
        kept = [r for r in records if r["scenario"] == scenario and r not in fresh]
        for label, group in ((f"{scenario}: fresh builds", fresh), (f"{scenario}: corpus image",
                                                                     kept)):  # fmt: skip
            if not group:
                continue
            print(f"\n### {label} (N = {len(group)}); unchanged by the measurement: "
                  f"{sum(r['unchanged'] for r in group)}; bounds hit: "
                  f"{sum(bool(r['bounds_hit']) for r in group)}\n")  # fmt: skip
            for r in group:
                print(f"- {r['image']} {r['sha256']} layout {r['layout']['pairs']}")
            print("\n| Quantity | Median | Range |")
            print("|---|---|---|")
            rows = [flat(r) for r in group]
            for key in dict.fromkeys(k for row in rows for k in row):
                values = [row.get(key, 0) for row in rows]
                print(f"| {key} | {statistics.median(values):g} | {min(values)}–{max(values)} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="build, measure and append to the results")
    run_cmd.add_argument("--builds", type=int, default=5)
    run_cmd.add_argument("--scenarios", nargs="+", default=["reuse", "reuse_same"],
                         choices=["reuse", "reuse_same"])  # fmt: skip
    run_cmd.add_argument("--image", type=Path, help="measure this built image instead")
    table_cmd = commands.add_parser("table", help="print the tables of EXP-010.md §6")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.results, args.builds, args.scenarios, args.image)
    else:
        table(args.results)


if __name__ == "__main__":
    main()
