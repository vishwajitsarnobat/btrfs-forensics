"""EXP-008: what the orphan graph adds to leaf-by-leaf recovery, and whether any join is wrong.

The hypothesis and predictions are in experiments/EXP-008.md §1. Scenario `deep` (the recipe of
corpus image `m4_deep`) is deterministic: every padding file `pad/pN` holds `seq 1 300` or, after
round r with N ≡ r mod 7 + 1 (mod 7), `seq r (300 + r)`; victims, flash files and the file
unlinked while open have their SHA-256 in the serial log.

For every build: catalog with a full sweep; `recover --root all --tree all --orphans` (every
orphan leaf on its own, M4) and `recover --root all --tree all --graph` (fragments, sibling joins,
parent paths). Counted: orphan leaves under a fragment; files cut by a leaf end that come out
complete; files that gain a path; refusals; and three checks for a wrong join (H4).

Usage, from the repo root:
  uv run python experiments/exp008.py run [--builds 5]
  uv run python experiments/exp008.py run --image images/scenarios/m4_deep.img
  uv run python experiments/exp008.py table
Both take `--results PATH` (default images/scratch/exp/EXP-008/results.jsonl).
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
from btrfska.recover.dbtree import orphan_leaves
from btrfska.recover.engine import recover

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-008"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
TRUTH = re.compile(r"=== (?:VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})")
EMPTY = hashlib.sha256(b"").hexdigest()
ROUNDS = 24
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


def seq(first: int, last: int) -> str:
    text = "".join(f"{n}\n" for n in range(first, last + 1))
    return hashlib.sha256(text.encode()).hexdigest()


def padding_contents(number: int) -> set[str]:
    """Every content the scenario can have written to pad/p<number>."""
    allowed = {seq(1, 300)}
    for r in range(1, ROUNDS + 1):
        if (number - (r % 7 + 1)) % 7 == 0 and number >= r % 7 + 1:
            allowed.add(seq(r, 300 + r))
    return allowed


def files_of(conn, recovery_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT a.*, (SELECT MIN(p.bytenr) FROM provenance p WHERE p.artifact_id = a.artifact_id"
        " AND p.role = 'inode_item') AS inode_leaf FROM artifacts a"
        " WHERE a.recovery_id = ? AND a.kind IN ('file', 'unknown')",
        (recovery_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def content_of(conn, row: dict) -> dict:
    if row["status"] != "duplicate":
        return row
    found = conn.execute(
        "SELECT * FROM artifacts WHERE artifact_id = ?", (row["duplicate_of"],)
    ).fetchone()
    return dict(found)


def leaves_of(conn, artifact_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(DISTINCT bytenr) FROM provenance WHERE artifact_id = ?", (artifact_id,)
    ).fetchone()[0]


def wrong_joins(conn, graph_rows: list[dict], truth: dict[str, str]) -> dict:
    """H4 as registered (a, b, c) and as amended before the builds (b2, c2): EXP-008.md §1."""
    logged = padding = signature = checked_logged = checked_padding = checked_signature = 0
    joined_content = joined_wrong = 0
    anchored = {}
    for row in graph_rows:
        if row["source_kind"] in ("anchored_root", "orphan_item") and row["extent_signature"]:
            key = (row["tree_id"], row["objectid"], row["inode_generation"], row["inode_transid"])
            anchored.setdefault(key, set()).add(row["extent_signature"])
    for row in graph_rows:
        if row["source_kind"] != "orphan_graph" or row["kind"] != "file":
            continue
        key = (row["tree_id"], row["objectid"], row["inode_generation"], row["inode_transid"])
        if key in anchored:
            checked_signature += 1
            signature += row["extent_signature"] not in anchored[key]
        content = content_of(conn, row)
        # c2: only files whose content a join assembled (items from two leaves or more), whole
        if (
            key in anchored
            and content["status"] == "complete"
            and (leaves_of(conn, content["artifact_id"]) > 1)
        ):
            joined_content += 1
            joined_wrong += row["extent_signature"] not in anchored[key]
        if content["status"] != "complete" or (content["size"] == 0 and content["sha256"] == EMPTY):
            continue
        name = row["path"].rsplit("/", 1)[-1]
        if name in truth:
            checked_logged += 1
            logged += content["sha256"] != truth[name]
        elif re.fullmatch(r"pad/p\d+", row["path"]):
            checked_padding += 1
            padding += content["sha256"] not in padding_contents(int(name[1:]))
    return {
        "logged_files_checked": checked_logged,
        "logged_files_with_a_wrong_hash": logged,
        "padding_files_checked": checked_padding,
        "padding_files_with_an_impossible_content": padding,
        "files_also_held_by_an_anchored_root": checked_signature,
        "of_them_with_another_extent_signature": signature,
        "complete_files_from_several_leaves_also_held_by_a_root": joined_content,
        "of_them_with_another_extent_signature_(c2)": joined_wrong,
    }


def measure(image: Path) -> dict:
    log = image.with_suffix(".log")
    truth = dict(TRUTH.findall(log.read_text())) if log.exists() else {}
    work = OUT / "work" / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    try:
        build_catalog(image, work / "evidence.db", full_sweep=True)
        options = {"roots": ("all",), "tree_id": None}
        lone = recover(image, work / "evidence.db", work / "out_orphans", orphans=True, **options)
        joined = recover(image, work / "evidence.db", work / "out_graph", graph=True, **options)
        conn = db.open_readonly(work / "evidence.db")
        before_rows = files_of(conn, lone.recovery_id)
        after_rows = files_of(conn, joined.recovery_id)
        leaves = {leaf.bytenr for _, leaf in orphan_leaves(conn)}
        under = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT p.bytenr FROM provenance p JOIN artifacts a USING (artifact_id)"
                " WHERE a.recovery_id = ? AND a.source LIKE 'fragment:%'",
                (joined.recovery_id,),
            )
        }

        def key(row: dict) -> tuple:
            return (row["tree_id"], row["objectid"], row["inode_generation"],
                    row["inode_transid"], row["inode_leaf"])  # fmt: skip

        after = {}
        for row in after_rows:
            if row["source_kind"] in ("orphan_graph", "orphan_node"):
                after.setdefault(key(row), []).append(row)
        orphan_before = [r for r in before_rows if r["source_kind"] == "orphan_node"]
        cut = [
            r for r in orphan_before
            if r["kind"] == "file" and r["status"] == "partial"
            and any(m[2] == "continues_elsewhere" for m in json.loads(r["missing"]))
        ]  # fmt: skip
        pathless = [
            r for r in orphan_before
            if r["kind"] == "file" and not r["attached"]
            and content_of(conn, r)["status"] == "complete"
        ]  # fmt: skip

        def now(row: dict, test) -> bool:
            return any(test(other) for other in after.get(key(row), ()))

        joins = [j for r in after_rows for j in json.loads(r["joined"])]
        refusals = [
            p for r in after_rows for p in json.loads(r["problems"])
            if p.startswith(("not joined with another leaf", "no path:"))
        ]  # fmt: skip
        record = {
            "image": image.name,
            "sha256": before,
            "bounds_hit": joined.fragments_found > joined.fragments,
            "orphan_leaves": len(leaves),
            "orphan_leaves_under_a_fragment": len(leaves & under),
            "fragments": joined.fragments,
            "cut_files_under_orphans": len(cut),
            "of_them_complete_under_graph": sum(
                now(r, lambda o: content_of(conn, o)["status"] == "complete") for r in cut
            ),
            "pathless_complete_files_under_orphans": len(pathless),
            "of_them_with_a_path_under_graph": sum(
                now(r, lambda o: o["attached"]) for r in pathless
            ),
            "artifacts_with_a_pointer_join": sum(j["kind"] == "pointer" for j in joins),
            "artifacts_with_a_sibling_join": sum(j["kind"] == "sibling" for j in joins),
            "parent_path_joins": sum(j["kind"] == "parent_path" for j in joins),
            "refusals": len(refusals),
            "refused_sibling_joins": sum(p.startswith("not joined") for p in refusals),
            "refused_paths": sum(p.startswith("no path") for p in refusals),
            "files_with_an_inode_item_older_than_an_extent": sum(
                "inode_item_older_than_extent" in r["missing"] for r in after_rows
            ),
            "new_complete_files_no_root_gives": sum(
                r["source_kind"] == "orphan_graph" and r["status"] == "complete"
                and r["kind"] == "file" for r in after_rows
            ),
            "wrong": wrong_joins(conn, after_rows, truth),
        }  # fmt: skip
        conn.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record["unchanged"] = sha256(image) == before
    return record


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
            path = build(f"exp008_r{number}")
            try:
                record = measure(path)
            finally:
                path.unlink(missing_ok=True)
                path.with_suffix(".log").unlink(missing_ok=True)
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(
                f"done   {record['image']}: {record['orphan_leaves_under_a_fragment']} of "
                f"{record['orphan_leaves']} orphan leaves under a fragment, wrong: "
                f"{record['wrong']}"
            )


def table(results: Path) -> None:
    records = [json.loads(line) for line in results.read_text().splitlines()]
    groups = {
        "fresh builds of scenario deep": [r for r in records if r["image"].startswith("exp008_")],
        "corpus images": [r for r in records if not r["image"].startswith("exp008_")],
    }
    for label, group in groups.items():
        if not group:
            continue
        print(f"\n### {label} (N = {len(group)}): {', '.join(r['image'] for r in group)}; "
              f"unchanged: {sum(r['unchanged'] for r in group)}; bounds hit: "
              f"{sum(r['bounds_hit'] for r in group)}\n")  # fmt: skip
        print("| Quantity | Median | Range |")
        print("|---|---|---|")
        skip = ("image", "sha256", "bounds_hit", "unchanged", "wrong")
        rows = [
            {k.replace("_", " "): v for k, v in r.items() if k not in skip}
            | {k.replace("_", " "): v for k, v in r["wrong"].items()}
            for r in group
        ]
        for name in rows[0]:
            values = [row[name] for row in rows]
            print(f"| {name} | {statistics.median(values):g} | {min(values)}–{max(values)} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="build, measure and append to the results")
    run_cmd.add_argument("--builds", type=int, default=5)
    run_cmd.add_argument("--image", type=Path, help="measure this built image instead")
    table_cmd = commands.add_parser("table", help="print the tables of EXP-008.md §6")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.results, args.builds, args.image)
    else:
        table(args.results)


if __name__ == "__main__":
    main()
