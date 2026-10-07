"""EXP-013: data-checksum verdicts of recovered files, per source kind, on the corpus images.

The hypothesis and predictions are in experiments/EXP-013.md §1. Every image is fixed, so one run
per image: catalog with a full sweep, then `recover --root all --tree all --orphans --logs`, and
the verdicts counted per source kind, with the checks H1 to H4 against the scenario's log.

Usage, from the repo root:
  uv run python experiments/exp013.py run [IMAGE ...]   (default: the images below that exist)
  uv run python experiments/exp013.py table
Both take `--results PATH` (default images/scratch/exp/EXP-013/results.jsonl).
"""

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover
from btrfska.substrate import ondisk
from btrfska.substrate.datacsum import VERDICTS

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-013"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
# The images the tool opens whose data differs (EXP-013 §2), in manifest order, then the sandbox.
IMAGES = [
    "m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m1_badnode",
    "m1_badnode_both", "m2_logtree", "s01_discard_none_r1", "s01_discard_async_r1",
    "s01_discard_sync_r1", "m3_wide", "m4_planted_slack", "m4_deep", "m4_deep_lost_parent",
    "m5_delsubvol", "m5_delsubvol_lost_items", "m6_datacsum", "m6_datacsum_flipped",
]  # fmt: skip
# A derived image has the log of the image it was made from (corpus/manifest.tsv).
DERIVED_FROM = {
    "m1_badnode": "m1_xxhash",
    "m1_badnode_both": "m1_xxhash",
    "m4_planted_slack": "m3_wide",
    "m4_deep_lost_parent": "m4_deep",
    "m5_delsubvol_lost_items": "m5_delsubvol",
    "m6_datacsum_flipped": "m6_datacsum",
}
HASH = re.compile(r"\b[0-9a-f]{64}\b")
NAMED = [
    re.compile(r"=== (?:FILE|DOOMED|VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})"),
    re.compile(r"^([0-9a-f]{64})  /mnt/(\S+)$", re.M),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def truth(image: Path) -> tuple[set[str], dict[str, str]]:
    """(every hash the scenario logged, {file name: hash} for names logged with one hash)."""
    log = SCENARIOS / f"{DERIVED_FROM.get(image.stem, image.stem)}.log"
    if not log.exists():
        return set(), {}
    text = log.read_text(errors="replace")
    names: dict[str, set[str]] = {}
    for match in NAMED[0].finditer(text):
        names.setdefault(match[1].rsplit("/", 1)[-1], set()).add(match[2])
    for match in NAMED[1].finditer(text):
        names.setdefault(match[2].rsplit("/", 1)[-1], set()).add(match[1])
    single = {name: next(iter(found)) for name, found in names.items() if len(found) == 1}
    return set(HASH.findall(text)), single


def measure(image: Path) -> dict:
    work = OUT / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    build_catalog(image, work / "evidence.db", full_sweep=True)
    recover(image, work / "evidence.db", work / "out", roots=("all",), tree_id=None,
            orphans=True, logs=True)  # fmt: skip
    hashes, names = truth(image)
    conn = db.open_readonly(work / "evidence.db")
    try:
        current = conn.execute(
            "SELECT state_id FROM states WHERE known_as LIKE '%\"current\"%'"
        ).fetchone()
        current = None if current is None else current[0]
        rows = conn.execute(
            "SELECT a.artifact_id, a.source_kind, a.state_id, a.path, a.sha256, a.csum_verdict,"
            " (SELECT i.flags FROM provenance p JOIN inodes i USING (content_id, slot)"
            "  WHERE p.artifact_id = a.artifact_id AND p.role = 'inode_item') AS flags"
            " FROM artifacts a WHERE a.kind = 'file' AND a.status != 'duplicate'"
        ).fetchall()
        records = {
            row[0]: [json.loads(r[0]) for r in conn.execute(
                "SELECT read_record FROM provenance WHERE artifact_id = ? AND role = 'extent_data'",
                (row[0],),
            )]
            for row in rows
        }  # fmt: skip
        summary = json.loads(conn.execute("SELECT summary FROM recovery_runs").fetchone()[0])
    finally:
        conn.close()
    by_source = Counter()
    h1_set, h1_bad, h2_checked, h2_bad, h3_checked, h3_bad = 0, [], 0, [], 0, []
    stale_bad = repaired = tail = 0
    for artifact_id, kind, state_id, path, digest, verdict, flags in rows:
        by_source[f"{kind} {verdict or 'none'}"] += 1
        extents = records[artifact_id]
        checks = [e["csum"] for e in extents if e.get("csum")]
        repaired += sum(c["repaired_count"] for c in checks)
        tail += sum(c["tail_rewritten"] for c in checks)
        on_disk = any(e["kind"] == "regular" and e.get("csum") for e in extents)
        nodatasum = bool((flags or 0) & ondisk.INODE_NODATASUM)
        if kind == "anchored_root" and state_id == current and on_disk and not nodatasum:
            h1_set += 1
            if verdict != "match":
                h1_bad.append([path, verdict])
        if digest in hashes and verdict is not None:
            h2_checked += 1
            if verdict == "mismatch":
                h2_bad.append(path)
        name = path.rsplit("/", 1)[-1]
        if verdict == "match" and name in names and digest is not None:
            h3_checked += 1
            if digest != names[name]:
                h3_bad.append([kind, path])
        if verdict in ("mismatch", "unavailable") and not (
            kind == "anchored_root" and state_id == current
        ):
            stale_bad += 1
    trees = summary["csum_trees"]
    return {
        "image": image.name,
        "sha256_before": before,
        "sha256_after": sha256(image),
        "files": len(rows),
        "by_source": dict(sorted(by_source.items())),
        "h1": {"checked": h1_set, "not_match": h1_bad},
        "h2": {"checked": h2_checked, "mismatch": h2_bad},
        "h3": {"checked": h3_checked, "other_hash": h3_bad},
        "h4_stale_mismatch_or_unavailable": stale_bad,
        "sectors_repaired": repaired,
        "tail_rewritten": tail,
        "csum_trees": len(trees),
        "csum_trees_with_gap": sum(not t["complete"] for t in trees.values()),
    }


def run(args) -> None:
    images = [Path(p) for p in args.images] or [
        path for path in [*(SCENARIOS / f"{n}.img" for n in IMAGES), REPO / "sandbox.img"]
        if path.exists()
    ]  # fmt: skip
    args.results.parent.mkdir(parents=True, exist_ok=True)
    with args.results.open("w") as out:
        for image in images:
            result = measure(image)
            out.write(json.dumps(result) + "\n")
            out.flush()
            print(image.name, json.dumps({k: result[k] for k in ("files", "by_source")}))
            shutil.rmtree(OUT / image.stem, ignore_errors=True)


def table(args) -> None:
    results = [json.loads(line) for line in args.results.read_text().splitlines()]
    kinds = sorted({key.rsplit(" ", 1)[0] for r in results for key in r["by_source"]})
    columns = [*VERDICTS, "none"]
    print("| image | source kind | " + " | ".join(f"`{c}`" for c in columns) + " |")
    print("|---|---|" + "---|" * len(columns))
    totals: dict[str, Counter] = {kind: Counter() for kind in kinds}
    for r in results:
        for kind in kinds:
            counts = [r["by_source"].get(f"{kind} {c}", 0) for c in columns]
            if any(counts):
                totals[kind].update(dict(zip(columns, counts, strict=True)))
                print(f"| `{r['image']}` | {kind} | " + " | ".join(map(str, counts)) + " |")
    for kind in kinds:
        print(f"| **all** | {kind} | " + " | ".join(str(totals[kind][c]) for c in columns) + " |")
    print()
    print("| image | H1 checked, not match | H2 checked, mismatch | H3 checked, other hash |"
          " H4 stale | repaired | tail | csum trees (gap) | unchanged |")  # fmt: skip
    print("|---|---|---|---|---|---|---|---|---|")
    for r in results:
        print(
            f"| `{r['image']}` | {r['h1']['checked']}, {len(r['h1']['not_match'])} | "
            f"{r['h2']['checked']}, {len(r['h2']['mismatch'])} | "
            f"{r['h3']['checked']}, {len(r['h3']['other_hash'])} | "
            f"{r['h4_stale_mismatch_or_unavailable']} | {r['sectors_repaired']} | "
            f"{r['tail_rewritten']} | {r['csum_trees']} ({r['csum_trees_with_gap']}) | "
            f"{r['sha256_before'] == r['sha256_after']} |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", type=Path, default=RESULTS)
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("images", nargs="*")
    sub.add_parser("table")
    args = parser.parse_args()
    {"run": run, "table": table}[args.command](args)


if __name__ == "__main__":
    main()
