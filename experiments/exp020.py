"""EXP-020: confidence tiers of recovered files, per source kind, against the scenarios' logs.

The hypothesis and predictions are in experiments/EXP-020.md §1. Every image is fixed, so one run
per image: catalog with a full sweep, then `recover --root all --tree all --graph --logs`, and the
tiers counted per source kind, with the checks H1 to H4 against the scenario's log.

Usage, from the repo root:
  uv run python experiments/exp020.py run [IMAGE ...]   (default: the images below that exist)
  uv run python experiments/exp020.py table
Both take `--results PATH` (default images/scratch/exp/EXP-020/results.jsonl).
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
from btrfska.recover.tiers import TIERS
from btrfska.substrate import ondisk

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-020"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
# The images the tool opens whose data differs (EXP-020 §2), in manifest order, then the sandbox.
IMAGES = [
    "m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib", "m1_badnode",
    "m1_badnode_both", "m2_logtree", "s01_discard_none_r1", "s01_discard_async_r1",
    "s01_discard_sync_r1", "m3_wide", "m4_planted_slack", "m4_deep", "m4_deep_lost_parent",
    "m5_delsubvol", "m5_delsubvol_lost_items", "m5_reuse", "m5_reuse_same", "m6_datacsum",
    "m6_datacsum_flipped", "m6_reformat", "m6_reformat_geometry", "m6_fsid_u", "m6_fsid_m",
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
NAMED = [
    re.compile(r"=== (?:FILE|DOOMED|VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})"),
    re.compile(r"^([0-9a-f]{64})  /mnt/(\S+)$", re.M),
]
ORPHANS = ("orphan_node", "orphan_graph")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def truth(image: Path) -> dict[str, set[str]]:
    """{file name: every hash the scenario logged for it}."""
    log = SCENARIOS / f"{DERIVED_FROM.get(image.stem, image.stem)}.log"
    if not log.exists():
        return {}
    text = log.read_text(errors="replace")
    names: dict[str, set[str]] = {}
    for match in NAMED[0].finditer(text):
        names.setdefault(match[1].rsplit("/", 1)[-1], set()).add(match[2])
    for match in NAMED[1].finditer(text):
        names.setdefault(match[2].rsplit("/", 1)[-1], set()).add(match[1])
    return names


def checksummed_on_disk(conn, artifact_id: int) -> bool:
    """At least one regular extent read and checked, and no NODATASUM flag (the H2 set)."""
    records = [
        json.loads(row[0])
        for row in conn.execute(
            "SELECT read_record FROM provenance WHERE artifact_id = ? AND role = 'extent_data'",
            (artifact_id,),
        )
        if row[0]
    ]
    flags = conn.execute(
        "SELECT i.flags FROM provenance p JOIN inodes i USING (content_id, slot)"
        " WHERE p.artifact_id = ? AND p.role = 'inode_item'",
        (artifact_id,),
    ).fetchone()
    on_disk = any(r["kind"] == "regular" and r.get("csum") for r in records)
    return on_disk and not (flags and flags[0] & ondisk.INODE_NODATASUM)


def prefix_sha256(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while size and (block := f.read(min(1 << 20, size))):
            digest.update(block)
            size -= len(block)
    return digest.hexdigest()


def explain(miss: dict, logged: list[tuple[int, Path]]) -> str:
    """Why a `confirmed` file's hash is not in the log (EXP-020 §6.1): `empty` (a version of size
    0, created and not yet written at that commit), `prefix_of_logged` (its bytes are the start of
    a recovered file whose hash the log has for that name: a commit in the middle of the write),
    else `unexplained`."""
    if miss["size"] == 0:
        return "empty"
    for size, path in logged:
        if size >= miss["size"] and prefix_sha256(path, miss["size"]) == miss["sha256"]:
            return "prefix_of_logged"
    return "unexplained"


def measure(image: Path) -> dict:
    work = OUT / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    build_catalog(image, work / "evidence.db", full_sweep=True)
    recover(image, work / "evidence.db", work / "out", roots=("all",), tree_id=None,
            graph=True, logs=True)  # fmt: skip
    names = truth(image)
    conn = db.open_readonly(work / "evidence.db")
    try:
        current = conn.execute(
            "SELECT state_id FROM states WHERE known_as LIKE '%\"current\"%'"
        ).fetchone()
        current = None if current is None else current[0]
        everything = Counter(row[0] for row in conn.execute("SELECT tier FROM artifacts"))
        disagree = conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE tier_rules LIKE '%\"backref_disagrees\"%'"
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT artifact_id, source_kind, state_id, path, status, sha256, csum_verdict, tier,"
            " tier_rules, size, output_path FROM artifacts"
            " WHERE kind = 'file' AND status != 'duplicate'"
        ).fetchall()
        h2_set = {
            row[0]
            for row in rows
            if row[1] == "anchored_root" and row[2] == current and checksummed_on_disk(conn, row[0])
        }
    finally:
        conn.close()
    logged: dict[str, list[tuple[int, Path]]] = {}  # name -> recovered files with a logged hash
    for row in rows:
        name = row[3].rsplit("/", 1)[-1]
        if row[4] == "complete" and row[5] in names.get(name, ()):
            logged.setdefault(name, []).append((row[9], work / "out" / row[10]))
    by_source, rules, proof = Counter(), Counter(), Counter()
    h1_checked, h1_wrong, h2_bad, h3 = 0, [], [], []
    orphan_match = 0
    h4 = {tier: [0, 0] for tier in TIERS}  # evaluated, right
    for artifact_id, kind, _, path, status, digest, verdict, tier, fired, size, _ in rows:
        fired = json.loads(fired)
        by_source[f"{kind} {tier}"] += 1
        rules.update(fired)
        if tier == "confirmed":
            proof["csum_match" if "csum_match" in fired else "content_in_leaf"] += 1
        name = path.rsplit("/", 1)[-1]
        if name in names:
            right = status == "complete" and digest in names[name]
            h4[tier][0] += 1
            h4[tier][1] += right
            if tier == "confirmed":
                h1_checked += 1
                if not right:
                    miss = {"kind": kind, "path": path, "sha256": digest, "size": size}
                    h1_wrong.append(miss | {"why": explain(miss, logged.get(name, []))})
        if artifact_id in h2_set and tier != "confirmed":
            h2_bad.append([path, tier, [r for r in fired if r not in ("blocks_validated",)]])
        if kind in ORPHANS:
            orphan_match += verdict == "match"
            if tier == "confirmed":
                h3.append([kind, path, fired])
    return {
        "image": image.name,
        "sha256_before": before,
        "sha256_after": sha256(image),
        "files": len(rows),
        "artifacts": dict(sorted(everything.items())),
        "by_source": dict(sorted(by_source.items())),
        "rules": dict(sorted(rules.items())),
        "confirmed_by": dict(proof),
        "h1": {"checked": h1_checked, "wrong": h1_wrong},
        "h2": {"checked": len(h2_set), "not_confirmed": h2_bad, "backref_disagrees": disagree},
        "h3": {"orphan_confirmed": h3, "orphan_match": orphan_match},
        "h4": h4,
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
    print("| image | source kind | " + " | ".join(f"`{t}`" for t in TIERS) + " |")
    print("|---|---|" + "---|" * len(TIERS))
    totals: dict[str, Counter] = {kind: Counter() for kind in kinds}
    for r in results:
        for kind in kinds:
            counts = [r["by_source"].get(f"{kind} {t}", 0) for t in TIERS]
            if any(counts):
                totals[kind].update(dict(zip(TIERS, counts, strict=True)))
                print(f"| `{r['image']}` | {kind} | " + " | ".join(map(str, counts)) + " |")
    for kind in kinds:
        print(f"| **all** | {kind} | " + " | ".join(str(totals[kind][t]) for t in TIERS) + " |")
    print()
    every = Counter()
    for r in results:
        every.update(r["artifacts"])
    print("every artifact: " + ", ".join(f"{t} {every[t]}" for t in TIERS))
    proof = Counter()
    for r in results:
        proof.update(r["confirmed_by"])
    print(f"confirmed files resting on: {dict(proof)}")
    rules = Counter()
    for r in results:
        rules.update(r["rules"])
    print("rules over files: " + ", ".join(f"{k} {v}" for k, v in rules.most_common()))
    print()
    print("| image | H1 checked, wrong | H2 checked, not confirmed | backref_disagrees |"
          " H3 orphans confirmed (orphan match) | H4 right/evaluated: confirmed, probable,"
          " unattached | unchanged |")  # fmt: skip
    print("|---|---|---|---|---|---|---|")
    h4 = {t: [0, 0] for t in TIERS}
    for r in results:
        for t in TIERS:
            h4[t][0] += r["h4"][t][0]
            h4[t][1] += r["h4"][t][1]
        print(
            f"| `{r['image']}` | {r['h1']['checked']}, {len(r['h1']['wrong'])} | "
            f"{r['h2']['checked']}, {len(r['h2']['not_confirmed'])} | "
            f"{r['h2']['backref_disagrees']} | {len(r['h3']['orphan_confirmed'])} "
            f"({r['h3']['orphan_match']}) | "
            + ", ".join(f"{r['h4'][t][1]}/{r['h4'][t][0]}" for t in TIERS)
            + f" | {r['sha256_before'] == r['sha256_after']} |"
        )
    print()
    print("H4 over all images: " + ", ".join(f"{t} {h4[t][1]}/{h4[t][0]}" for t in TIERS))
    for r in results:
        for key, found in (("H1", r["h1"]["wrong"]), ("H2", r["h2"]["not_confirmed"]),
                           ("H3", r["h3"]["orphan_confirmed"])):  # fmt: skip
            for entry in found:
                print(f"{key} {r['image']}: {entry}")
    why = Counter(miss["why"] for r in results for miss in r["h1"]["wrong"])
    print(f"H1 misses by explanation: {dict(why)}")


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
