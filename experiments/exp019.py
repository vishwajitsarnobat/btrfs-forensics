"""EXP-019: free space, the observed discard mode and the overwrite risk of recovered data.

The hypotheses and predictions are in experiments/EXP-019.md §1. Per image: catalog with a full
sweep; read the current allocation with and without the free space tree (cross-check, findings,
older trees); the observed discard mode; `recover --root all --tree all --orphans` once with the
observed mode and once with the mode the guest log's `=== MOUNTED` line states; the current
state's files (H4); on `m4_deep`, every regular victim's `freed_in` against the log (H3).

Usage, from the repo root:
  uv run python experiments/exp019.py run                  # every kept corpus image
  uv run python experiments/exp019.py run IMAGE...
  uv run python experiments/exp019.py build [--builds 5]   # fresh s01 trio and m4_deep builds
  uv run python experiments/exp019.py table
All take `--results PATH` (default images/scratch/exp/EXP-019/results.jsonl); `build` appends.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
from collections import Counter
from pathlib import Path

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.recover.engine import recover
from btrfska.recover.space import SpaceViews
from btrfska.substrate.fs import UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-019"
RESULTS = OUT / "results.jsonl"
SCENARIOS = REPO / "images" / "scenarios"
BUILDS = OUT / "builds"
DERIVED_FROM = {
    "m1_unknown_incompat": "m1_xxhash", "m1_mirror_damage": "m1_xxhash",
    "m1_foreign_mirror": "m1_xxhash", "m1_badnode": "m1_xxhash", "m1_badnode_both": "m1_xxhash",
    "m4_planted_slack": "m3_wide", "m4_deep_lost_parent": "m4_deep",
    "m5_delsubvol_lost_items": "m5_delsubvol", "m6_datacsum_flipped": "m6_datacsum",
}  # fmt: skip
MOUNTED = re.compile(r"=== MOUNTED \S+ \S+ btrfs (\S+)")
EVENT = re.compile(r"=== EVENT (\w+) \d+ (\d+) (\S+)")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def log_of(image: Path) -> str:
    stem = image.stem
    for base, name in ((image.parent, stem), (SCENARIOS, DERIVED_FROM.get(stem, stem))):
        path = base / f"{name}.log"
        if path.exists():
            return path.read_text(errors="replace")
    return ""


def stated_mode(log: str) -> str | None:
    """The discard mode of the guest's mount options: `discard` alone is sync (super.c)."""
    match = MOUNTED.search(log)
    if match is None:
        return None
    options = match[1].split(",")
    if "discard=async" in options:
        return "async"
    if "discard" in options or "discard=sync" in options:
        return "sync"
    return "none"


def counts(conn, recovery_id: int) -> dict:
    found: dict[str, Counter] = {}
    for kind, verdict, risk in conn.execute(
        "SELECT source_kind, space_verdict, overwrite_risk FROM artifacts WHERE recovery_id = ?",
        (recovery_id,),
    ):
        found.setdefault(kind, Counter())[f"{verdict} {risk}"] += 1
    return {kind: dict(c) for kind, c in found.items()}


def measure(image: Path) -> dict:
    work = OUT / "work" / image.stem
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    log = log_of(image)
    record = {"image": image.stem, "sha256_before": sha256(image), "stated": stated_mode(log)}
    try:
        build_catalog(image, work / "evidence.db", full_sweep=True)
        conn = db.open_readonly(work / "evidence.db")
        with open_image(image) as img:
            reader = open_filesystem(img).reader
            views = SpaceViews(conn, reader)
            derived = SpaceViews(conn, reader, use_fst=False)
            view = views.view
            record |= {
                "source": view.source if view else None,
                "complete": bool(view and view.complete),
                "cross_check": view.cross_check() if view else None,
                "derived_equal": bool(view and derived.view and
                                      derived.view.free.pairs == view.free.pairs),
                "fst_findings": [] if view is None else view.notes(),
                "history": len(views.history()),
                "history_findings": sum(len(v.fst.notes()) for _, v, _ in views.history()),
                "observed": views.discard.observed,
                "evidence": views.discard.evidence,
            }  # fmt: skip
        conn.close()
        runs = {}
        for label, discard in (("observed", None), ("stated", record["stated"])):
            done = recover(image, work / "evidence.db", work / f"out_{label}", roots=("all",),
                           tree_id=None, orphans=True, discard=discard)  # fmt: skip
            runs[label] = done.recovery_id
            shutil.rmtree(work / f"out_{label}", ignore_errors=True)
        conn = db.open_readonly(work / "evidence.db")
        record["by_source"] = counts(conn, runs["observed"])
        record["by_source_stated"] = counts(conn, runs["stated"])
        live = conn.execute(
            "SELECT path, space_verdict, overwrite_risk FROM artifacts a JOIN states s"
            " USING (state_id) WHERE a.recovery_id = ? AND a.kind = 'file' AND a.status ="
            " 'complete' AND a.source_kind = 'anchored_root' AND s.known_as LIKE '%\"current\"%'",
            (runs["observed"],),
        ).fetchall()
        wrong = [r[0] for r in live if (r[1], r[2]) != ("in_use", 0)]
        record["h4"] = {"files": len(live), "not_in_use": wrong}
        record["h3"] = dated(conn, runs["observed"], log)
        conn.close()
    except UnsupportedFormat as exc:
        record["refused"] = str(exc)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record["sha256_after"] = sha256(image)
    return record


def dated(conn, recovery_id: int, log: str) -> dict | None:
    """Every regular victim's `freed_in` against the generation of its `delete` event."""
    deleted = {path: int(gen) for kind, gen, path in EVENT.findall(log) if kind == "delete"}
    if not any(path.startswith("victims/") for path in deleted):
        return None
    found = {"victims": 0, "free": 0, "by_equals_delete": 0, "after_below_by": 0, "wrong": []}
    rows = conn.execute(
        "SELECT a.path, a.space_verdict, p.read_record FROM artifacts a JOIN provenance p"
        " USING (artifact_id) WHERE a.recovery_id = ? AND a.path LIKE 'victims/victim_%'"
        " AND a.status = 'complete' AND p.space_verdict IS NOT NULL",
        (recovery_id,),
    ).fetchall()
    seen = set()
    for path, verdict, raw in rows:
        if path in seen:
            continue
        seen.add(path)
        freed = json.loads(raw)["space"]["freed_in"]
        found["victims"] += 1
        found["free"] += verdict == "free"
        if freed and freed["by"] == deleted.get(path):
            found["by_equals_delete"] += 1
        else:
            found["wrong"].append([path, freed, deleted.get(path)])
        found["after_below_by"] += bool(freed and freed["after"] is not None
                                        and freed["after"] < freed["by"])  # fmt: skip
    return found


def kept_images() -> list[Path]:
    with (REPO / "corpus" / "manifest.tsv").open() as f:
        names = [row["name"] for row in csv.DictReader(f, delimiter="\t")]
    return [SCENARIOS / f"{n}.img" for n in names if (SCENARIOS / f"{n}.img").exists()]


def run(args) -> None:
    images = [Path(p) for p in args.images] or kept_images()
    args.results.parent.mkdir(parents=True, exist_ok=True)
    with args.results.open("a") as out:
        for image in images:
            record = measure(image) | {"kind": "kept"}
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(image.name, record.get("observed"), record.get("cross_check"))


def manifest_command(name: str) -> str:
    with (REPO / "corpus" / "manifest.tsv").open() as f:
        return next(r["command"] for r in csv.DictReader(f, delimiter="\t") if r["name"] == name)


def build(args) -> None:
    """Fresh builds into images/scratch, each measured and deleted."""
    BUILDS.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                   stdout=subprocess.DEVNULL)  # fmt: skip
    deep = shlex.split(manifest_command("m4_deep"))
    env_deep = dict(part.split("=", 1) for part in deep if "=" in part.split("/")[0])
    plans = [(f"exp019_{mode}_r{n}", [str(REPO / "corpus/vm/scenarios" / f"discard_{mode}.sh")],
              {"NAME": f"exp019_{mode}_r{n}"}, mode)
             for mode in args.modes for n in range(1, args.builds + 1)]  # fmt: skip
    plans += [(f"exp019_deep_r{n}", [str(REPO / "corpus/vm/make_image.sh"), f"exp019_deep_r{n}"],
               env_deep, "deep") for n in range(1, args.deep_builds + 1)]  # fmt: skip
    with args.results.open("a") as out:
        for name, command, env, mode in plans:
            image = BUILDS / f"{name}.img"
            subprocess.run(command, env=os.environ | env | {"OUT_DIR": str(BUILDS)}, check=True,
                           stdout=subprocess.DEVNULL)  # fmt: skip
            try:
                record = measure(image) | {"kind": "fresh", "mode": mode}
            finally:
                image.unlink(missing_ok=True)
                image.with_suffix(".log").unlink(missing_ok=True)
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(name, record.get("observed"), record.get("cross_check"), record.get("h3"))


def spread(values: list[int]) -> str:
    return f"{statistics.median(values):g} ({min(values)}–{max(values)})" if values else "–"


def table(args) -> None:
    results = [json.loads(line) for line in args.results.read_text().splitlines()]
    print("| image | source | cross-check (fst, extent) | findings | older trees | observed |"
          " stated | H4 files, not in use | unchanged |")  # fmt: skip
    print("|---|---|---|---|---|---|---|---|---|")
    for r in (r for r in results if r["kind"] == "kept"):
        if "refused" in r:
            print(f"| `{r['image']}` | refused | | | | | | | |")
            continue
        cc = r["cross_check"] or {}
        print(
            f"| `{r['image']}` | {r['source']} | {cc.get('free_space_tree_only')}, "
            f"{cc.get('extent_tree_only')} | {len(r['fst_findings'])} + {r['history_findings']} | "
            f"{r['history']} | {r['observed']} | {r['stated']} | {r['h4']['files']}, "
            f"{len(r['h4']['not_in_use'])} | {r['sha256_before'] == r['sha256_after']} |"
        )
    for r in (r for r in results if r["kind"] == "kept" and r.get("h3")):
        print(f"\nH3 on `{r['image']}`: {json.dumps(r['h3'])}")
    print()
    found_keys = {k for r in results for f in r.get("by_source", {}).values() for k in f}
    verdicts = sorted(found_keys, key=lambda k: (k.split()[1], k))
    print("| image | source kind | " + " | ".join(f"`{v}`" for v in verdicts)
          + " | `free 3` with the stated mode |")  # fmt: skip
    print("|---|---|" + "---|" * (len(verdicts) + 1))
    for r in (r for r in results if r["kind"] == "kept" and "by_source" in r):
        for kind, found in sorted(r["by_source"].items()):
            stated = r["by_source_stated"].get(kind, {})
            cells = " | ".join(str(found.get(v, 0)) for v in verdicts)
            print(f"| `{r['image']}` | {kind} | {cells} | {stated.get('free 3', 0)} |")
    print()
    fresh = [r for r in results if r["kind"] == "fresh"]
    for mode in sorted({r["mode"] for r in fresh}):
        group = [r for r in fresh if r["mode"] == mode]
        observed = Counter(r["observed"] for r in group)
        line = f"- `{mode}`, N = {len(group)}: observed {dict(observed)}"
        for key in ("metadata_zeroed", "metadata_intact", "data_zeroed", "data_intact"):
            line += f"; {key} {spread([r['evidence'][key] for r in group])}"
        line += f"; cross-check zero {sum(r['cross_check'] == {'free_space_tree_only': 0, 'extent_tree_only': 0, 'ranges': []} for r in group)}/{len(group)}"  # noqa: E501
        line += f"; H4 not in use {sum(len(r['h4']['not_in_use']) for r in group)}"
        if mode == "deep":
            h3 = [r["h3"] for r in group]
            line += (f"; victims {spread([h['victims'] for h in h3])}, by = delete "
                     f"{spread([h['by_equals_delete'] for h in h3])}, after < by "
                     f"{spread([h['after_below_by'] for h in h3])}")  # fmt: skip
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", type=Path, default=RESULTS)
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("images", nargs="*")
    builder = sub.add_parser("build")
    builder.add_argument("--builds", type=int, default=5)
    builder.add_argument("--deep-builds", type=int, default=5)
    builder.add_argument("--modes", nargs="*", default=["none", "async", "sync"])
    sub.add_parser("table")
    args = parser.parse_args()
    {"run": run, "build": build, "table": table}[args.command](args)


if __name__ == "__main__":
    main()
