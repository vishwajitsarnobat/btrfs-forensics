"""EXP-009: precision and recall of `btrfska timeline` per event type, against the scenario log.

The hypothesis and predictions are in experiments/EXP-009.md §1. Scenario `deep` (the recipe of
corpus image `m4_deep`) logs every create, rename and delete of tree 5 as
`=== EVENT KIND INODE GENERATION PATH [NEW PATH]`, GENERATION being the transaction it happened in.

For every build: catalog with a full sweep, the timeline of tree 5 with the uncommitted sources,
and each reported create, rename (or move) and delete (or never_committed) matched against the
log by identity (inode, creation generation) and by the logged generation lying within the
event's interval (EXP-009.md §2).

Builds go to OUT/builds with their own guest initramfs under OUT/vm, so neither
images/scenarios nor images/vm is touched.

Usage, from the repo root:
  uv run python experiments/exp009.py run [--builds 5] [--first 1] [--keep] [--out DIR]
  uv run python experiments/exp009.py run --image images/scenarios/m4_deep.img
  uv run python experiments/exp009.py table
All take `--results PATH` (default OUT/results.jsonl; OUT is images/scratch/exp/EXP-009).
`--first` numbers the builds from N (one build per call, under a lock, is `--builds 1 --first N`);
`--keep` leaves the builds in OUT/builds, to be measured again (`--image`) by another version.
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
from btrfska.timeline.build import Timeline

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-009"
EVENT = re.compile(r"^=== EVENT (create|rename|delete|unlink) (\d+) (\d+) (\S+)(?: (\S+))?", re.M)
TYPES = ("create", "rename", "delete")
REPORTED = {"create": "create", "rename": "rename", "move": "rename", "delete": "delete",
            "never_committed": "delete"}  # fmt: skip
TOP_DIRECTORY = 256  # made by mkfs, not by the scenario
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


def logged_events(log: str) -> list[dict]:
    """The scenario's events, each with its identity (inode, creation generation)."""
    created: dict[int, int] = {}
    found = []
    for kind, inode, generation, path, new in EVENT.findall(log):
        inode, generation = int(inode), int(generation)
        if kind == "create":
            created[inode] = generation
        found.append({
            "type": kind, "identity": (inode, created.get(inode)), "generation": generation,
            "path": path, "new": new or None,
        })  # fmt: skip
    return found


def matches(truth: dict, event: dict) -> bool:
    if truth["identity"] != (event["objectid"], event["created"]):
        return False
    if truth["type"] == "create":
        return event["created"] == truth["generation"]
    if truth["type"] == "rename" and event["to"]["name"] != truth["new"].rsplit("/", 1)[-1]:
        return False
    low, high = event["generations"]
    return low <= truth["generation"] <= high


def score(truths: list[dict], events: list[dict]) -> dict:
    """Precision, recall and recall within reach per type, and the flags of EXP-009.md §2."""
    told: dict[tuple, list] = {}
    for e in events:
        told.setdefault((e["objectid"], e["created"]), []).append(
            [e["event"], e["path"], e["generations"], e["first_seen"]["source"]]
        )
    seen = set(told)
    measured = [e for e in events if e["event"] in REPORTED and e["objectid"] != TOP_DIRECTORY]
    record: dict = {}
    for kind in TYPES:
        logged = [t for t in truths if t["type"] == kind]
        reported = [e for e in measured if REPORTED[e["event"]] == kind]
        taken: set[int] = set()
        right = 0
        for event in reported:
            for number, truth in enumerate(logged):
                if number not in taken and matches(truth, event):
                    taken.add(number)
                    right += 1
                    break
        reach = [n for n, t in enumerate(logged) if t["identity"] in seen]
        record[kind] = {
            "logged": len(logged),
            "reported": len(reported),
            "matched": right,
            "precision": right / len(reported) if reported else None,
            "recall": len(taken) / len(logged) if logged else None,
            "within_reach": len(reach),
            "recall_within_reach": len(taken & set(reach)) / len(reach) if reach else None,
            # a missed event within reach, with what the timeline did say about that file
            "missed": sorted(logged[n]["path"] for n in range(len(logged)) if n not in taken),
            "missed_within_reach": [
                {"path": logged[n]["path"], "generation": logged[n]["generation"],
                 "reported": told.get(logged[n]["identity"], [])}
                for n in reach if n not in taken
            ],
            "wrong": [
                {k: e.get(k) for k in ("event", "objectid", "created", "path", "generations")}
                for e in reported if not any(matches(t, e) for t in logged)
            ],
        }  # fmt: skip
    widths = [e["generations"][1] - e["generations"][0] for e in measured
              if e["event"] == "delete"]  # fmt: skip
    (unlink,) = [t for t in truths if t["type"] == "unlink"] or [None]
    record |= {
        "events_measured": len(measured),
        "order_assumed": sum(e["order_assumed"] for e in measured),
        "log_only": sum(e["log_only"] for e in measured),
        "log_only_not_flash": sum(
            e["log_only"] and not e["path"].startswith("flash_") for e in measured
        ),
        "delete_width_median": statistics.median(widths) if widths else None,
        "delete_width_max": max(widths) if widths else None,
        "delete_widths": sorted(widths),
        "link_or_move": sum(e["event"] in ("link", "move") for e in events),
        # the endings of identities no committed state holds that are not proved never committed
        "not_seen_uncommitted": sorted(
            e["path"] for e in events if e["event"] == "not_seen" and e["between"] is None
        ),
        "unlink_within_its_generation": unlink is not None and any(
            e["event"] == "unlink" and (e["objectid"], e["created"]) == unlink["identity"]
            and e["generations"][0] <= unlink["generation"] <= e["generations"][1]
            for e in events
        ),
    }  # fmt: skip
    return record


def measure(image: Path, work: Path) -> dict:
    truths = logged_events(image.with_suffix(".log").read_text())
    if not truths:
        raise SystemExit(f"{image}: its log has no `=== EVENT` lines (built before EXP-009)")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    before = sha256(image)
    try:
        build_catalog(image, work / "evidence.db", full_sweep=True)
        conn = db.open_readonly(work / "evidence.db")
        states = conn.execute("SELECT COUNT(*), MIN(generation) FROM states").fetchone()
        events = list(Timeline(conn, tree_id=5, uncommitted=True).events(5))
        conn.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record = {"image": image.name, "sha256": before, "states": states[0],
              "oldest_state": states[1], "events": len(events)}  # fmt: skip
    record |= score(truths, events)
    record["unchanged"] = sha256(image) == before
    return record


def build(name: str, out: Path) -> Path:
    """One build of scenario deep into out/builds, through the guest initramfs of out/vm."""
    subprocess.run(
        [str(REPO / "corpus" / "vm" / "make_image.sh"), name],
        env=os.environ | BUILD_ENV | {"OUT_DIR": str(out / "builds"), "VM_DIR": str(out / "vm")},
        check=True, stdout=subprocess.DEVNULL,
    )  # fmt: skip
    return out / "builds" / f"{name}.img"


def private_vm(out: Path) -> None:
    """A guest initramfs of this checkout's scenarios, next to a copy of the fetched bundle made
    of hard links (the scripts search it with `find`, which does not enter a symbolic link)."""
    vm = out / "vm"
    vm.mkdir(parents=True, exist_ok=True)
    for part in ("kernel", "tools"):
        if not (vm / part).exists():
            shutil.copytree(REPO / "images" / "vm" / part, vm / part, symlinks=True,
                            copy_function=os.link)  # fmt: skip
    subprocess.run([str(REPO / "corpus" / "vm" / "build_initramfs.sh")], check=True,
                   env=os.environ | {"VM_DIR": str(vm)}, stdout=subprocess.DEVNULL)  # fmt: skip


def run(results: Path, out: Path, builds: int, image: Path | None, first: int = 1,
        keep: bool = False) -> None:  # fmt: skip
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as sink:
        if image is not None:
            sink.write(json.dumps(measure(image, out / "work")) + "\n")
            return
        private_vm(out)
        for number in range(first, first + builds):
            path = build(f"exp009_r{number}", out)
            try:
                record = measure(path, out / "work")
            finally:
                if not keep:
                    path.unlink(missing_ok=True)
                    path.with_suffix(".log").unlink(missing_ok=True)
            sink.write(json.dumps(record) + "\n")
            sink.flush()
            print(
                f"done   {record['image']}: "
                + ", ".join(
                    f"{kind} {record[kind]['matched']}/{record[kind]['reported']} reported right, "
                    f"{record[kind]['matched']}/{record[kind]['logged']} logged found"
                    for kind in TYPES
                )
            )


def table(results: Path) -> None:
    records = [json.loads(line) for line in results.read_text().splitlines()]
    groups = {
        "fresh builds of scenario deep": [r for r in records if r["image"].startswith("exp009_")],
        "other images": [r for r in records if not r["image"].startswith("exp009_")],
    }
    for label, group in groups.items():
        if not group:
            continue
        print(f"\n### {label} (N = {len(group)}): {', '.join(r['image'] for r in group)}; "
              f"unchanged: {sum(r['unchanged'] for r in group)}\n")  # fmt: skip
        print("| Quantity | Median | Range |")
        print("|---|---|---|")

        def row(name: str, values: list) -> None:
            values = [v for v in values if v is not None]
            if not values:
                print(f"| {name} | – | – |")
                return
            print(f"| {name} | {statistics.median(values):.3g} | "
                  f"{min(values):.3g}–{max(values):.3g} |")  # fmt: skip

        for key in ("states", "oldest_state", "events", "events_measured"):
            row(key.replace("_", " "), [r[key] for r in group])
        for kind in TYPES:
            for key in ("logged", "reported", "matched", "precision", "recall", "within_reach",
                        "recall_within_reach"):  # fmt: skip
                row(f"{kind}: {key.replace('_', ' ')}", [r[kind][key] for r in group])
        for key in ("order_assumed", "log_only", "log_only_not_flash", "delete_width_median",
                    "delete_width_max", "link_or_move"):  # fmt: skip
            row(key.replace("_", " "), [r[key] for r in group])
        row("share order assumed", [r["order_assumed"] / r["events_measured"] for r in group])
        row("share log only", [r["log_only"] / r["events_measured"] for r in group])
        print(
            f"\nnot_seen of identities no committed state holds: "
            f"{[r.get('not_seen_uncommitted') for r in group]}"
        )
        print(
            f"\nunlink within its generation: "
            f"{sum(r['unlink_within_its_generation'] for r in group)} of {len(group)}"
        )
        for r in group:
            for kind in TYPES:
                if r[kind]["missed"] or r[kind]["wrong"]:
                    print(f"- {r['image']} {kind}: missed {r[kind]['missed']}; "
                          f"wrong {r[kind]['wrong']}")  # fmt: skip
                for miss in r[kind]["missed_within_reach"]:
                    print(f"  - within reach and missed: {miss}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="build, measure and append to the results")
    run_cmd.add_argument("--builds", type=int, default=5)
    run_cmd.add_argument("--first", type=int, default=1, help="the number of the first build")
    run_cmd.add_argument("--keep", action="store_true", help="keep the builds in OUT/builds")
    run_cmd.add_argument("--image", type=Path, help="measure this built image instead")
    run_cmd.add_argument("--out", type=Path, default=OUT, help="a directory under images/")
    table_cmd = commands.add_parser("table", help="print the tables of EXP-009.md §6")
    for command in (run_cmd, table_cmd):
        command.add_argument("--results", type=Path)
    args = parser.parse_args()
    out = args.out.absolute() if args.command == "run" else OUT
    results = args.results or out / "results.jsonl"
    if args.command == "run":
        run(results, out, args.builds, args.image, args.first, args.keep)
    else:
        table(results)


if __name__ == "__main__":
    main()
