"""EXP-005: what the slack of tree blocks holds, superseded and live, leaf and internal node.

The hypothesis and the four registered predictions are in experiments/EXP-005.md §1; read them
first. In short: the kernel's write path zeroes everything beyond `nritems` before it checksums a
tree block (prepare_eb_write, v7.0 fs/btrfs/extent_io.c:2215), so every checksum-valid block should
have all-zero slack (P1), a superseded block no more than its successor (P2), mkfs-written blocks
included (P3), and the prototype's beyond-`nritems` hits on sandbox.img cannot lie in slack (P4).

For every image, read-only as always:
1. `scan_image(..., full_sweep=True)` yields every candidate block of the whole image, classified;
2. for each valid physical copy the slack range is computed and its non-zero bytes are counted;
3. blocks of one tree, level and first key are paired generation by generation.
`legacy` runs the frozen prototype on sandbox.img and locates each of its beyond-`nritems` hits.

Usage, from the repo root:
  uv run python experiments/exp005.py run [IMAGE...]   # default: every manifest image + sandbox.img
  uv run python experiments/exp005.py legacy           # P4: the prototype on sandbox.img
  uv run python experiments/exp005.py table            # the tables of EXP-005.md §6
  uv run python experiments/exp005.py describe IMAGE   # one image's non-zero slack, decoded
`run` also formats never-mounted control images (the pinned mkfs in four variants, and the host's
mkfs.btrfs when there is one), measures them and deletes them: every block of a control was
written by mkfs, which tells mkfs-written blocks from kernel-written ones by generation.
Every command takes `--results PATH` (default images/scratch/exp/EXP-005/results.jsonl).
"""

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from btrfska.scan.classify import scan_image
from btrfska.substrate import ondisk
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.items import KEY_TYPE_NAMES
from btrfska.substrate.slack import slack_range

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "images" / "scratch" / "exp" / "EXP-005"
RESULTS = OUT / "results.jsonl"
MANIFEST = REPO / "corpus" / "manifest.tsv"
SCENARIOS = REPO / "images" / "scenarios"
PINNED = REPO / "corpus" / "vm" / "pinned.sh"
CONTROL = OUT / "control"

HEADER = ondisk.HEADER.size
SAMPLE = 64  # bytes of a non-zero slack kept in the record, from its first non-zero byte


def default_images() -> list[Path]:
    with MANIFEST.open(newline="") as f:
        names = [row["name"] for row in csv.DictReader(f, delimiter="\t")]
    return [*(SCENARIOS / f"{name}.img" for name in names), REPO / "sandbox.img"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def measure_slack(block, nodesize: int) -> dict:
    start, end = slack_range(block, nodesize)
    slack = bytes(block[start:end]) if end > start else b""
    nonzero = len(slack) - slack.count(0)
    row = {"slack_start": start, "slack_len": len(slack), "nonzero": nonzero}
    if nonzero:
        first = next(i for i, b in enumerate(slack) if b)
        last = max(i for i, b in enumerate(slack) if b)
        row["first_nonzero"] = start + first
        row["last_nonzero"] = start + last
        row["sample_hex"] = slack[first : first + SAMPLE].hex()
        row["stale_headers"] = stale_headers(block, start, end)
    return row


def stale_headers(block, start: int, end: int) -> list[list[int]]:
    """The slack of a leaf read as item headers, slot by slot, up to the first all-zero slot.

    Each entry is [key objectid, key type, key offset, data offset, data size]. Nothing is
    validated: this only describes what the bytes look like.
    """
    if ondisk.HEADER.unpack_from(block)["level"] > 0:
        return []
    found = []
    for pos in range(start, end - ondisk.ITEM.size + 1, ondisk.ITEM.size):
        if not any(block[pos : pos + ondisk.ITEM.size]):
            break
        f = ondisk.ITEM.unpack_from(block, pos)
        found.append([f["key_objectid"], f["key_type"], f["key_offset"], f["offset"], f["size"]])
    return found


def first_key(block, level: int) -> tuple[int, int, int] | None:
    header = ondisk.HEADER.unpack_from(block)
    if header["nritems"] == 0:
        return None
    layout = ondisk.KEY_PTR if level > 0 else ondisk.ITEM
    fields = layout.unpack_from(block, HEADER)
    return fields["key_objectid"], fields["key_type"], fields["key_offset"]


def pair_up(blocks: list[dict]) -> list[dict]:
    """Superseded-successor pairs: same tree, level and first key, consecutive generations."""
    groups = defaultdict(list)
    for b in blocks:
        if b["first_key"] is not None:
            groups[(b["owner"], b["level"], tuple(b["first_key"]))].append(b)
    pairs = []
    for members in groups.values():
        members.sort(key=lambda b: (b["generation"], b["bytenr"]))
        for older, newer in zip(members, members[1:], strict=False):
            if older["generation"] == newer["generation"]:
                continue
            pairs.append(
                {
                    "level": older["level"],
                    "owner": older["owner"],
                    "older": [older["bytenr"], older["generation"], older["nonzero"]],
                    "newer": [newer["bytenr"], newer["generation"], newer["nonzero"]],
                    "live_ended": newer["status"] == "live",
                }
            )
    return pairs


def measure(path: Path) -> dict:
    result = {"image": path.name, "sha256": sha256(path)}
    with open_image(path) as img:
        try:
            fs = open_filesystem(img)
        except UnsupportedFormat as exc:
            return result | {"refused": f"feature gate: {exc}"}
        except NoValidSuperblock as exc:
            return result | {"refused": f"no valid superblock: {exc}"}
        nodesize = fs.reader.ctx.nodesize
        scan = scan_image(img, fs, full_sweep=True)
        copies, invalid = [], 0
        for c in scan.classified:
            r = c.record
            if not r.valid:
                invalid += 1
                continue
            block = img.mmap[r.physical : r.physical + nodesize]
            copies.append(
                {
                    "physical": r.physical,
                    "bytenr": r.bytenr,
                    "generation": r.generation,
                    "owner": r.owner,
                    "level": r.level,
                    "nritems": r.nritems,
                    "status": c.status,
                    "outside_map": c.outside_map,
                    "first_key": first_key(block, r.level),
                    **measure_slack(block, nodesize),
                }
            )
    # One logical block per (bytenr, generation, level, owner); its copies may differ in slack.
    by_block = defaultdict(list)
    for c in copies:
        by_block[(c["bytenr"], c["generation"], c["level"], c["owner"])].append(c)
    rank = {"live": 0, "backup_reachable": 1, "unreferenced": 2}
    blocks = []
    for members in by_block.values():
        best = min(members, key=lambda c: rank[c["status"]])
        blocks.append(
            best
            | {
                "nonzero": max(c["nonzero"] for c in members),
                "copies": len(members),
                "copies_differ": len({(c["nonzero"], c.get("sample_hex")) for c in members}) > 1,
                "outside_map": all(c["outside_map"] for c in members),
            }
        )
    classes = Counter()
    for b in blocks:
        key = (
            "internal" if b["level"] > 0 else "leaf",
            b["status"],
            "outside" if b["outside_map"] else "inside",
            b["generation"],
        )
        classes[key + ("blocks",)] += 1
        classes[key + ("with_nonzero",)] += b["nonzero"] > 0
        classes[key + ("slack_bytes",)] += b["slack_len"]
        classes[key + ("nonzero_bytes",)] += b["nonzero"]
    pairs = pair_up(blocks)
    return result | {
        "superblock_generation": fs.fields["generation"],
        "nodesize": nodesize,
        "valid_copies": len(copies),
        "invalid_candidates": invalid,
        "blocks": len(blocks),
        "classes": [[*key, count] for key, count in sorted(classes.items())],
        "nonzero_blocks": [b for b in blocks if b["nonzero"]],
        "copies_differ": sum(b["copies_differ"] for b in blocks),
        "pairs": pairs,
    }


def make_control(name: str, mkfs: list[str], args: list[str]) -> dict | None:
    """Format a scratch image, never mount it, measure it, delete it: every block is mkfs's."""
    try:
        version = subprocess.run([*mkfs, "--version"], capture_output=True, text=True, check=True)
    except OSError, subprocess.CalledProcessError:
        return None
    CONTROL.mkdir(parents=True, exist_ok=True)
    path = CONTROL / f"{name}.img"
    subprocess.run(["truncate", "-s", "512M", str(path)], check=True)
    try:
        subprocess.run([*mkfs, "-q", "-f", *args, str(path)], check=True)
        record = measure(path)
    finally:
        path.unlink(missing_ok=True)
    return record | {"control": True, "mkfs": version.stdout.splitlines()[0], "mkfs_args": args}


def controls() -> list[dict]:
    """Never-mounted images: the pinned mkfs in every variant the manifest uses, and the host's."""
    pinned = [str(PINNED), "mkfs.btrfs"]
    wanted = [
        ("control_pinned_xxhash", pinned, ["--csum", "xxhash"]),
        ("control_pinned_sha256_bgt", pinned, ["--csum", "sha256", "-O", "block-group-tree"]),
        ("control_pinned_blake2b", pinned, ["--csum", "blake2"]),
        ("control_pinned_crc32c", pinned, ["--csum", "crc32c"]),
        ("control_host_default", ["mkfs.btrfs"], []),
    ]
    made = []
    for name, mkfs, args in wanted:
        record = make_control(name, mkfs, args)
        if record is None:
            print(f"skip   {name}: {mkfs[-1]} of that kind is not available", file=sys.stderr)
        else:
            made.append(record)
    shutil.rmtree(CONTROL, ignore_errors=True)
    return made


def _note(record: dict) -> str:
    if "refused" in record:
        return record["refused"]
    nonzero = record["nonzero_blocks"]
    top = max((b["generation"] for b in nonzero), default=None)
    return (
        f"superblock generation {record['superblock_generation']}, {record['blocks']} blocks, "
        f"{len(nonzero)} with non-zero slack (highest generation among them: {top}); "
        f"{len(record['pairs'])} pairs"
    )


def run(paths: list[Path], results: Path, with_controls: bool) -> None:
    results.parent.mkdir(parents=True, exist_ok=True)
    with results.open("a") as out:
        for record in controls() if with_controls else []:
            out.write(json.dumps(record) + "\n")
            print(f"done   {record['image']} ({record['mkfs']}): {_note(record)}")
        for path in paths:
            if not path.exists():
                print(f"skip   {path.name}: absent", file=sys.stderr)
                continue
            record = measure(path)
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(f"done   {path.name}: {_note(record)}")


def load(results: Path) -> dict[str, dict]:
    records = {}
    for line in results.read_text().splitlines():
        record = json.loads(line)
        records[record["image"]] = record  # the last measurement of an image wins
    return records


def count(record: dict, field: str, mkfs_generation: int | None = None, **where) -> int:
    """Sum one field of `classes`; `writer` is "mkfs" up to `mkfs_generation`, else "kernel"."""
    names = ("kind", "status", "placement", "generation", "field")
    total = 0
    for *key, n in record["classes"]:
        row = dict(zip(names, key, strict=True))
        if mkfs_generation is not None:
            row["writer"] = "mkfs" if row["generation"] <= mkfs_generation else "kernel"
        if row["field"] == field and all(row[k] == v for k, v in where.items()):
            total += n
    return total


def pinned_mkfs_generation(records: dict[str, dict]) -> int:
    """The generation the pinned mkfs leaves behind, which must not depend on the variant."""
    found = {
        r["superblock_generation"]
        for name, r in records.items()
        if r.get("control") and name.startswith("control_pinned_")
    }
    if len(found) != 1:
        raise SystemExit(f"pinned controls missing or disagreeing on the generation: {found}")
    return found.pop()


def _cells(r: dict, g: int) -> dict:
    kernel_pairs = [p for p in r["pairs"] if p["older"][1] > g]
    return {
        "blocks": r["blocks"],
        "copies": r["valid_copies"],
        "mkfs": count(r, "blocks", g, writer="mkfs"),
        "mkfs_nz": count(r, "with_nonzero", g, writer="mkfs"),
        "leaves": count(r, "blocks", g, writer="kernel", kind="leaf"),
        "leaves_nz": count(r, "with_nonzero", g, writer="kernel", kind="leaf"),
        "internal": count(r, "blocks", g, writer="kernel", kind="internal"),
        "internal_nz": count(r, "with_nonzero", g, writer="kernel", kind="internal"),
        "slack": count(r, "slack_bytes", g, writer="kernel"),
        "nz": count(r, "nonzero_bytes", g, writer="kernel"),
        "pairs_leaf": sum(p["level"] == 0 for p in kernel_pairs),
        "pairs_internal": sum(p["level"] > 0 for p in kernel_pairs),
        "pairs_live": sum(p["live_ended"] for p in kernel_pairs),
        "pairs_nz": sum(bool(p["older"][2] or p["newer"][2]) for p in kernel_pairs),
        "images": 1,
    }


def _row(label: str, generation, g, c: dict) -> str:
    return (
        f"| {label} | {generation} | {g} | {c['blocks']} ({c['copies']}) "
        f"| {c['mkfs']}, {c['mkfs_nz']} | {c['leaves']}, {c['leaves_nz']} "
        f"| {c['internal']}, {c['internal_nz']} | {c['slack']}, {c['nz']} "
        f"| {c['pairs_leaf']} / {c['pairs_internal']} ({c['pairs_live']}), {c['pairs_nz']} |"
    )


def table(results: Path) -> None:
    records = load(results)
    pinned = pinned_mkfs_generation(records)
    print(
        "| Never-mounted control | mkfs | sb gen | Blocks | With non-zero slack | Non-zero bytes |"
    )
    print("|---|---|---|---|---|---|")
    for name, r in records.items():
        if r.get("control"):
            print(
                f"| `{name}` (`{' '.join(r['mkfs_args'])}`) | {r['mkfs']} "
                f"| {r['superblock_generation']} | {r['blocks']} | {len(r['nonzero_blocks'])} "
                f"| {count(r, 'nonzero_bytes')} |"
            )
    print(
        "\n| Image | sb gen | G | Valid blocks (copies) | Generation ≤ G (mkfs): blocks, with "
        "non-zero slack | Generation > G (kernel): leaves, with non-zero slack | internal nodes, "
        "with non-zero slack | slack bytes examined, non-zero | pairs leaf / internal (ending in "
        "a live block), with non-zero slack |"
    )
    print("|---|---|---|---|---|---|---|---|---|")
    total = Counter()
    unknown = []
    for name, r in records.items():
        if r.get("control"):
            continue
        if "refused" in r:
            print(f"| `{name}` | – | – | not measured: {r['refused']} | – | – | – | – | – |")
            continue
        if name not in MANIFEST_IMAGES():
            unknown.append((name, r))  # formatted by an mkfs we have no control for
            continue
        cells = _cells(r, pinned)
        total.update(cells)
        print(_row(f"`{name}`", r["superblock_generation"], pinned, cells))
    print(_row(f"**{total['images']} images**", "", pinned, total))
    for name, r in unknown:
        top = max((b["generation"] for b in r["nonzero_blocks"]), default=0)
        print(_row(f"`{name}` (G: its highest generation with non-zero slack)",
                   r["superblock_generation"], top, _cells(r, top)))  # fmt: skip

    print("\n| Kernel-written blocks of the manifest images | Blocks | With non-zero slack "
          "| Slack bytes | Non-zero bytes |")  # fmt: skip
    print("|---|---|---|---|---|")
    measured = [r for n, r in records.items() if n in MANIFEST_IMAGES() and "refused" not in r]
    for kind in ("leaf", "internal"):
        for status in ("live", "backup_reachable", "unreferenced"):
            for placement in ("inside", "outside"):
                where = {"writer": "kernel", "kind": kind, "status": status, "placement": placement}
                counts = [
                    sum(count(r, field, pinned, **where) for r in measured)
                    for field in ("blocks", "with_nonzero", "slack_bytes", "nonzero_bytes")
                ]
                if counts[0]:
                    label = f"{kind}, {status}, {placement} the map"
                    print(f"| {label} | " + " | ".join(map(str, counts)) + " |")
    handed = [
        p
        for r in measured
        for p in r["pairs"]
        if p["older"][1] <= pinned < p["newer"][1] and p["older"][2]
    ]
    print(
        f"\nPairs in which an mkfs-written block with non-zero slack was rewritten by the kernel: "
        f"{len(handed)}; successors with any non-zero slack byte: "
        f"{sum(bool(p['newer'][2]) for p in handed)}."
    )
    types = Counter()
    for r in records.values():
        for b in r.get("nonzero_blocks", []):
            types.update(KEY_TYPE_NAMES.get(h[1], f"UNKNOWN.{h[1]}") for h in b["stale_headers"])
    tally = ", ".join(f"{name} {n}" for name, n in types.most_common())
    print(f"\nStale item headers in non-zero slack, by key type, over all records: {tally}.")
    differ = sum(r.get("copies_differ", 0) for r in records.values())
    print(f"\nBlocks whose physical copies differ in slack, over all records: {differ}.")


def MANIFEST_IMAGES() -> set[str]:  # noqa: N802
    with MANIFEST.open(newline="") as f:
        return {f"{row['name']}.img" for row in csv.DictReader(f, delimiter="\t")}


def describe(results: Path, image: str) -> None:
    """Every block of one record with non-zero slack: where, how much, and the first bytes."""
    for b in load(results)[image]["nonzero_blocks"]:
        print(
            f"bytenr {b['bytenr']} gen {b['generation']} owner {b['owner']} level {b['level']} "
            f"nritems {b['nritems']} at {b['physical']} ({b['status']}): {b['nonzero']} non-zero "
            f"of {b['slack_len']} slack bytes, block offsets {b['first_nonzero']}.."
            f"{b['last_nonzero']}: {b['sample_hex']}"
        )
        for objectid, key_type, offset, data_offset, size in b["stale_headers"]:
            name = KEY_TYPE_NAMES.get(key_type, f"UNKNOWN.{key_type}")
            print(
                f"    stale header ({objectid} {name} {offset}) data at {data_offset} size {size}"
            )


def legacy(results: Path) -> None:
    """P4: run the frozen prototype on sandbox.img and set its slack findings beside ours."""
    out = OUT / "legacy"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    image = REPO / "sandbox.img"
    before = sha256(image)
    done = subprocess.run(
        [sys.executable, "main.py", str(image), "-o", str(out / "out"), "--full-sweep"],
        cwd=REPO / "legacy", capture_output=True, text=True,
    )  # fmt: skip
    (out / "stdout.txt").write_text(done.stdout + done.stderr)
    print(f"prototype exit {done.returncode}; sandbox.img unchanged: {sha256(image) == before}")
    wanted = ("orphan_items_found", "leaf_slacks_found", "internal_orphan_ptrs_found",
              "internal_slack_residuals")  # fmt: skip

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in wanted:
                    print(f"{key}: {value}")
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(json.loads((out / "out" / "recovery_report.json").read_text()))
    ours = {}
    for b in load(results)["sandbox.img"]["nonzero_blocks"]:
        ours[b["physical"]] = b
    for saved in sorted((out / "out").glob("leaf_slack_0x*_gen*.bin")):
        physical = int(saved.name.split("_")[2], 16)
        data = saved.read_bytes()
        print(
            f"{saved.name}: {len(data)} bytes, {len(data) - data.count(0)} non-zero; "
            f"block at {physical}"
        )
    for b in ours.values():
        print(
            f"non-zero slack measured: bytenr {b['bytenr']} generation {b['generation']} owner "
            f"{b['owner']} ({b['status']}), first copy at {b['physical']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run_cmd = commands.add_parser("run", help="measure images and append to the results")
    run_cmd.add_argument("images", nargs="*", type=Path)
    run_cmd.add_argument("--no-controls", action="store_true", help="skip the mkfs-only images")
    table_cmd = commands.add_parser("table", help="print the tables of EXP-005.md")
    describe_cmd = commands.add_parser("describe", help="list one image's non-zero slack")
    describe_cmd.add_argument("image", help="record name, for example m3_wide.img")
    legacy_cmd = commands.add_parser("legacy", help="P4: the prototype's slack findings")
    for command in (run_cmd, table_cmd, describe_cmd, legacy_cmd):
        command.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    if args.command == "run":
        run(args.images or default_images(), args.results, not args.no_controls)
    elif args.command == "table":
        table(args.results)
    elif args.command == "legacy":
        legacy(args.results)
    else:
        describe(args.results, args.image)


if __name__ == "__main__":
    main()
