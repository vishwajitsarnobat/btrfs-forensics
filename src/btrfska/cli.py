"""Command-line interface."""

import argparse
import json
import sys
import uuid
from dataclasses import asdict

from btrfska import __version__
from btrfska.catalog import cli as catalog_cli
from btrfska.scan.classify import Classified, failure_counts, scan_image
from btrfska.scan.kernel_numpy import MAX_WORKERS
from btrfska.scan.roots import State, discover_image
from btrfska.substrate import csum, ondisk, superblock
from btrfska.substrate.extents import read_file
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.items import KEY_TYPE_NAMES, summary
from btrfska.substrate.node import CHECK_NAMES, FAILURE_CLASSES, ValidatedNode
from btrfska.substrate.roots import (
    TREE_IDS,
    RootNotFound,
    TreeRoot,
    find_root_set,
    parse_root_spec,
    resolve_tree,
)
from btrfska.substrate.tree import walk

EXIT_ERROR = 1
# The image was read but btrfska will not interpret it: no valid superblock, or the feature
# gate refused it.
EXIT_REFUSED = 2


def _flags(value: int, table: dict[str, int]) -> str:
    names = ondisk.flag_names(value, table)
    return f"{value:#x} ({', '.join(names)})" if names else f"{value:#x}"


def _print_copies(selection: superblock.Selection) -> None:
    print("superblock copies:")
    for copy in selection.copies:
        where = f"  mirror {copy.mirror} @ {copy.offset}"
        if not copy.present:
            print(f"{where}: not present (beyond image end)")
        elif copy.valid:
            fields = copy.fields
            size = csum.csum_size(fields["csum_type"])
            line = (
                f"{where}: valid, generation {fields['generation']}, "
                f"csum {csum.csum_name(fields['csum_type'])} {fields['csum'][:size].hex()}"
            )
            if copy in selection.foreign:
                line += f" (foreign fsid {uuid.UUID(bytes=fields['fsid'])})"
            if copy.problems:
                line += f" (warnings: {', '.join(copy.problems)})"
            print(line)
        else:
            print(f"{where}: INVALID ({', '.join(copy.problems)})")

    selected = selection.selected
    if selected is None:
        print("selected: none")
    else:
        print(f"selected: mirror {selected.mirror} (generation {selected.fields['generation']})")
        # The kernel mounts mirror 0 only (disk-io.c:3333) and rejects on every check btrfska
        # mirrors, warnings included; say so whenever that differs from the selection.
        primary = selection.copies[0]
        if primary is not selected or primary.problems:
            if primary.problems:
                state = f"invalid: {', '.join(primary.problems)}"
            else:
                state = f"valid, generation {primary.fields['generation']}"
            print(f"kernel would mount: mirror 0 ({state})")
    if selection.disagreements:
        print("disagreements:")
        for line in selection.disagreements:
            print(f"  {line}")
    else:
        print("disagreements: none")


def _print_fields(fields: dict, verdict: superblock.GateVerdict) -> None:
    print(f"fsid: {uuid.UUID(bytes=fields['fsid'])}")
    if any(fields["metadata_uuid"]):
        print(f"metadata_uuid: {uuid.UUID(bytes=fields['metadata_uuid'])}")
    print(f"tree fsid: {uuid.UUID(bytes=superblock.tree_fsid(fields))}")
    label = fields["label"].split(b"\0", 1)[0].decode("utf-8", "replace")
    print(f"label: {label!r}")
    print(f"generation: {fields['generation']}")
    print(f"root: {fields['root']} (level {fields['root_level']})")
    print(
        f"chunk_root: {fields['chunk_root']} (generation {fields['chunk_root_generation']}, "
        f"level {fields['chunk_root_level']})"
    )
    print(f"total_bytes: {fields['total_bytes']}")
    print(f"bytes_used: {fields['bytes_used']}")
    print(f"num_devices: {fields['num_devices']}")
    print(f"nodesize: {fields['nodesize']}")
    print(f"sectorsize: {fields['sectorsize']}")
    csum_type = fields["csum_type"]
    print(
        f"csum_type: {csum_type} ({csum.csum_name(csum_type)}, {csum.csum_size(csum_type)} bytes)"
    )
    print(f"compat_flags: {fields['compat_flags']:#x}")
    print(f"compat_ro_flags: {_flags(fields['compat_ro_flags'], ondisk.COMPAT_RO)}")
    if verdict.block_group_tree:
        print("  block-group tree present: block groups are read from tree 11")
    if verdict.unknown_compat_ro:
        unknown = ", ".join(verdict.unknown_compat_ro)
        print(f"  unknown compat_ro bits (read-only access stays safe): {unknown}")
    print(f"incompat_flags: {_flags(fields['incompat_flags'], ondisk.INCOMPAT)}")


def _print_backup_roots(fields: dict) -> None:
    print("backup roots (by generation):")
    for root in superblock.backup_roots(fields):
        trees = "  ".join(
            f"{tree} {root[tree]} (gen {root[tree + '_gen']})"
            for tree in ("chunk_root", "extent_root", "fs_root", "dev_root", "csum_root")
        )
        print(
            f"  gen {root['tree_root_gen']}  slot {root['slot']}  tree_root {root['tree_root']}  "
            f"{trees}"
        )


def cmd_info(args: argparse.Namespace) -> int:
    with open_image(args.image) as img:
        print(f"image:  {img.path}")
        print(f"size:   {img.size} bytes")
        print(f"sha256: {img.sha256()}")
        selection = superblock.read_superblock(img)

    _print_copies(selection)
    if selection.selected is None:
        print("NO_VALID_SUPERBLOCK")
        return EXIT_REFUSED

    fields = selection.selected.fields
    verdict = superblock.gate(fields, allow_unsupported=args.allow_unsupported)
    _print_fields(fields, verdict)
    _print_backup_roots(fields)
    if verdict.status == "OVERRIDDEN":
        print("gate: OVERRIDDEN (--allow-unsupported: derived rows are unsupported_format=1)")
    else:
        print(f"gate: {verdict.status}")
    for line in verdict.report_lines():
        print(line)
    return EXIT_REFUSED if verdict.refused else 0


def _root_spec(text: str) -> str:
    try:
        parse_root_spec(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None
    return text


def _tree_spec(text: str) -> str:
    if text in TREE_IDS or text.isdigit():
        return text
    names = ", ".join(TREE_IDS)
    raise argparse.ArgumentTypeError(f"invalid tree {text!r}: expected {names} or a tree id")


def _node_record(node: ValidatedNode) -> dict:
    """The node's identity and every physical copy's validation record.

    Every copy carries every check of `CHECK_NAMES`: null when not checked, which is all of them
    for a copy that is not `readable`. Schema: README.md, "`btrfska walk` output".
    """
    return {
        "bytenr": node.logical,
        "level": node.level,
        "generation": node.generation,
        "owner": node.owner,
        "valid": node.valid,
        "copies": [
            {
                "mirror": copy.mirror,
                "devid": copy.devid,
                "physical": copy.physical,
                "readable": copy.readable,
                "used": index == node.chosen,
                "valid": copy.ok,
                "checks": dict.fromkeys(CHECK_NAMES)
                | {check.name: check.ok for check in copy.checks if check.name in CHECK_NAMES},
                "problems": list(copy.problems),
            }
            for index, copy in enumerate(node.copies)
        ],
        "problems": list(node.problems),
    }


def _start(fs, args: argparse.Namespace) -> tuple[TreeRoot, dict]:
    """The walk's start block and its provenance record."""
    kind, number = parse_root_spec(args.root)
    tree = int(args.tree) if args.tree and args.tree.isdigit() else args.tree
    if kind == "bytenr":
        tree_id = TREE_IDS.get(tree, tree)
        start = TreeRoot(tree_id, number, None, None, "bytenr")
        source, name = args.root, args.tree
    else:
        root_set = find_root_set(fs.fields, args.root)
        start = resolve_tree(fs.reader, root_set, tree or "fs")
        source, name = root_set.source, args.tree or "fs"
    record = {
        "source": source,
        "tree": name,
        "tree_id": start.tree_id,
        "bytenr": start.bytenr,
        "level": start.level,
        "generation": start.generation,
        "via": start.via,
    }
    return start, record


def _note(line: str) -> None:
    print(line, file=sys.stderr)


def _open_checked(img, args: argparse.Namespace):
    """The filesystem, or None after reporting NO_VALID_SUPERBLOCK or a gate refusal on stderr."""
    try:
        fs = open_filesystem(img, allow_unsupported=args.allow_unsupported)
    except NoValidSuperblock:
        _note("NO_VALID_SUPERBLOCK")
        return None
    except UnsupportedFormat as exc:
        _note("gate: REFUSED")
        for line in exc.verdict.report_lines():
            _note(line)
        return None
    for line in fs.verdict.report_lines():
        _note(line)
    for problem in fs.chunk_map.problems:
        _note(f"chunk map: {problem}")
    return fs


def cmd_walk(args: argparse.Namespace) -> int:
    def emit(record: dict) -> None:
        print(json.dumps(record, separators=(",", ":")))

    note = _note
    with open_image(args.image) as img:
        fs = _open_checked(img, args)
        if fs is None:
            return EXIT_REFUSED
        try:
            start, root = _start(fs, args)
        except RootNotFound as exc:
            note(f"btrfska: error: {exc}")
            return EXIT_ERROR

        common = {
            "root": root,
            "chunk_map": fs.chunk_map.source,
            "unsupported_format": fs.unsupported_format,
        }
        nodes = invalid = item_count = hop_problems = 0
        for visit in walk(fs.reader, start.bytenr, start.expect()):
            node, nodes = visit.node, nodes + 1
            node_record = _node_record(node)
            where = {"parent": visit.parent, "parent_slot": visit.slot}
            if visit.problems:
                hop_problems += len(visit.problems)
                emit(
                    {
                        "record": "walk_problem",
                        **common,
                        "node": node_record,
                        **where,
                        "problems": list(visit.problems),
                    }
                )
            if not node.valid:
                invalid += 1
                emit({"record": "invalid_node", **common, "node": node_record, **where})
                continue
            for item in node.items if node.level == 0 else ():
                item_count += 1
                key = item.key
                type_name = KEY_TYPE_NAMES.get(key.type, f"UNKNOWN.{key.type}")
                emit(
                    {
                        "record": "item",
                        **common,
                        "node": node_record,
                        "slot": item.slot,
                        "key": {
                            "objectid": key.objectid,
                            "type": key.type,
                            "type_name": type_name,
                            "offset": key.offset,
                        },
                        "size": item.size,
                        "summary": summary(key, item.data),
                    }
                )
    note(
        f"btrfska walk: {nodes} nodes ({invalid} invalid), {item_count} items, "
        f"{hop_problems} walk problems"
    )
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    """File bytes to stdout, only when the whole file reads; JSON records and a summary to stderr.

    Nothing is written anywhere else. Schema: README.md, "`btrfska cat` output".
    """

    def emit(record: dict) -> None:
        _note(json.dumps(record, separators=(",", ":")))

    with open_image(args.image) as img:
        fs = _open_checked(img, args)
        if fs is None:
            return EXIT_REFUSED
        try:
            start, root = _start(fs, args)
        except RootNotFound as exc:
            _note(f"btrfska: error: {exc}")
            return EXIT_ERROR
        no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
        result = read_file(fs.reader, start, args.inode, no_holes=no_holes)
        common = {"root": root, "inode": args.inode, "unsupported_format": fs.unsupported_format}
        for extent in result.extents:
            emit({"record": "extent", **common, **asdict(extent)})
        summary = result.record()
        emit(
            {"record": "file", **common}
            | {key: summary[key] for key in ("size", "complete", "extents", "errors", "problems")}
        )
        if not result.complete:
            _note(f"btrfska cat: error: {'; '.join(result.failures)}")
            return EXIT_ERROR
        out = sys.stdout.buffer
        for chunk in result.chunks():
            out.write(chunk)
        out.flush()
    _note(f"btrfska cat: inode {args.inode}, {result.size} bytes, {len(result.extents)} extents")
    return 0


def _workers(text: str) -> int:
    value = int(text) if text.isdigit() else 0
    if not 1 <= value <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"expected 1 to {MAX_WORKERS} processes, not {text!r}")
    return value


def _scan_record(item: Classified, unsupported_format: bool) -> dict:
    """One scan candidate. Schema: README.md, "`btrfska scan` output"."""
    record = item.record
    return {
        "record": "node",
        "unsupported_format": unsupported_format,
        "physical": record.physical,
        "bytenr": record.bytenr,
        "bytenr_mapped": record.bytenr_mapped,
        "maps_here": record.maps_here,
        "generation": record.generation,
        "owner": record.owner,
        "level": record.level,
        "nritems": record.nritems,
        "valid": record.valid,
        "checks": dict.fromkeys(CHECK_NAMES) | {check.name: check.ok for check in record.checks},
        "problems": [
            *record.problems,
            *(f"{check.name}: {check.detail}" for check in record.checks if check.ok is False),
        ],
        "region": asdict(record.region),
        "status": item.status,
        "orphan": item.orphan,
        "outside_map": item.outside_map,
        "legacy_orphan": item.legacy_orphan,
        "log_tree": item.log_tree,
    }


def _failure_line(counts: dict[str, dict[str, int]]) -> str:
    """Invalid nodes met by the current and the backup-root walks, reuse apart from damage."""

    def side(found: dict[str, int]) -> str:
        detail = ", ".join(f"{name} {found[name]}" for name in FAILURE_CLASSES if found.get(name))
        return f"{sum(found.values())}" + (f" ({detail})" if detail else "")

    current, backup = side(counts["current"]), side(counts["backup"])
    return f"walk failures: current {current}; backup roots {backup}"


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan for tree blocks and classify them; the summary goes to stderr with --json."""
    stream = sys.stderr if args.json else sys.stdout
    with open_image(args.image) as img:
        fs = _open_checked(img, args)
        if fs is None:
            return EXIT_REFUSED
        result = scan_image(img, fs, full_sweep=args.full_sweep, workers=args.workers)
        # Streamed: one candidate in memory at a time (classify.py, "Memory").
        for item in result.classified:
            if args.json:
                record = _scan_record(item, fs.unsupported_format)
                print(json.dumps(record, separators=(",", ":")))

    plan, s, ctx = result.plan, result.summary, fs.reader.ctx
    probed = sum(region.end - region.start for region in plan.regions)
    hint = "full sweep" if plan.full_sweep else "use --full-sweep to include reallocated ranges"
    lines = [
        f"btrfska scan: {'full sweep' if plan.full_sweep else 'targeted'}, "
        f"{len(plan.regions)} regions, {probed} bytes probed at {ctx.sectorsize}-byte alignment",
        *(f"skipped: {r.kind} {r.start}-{r.end}" for r in plan.skipped),
        f"skipped as DATA: {s['skipped_data_bytes']} bytes ({hint})",
        f"candidates: {s['candidates']} (valid {s['valid']}, invalid {s['invalid']})",
        f"live: {s['live']}",
        f"orphans: {s['orphans']} (backup_reachable {s['backup_reachable']}, "
        f"unreferenced {s['unreferenced']})",
        f"outside current chunk map: {s['outside_map']} valid nodes "
        f"({s['outside_map_orphans']} orphans)",
        f"header bytenr not mapping to the node's physical offset: {s['bytenr_elsewhere']} "
        "valid nodes",
        f"legacy-compatible orphans (csum ok, generation < {ctx.generation}, nodesize-aligned): "
        f"{s['legacy_orphans']} ({s['legacy_orphans_outside_map']} outside current chunk map)",
        f"extent tree: {s['extent_tree']} tree blocks; reached only by walks: {s['walk_only']}; "
        f"listed only by the extent tree: {s['extent_tree_only']}",
        f"log tree: {s['log_tree_blocks']} blocks ({s['log_tree']} live copies)",
        _failure_line(s["walk_failures"]),
    ]
    for row in s["regions"]:
        region = row["region"]
        origin = "" if region.chunk is None else f" (chunk {region.chunk} stripe {region.stripe})"
        lines.append(
            f"region {region.kind} {region.start}-{region.end}{origin}: "
            f"candidates {row['candidates']}, valid {row['valid']}, live {row['live']}, "
            f"orphans {row['orphans']}"
        )
    lines += [f"problem: {problem}" for problem in (*plan.problems, *result.reach.problems)]
    for line in lines:
        print(line, file=stream)
    return 0


def _state_line(state: State) -> str:
    labels = ", ".join(state.known_as) or "not a superblock or backup root"
    named = [tree for tree in state.trees if tree.status != "skipped"]
    found = sum(tree.status == "found" for tree in named)
    missing = ", ".join(f"{name} {count}" for name, count in sorted(state.missing.items()))
    line = (
        f"state generation {state.generation} bytenr {state.bytenr} level {state.level} "
        f"[{labels}]: trees {found}/{len(named)} found, blocks {state.found}/{state.referenced} "
        f"(completeness {state.completeness:.3f}{'; missing ' + missing if missing else ''})"
    )
    root = state.chunk_root
    if root is None:
        line += "; chunk root unknown"
    else:
        differs = ", differs from current" if root.differs_from_current else ""
        line += f"; chunk root {root.bytenr} generation {root.generation} ({root.source}{differs})"
    line += f"; blocks placed by the current chunk map {state.maps_current}"
    if state.maps_historical is not None:
        line += f", by the state's chunk items {state.maps_historical}"
    return line + f", by neither {state.maps_neither}"


def _rediscovery_line(rediscovered) -> str:
    """Superblock and backup survival per slot reference and per distinct block: backup slots name
    the same block many times (an fs root unchanged across backups), so the two counts differ."""
    blocks: dict[tuple, list] = {}
    for item in rediscovered:
        key = (item.root.bytenr, item.root.generation, item.root.level)
        blocks.setdefault(key, []).append(item)
    return (
        f"rediscovered: {sum(item.candidate for item in rediscovered)}/{len(rediscovered)} "
        "superblock and backup root slot references are candidate roots "
        f"({sum(item.indexed for item in rediscovered)} indexed), naming {len(blocks)} distinct "
        f"blocks: {sum(any(i.candidate for i in same) for same in blocks.values())}/{len(blocks)} "
        f"candidate roots ({sum(any(i.indexed for i in same) for same in blocks.values())} indexed)"
    )


def cmd_roots(args: argparse.Namespace) -> int:
    """Old-root discovery; the summary goes to stderr with --json. Schema: README.md."""
    stream = sys.stderr if args.json else sys.stdout
    with open_image(args.image) as img:
        fs = _open_checked(img, args)
        if fs is None:
            return EXIT_REFUSED
        run = discover_image(img, fs, full_sweep=args.full_sweep, workers=args.workers)
    found, stats, plan = run.discovery, run.discovery.stats, run.plan

    if args.json:

        def emit(kind: str, payload: dict) -> None:
            record = {"record": kind, "unsupported_format": fs.unsupported_format, **payload}
            print(json.dumps(record, separators=(",", ":")))

        for item in found.rediscovered:
            emit("rediscovery", asdict(item.root) | {"indexed": item.indexed,
                                                     "candidate": item.candidate})  # fmt: skip
        for state in found.states:
            emit("state", asdict(state))
        for group in found.groups:
            emit("group", asdict(group))
        for log in found.logs:
            emit("log", asdict(log))
        for raw in found.raw:
            emit("raw_block", raw)
        for source, tree_id, bytenr, failure in found.walk_failures:
            where = {"source": source, "tree_id": tree_id, "bytenr": bytenr}
            emit("walk_failure", where | {"class": failure})

    skipped_data = sum(r.end - r.start for r in plan.skipped if r.chunk is not None)
    hint = "full sweep" if plan.full_sweep else "use --full-sweep to include reallocated ranges"
    beyond = sum(not state.known_as for state in found.states)
    lines = [
        f"btrfska roots: {'full sweep' if plan.full_sweep else 'targeted'}, "
        f"{stats['candidates']} candidates, {stats['indexed_copies']} valid copies of "
        f"{run.index.nodes} tree blocks indexed",
        f"skipped as DATA: {skipped_data} bytes ({hint})",
        f"log candidates: {stats['log_accepted']} indexed one generation ahead, "
        f"{stats['log_rejected']} rejected",
        f"groups: {len(found.groups)} (owner, generation, level); candidate roots: "
        f"{sum(group.candidates for group in found.groups)}",
        f"root tree candidates: {found.root_tree_candidates} ({len(found.states)} evaluated, "
        f"{beyond} beyond the superblock and backup roots)",
        _rediscovery_line(found.rediscovered),
        *(
            f"not rediscovered: {item.root.source} {item.root.tree} {item.root.bytenr} "
            f"generation {item.root.generation} ({'indexed' if item.indexed else 'not indexed'})"
            for item in found.rediscovered
            if not item.candidate
        ),
        *(_state_line(state) for state in found.states),
    ]
    for log in found.logs:
        lines.append(
            f"log generation {log.generation}: {log.blocks} blocks ({log.copies} copies), "
            f"candidate roots {log.candidates}, live {log.live}, superseded {log.superseded}"
            + (", left by a committed transaction" if log.committed else "")
        )
    if not found.logs:
        lines.append("log trees: none")
    lines += [
        f"raid stripe tree blocks: {stats['raid_stripe_blocks']}; "
        f"remap tree blocks: {stats['remap_blocks']}",
        _failure_line(failure_counts(found.walk_failures)),
        *(f"problem: {problem}" for problem in (*plan.problems, *run.walk_problems)),
        *(
            f"problem: state generation {state.generation} bytenr {state.bytenr}: {problem}"
            for state in found.states
            for problem in state.problems
        ),
    ]
    for line in lines:
        print(line, file=stream)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="btrfska",
        description="Read-only forensic analysis of raw Btrfs images.",
        epilog="exit status: 0 ok, 1 error, 2 refused (no valid superblock or unsupported format)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser(
        "info", help="superblock copies, feature gate, checksum type and backup roots"
    )
    info.add_argument("image", help="path to a raw Btrfs image")
    info.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (output is flagged)",
    )
    info.set_defaults(func=cmd_info)

    walk_cmd = sub.add_parser(
        "walk",
        help="walk one tree of the current state, a backup root or a block (JSON lines)",
        description=(
            "Emit one JSON line per leaf item, with the root it was reached from and every "
            "physical copy's validation record. Invalid nodes and walk problems are records "
            "too; a summary goes to stderr."
        ),
    )
    walk_cmd.add_argument("image", help="path to a raw Btrfs image")
    walk_cmd.add_argument(
        "--root",
        default="current",
        type=_root_spec,
        help="current (default), backup:GEN (a backup root by generation) or bytenr:N (one block)",
    )
    walk_cmd.add_argument(
        "--tree",
        type=_tree_spec,
        help=(
            f"{', '.join(TREE_IDS)} or a tree id (default fs); with bytenr:N it only sets the "
            "expected owner"
        ),
    )
    walk_cmd.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (records are flagged)",
    )
    walk_cmd.set_defaults(func=cmd_walk)

    cat_cmd = sub.add_parser(
        "cat",
        help="write one file's bytes from the current state or a backup root to stdout",
        description=(
            "Read an inode of an fs tree through the chunk map and write its bytes to stdout, "
            "only if every extent reads. One JSON record per extent and one for the file go to "
            "stderr, then a summary."
        ),
    )
    cat_cmd.add_argument("image", help="path to a raw Btrfs image")
    cat_cmd.add_argument(
        "--root",
        default="current",
        type=_root_spec,
        help="current (default), backup:GEN or bytenr:N (the fs tree block itself)",
    )
    cat_cmd.add_argument(
        "--tree", type=_tree_spec, help="fs (default) or a subvolume or snapshot id"
    )
    cat_cmd.add_argument("--inode", type=int, required=True, help="inode number in that tree")
    cat_cmd.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (records are flagged)",
    )
    cat_cmd.set_defaults(func=cmd_cat)

    scan_cmd = sub.add_parser(
        "scan",
        help="scan the image for tree blocks and classify them live, backup-reachable or orphaned",
        description=(
            "Probe every sector-aligned offset of the typed chunk regions and unmapped gaps for "
            "tree blocks of this filesystem, validate each candidate and classify it against the "
            "walks of the current state and the backup roots. A summary goes to stdout, or to "
            "stderr with --json."
        ),
    )
    scan_cmd.add_argument("image", help="path to a raw Btrfs image")
    scan_cmd.add_argument(
        "--full-sweep",
        action="store_true",
        help="probe DATA chunks too (everything except the boot area and superblock copies)",
    )
    scan_cmd.add_argument(
        "--workers",
        type=_workers,
        default=1,
        help=f"worker processes, 1 to {MAX_WORKERS} (default 1)",
    )
    scan_cmd.add_argument(
        "--json", action="store_true", help="one JSON line per candidate node on stdout"
    )
    scan_cmd.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (records are flagged)",
    )
    scan_cmd.set_defaults(func=cmd_scan)

    roots_cmd = sub.add_parser(
        "roots",
        help="find historical tree roots among the scanned blocks and how complete each is",
        description=(
            "Scan as `scan` does, index the valid tree blocks and find the candidate roots: blocks "
            "no parent of their generation or a newer one points to, at any level. Each "
            "candidate root-tree block is one state: its root tree and the trees its ROOT_ITEMs "
            "name are resolved through the scanned blocks, with a completeness figure (chunk and "
            "log trees excluded), and every "
            "superblock and backup root is checked for rediscovery. A summary goes to stdout, or "
            "to stderr with --json."
        ),
    )
    roots_cmd.add_argument("image", help="path to a raw Btrfs image")
    roots_cmd.add_argument(
        "--full-sweep",
        action="store_true",
        help="probe DATA chunks too (everything except the boot area and superblock copies)",
    )
    roots_cmd.add_argument(
        "--workers",
        type=_workers,
        default=1,
        help=f"worker processes for the scan, 1 to {MAX_WORKERS} (default 1)",
    )
    roots_cmd.add_argument("--json", action="store_true", help="JSON lines records on stdout")
    roots_cmd.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (records are flagged)",
    )
    roots_cmd.set_defaults(func=cmd_roots)

    catalog_cli.add_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"btrfska: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
