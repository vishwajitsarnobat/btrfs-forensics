"""Command-line interface."""

import argparse
import sys
import uuid

from btrfska import __version__
from btrfska.substrate import csum, ondisk, superblock
from btrfska.substrate.image import open_image

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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"btrfska: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
