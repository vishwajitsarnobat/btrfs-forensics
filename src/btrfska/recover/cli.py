"""`btrfska recover` (registered by btrfska/cli.py)."""

import argparse
import sys

from btrfska.catalog import db
from btrfska.recover.dbtree import RootNotCataloged
from btrfska.recover.engine import RecoveryError, recover
from btrfska.recover.output import OutputError
from btrfska.substrate import ondisk
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat

EXIT_ERROR = 1
EXIT_REFUSED = 2
STATUSES = ("complete", "partial", "refused_encrypted", "duplicate", "recorded", "failed")


def _note(line: str) -> None:
    print(line, file=sys.stderr)


def _root(text: str) -> str:
    kind, _, number = text.partition(":")
    if text == "current" or (kind in ("backup", "state") and number.isdigit()):
        return text
    raise argparse.ArgumentTypeError(
        f"invalid root {text!r}: expected current, backup:GEN or state:ID"
    )


def _tree(text: str) -> int | None:
    if text == "all":
        return None
    if text.isdigit():
        return int(text)
    raise argparse.ArgumentTypeError(f"invalid tree {text!r}: expected a tree id or `all`")


def cmd_recover(args: argparse.Namespace) -> int:
    try:
        done = recover(
            args.image,
            args.db,
            args.out,
            roots=tuple(args.root or ["current"]),
            tree_id=args.tree,
            dedup=not args.no_dedup,
            rehash=not args.no_rehash,
            note=lambda line: _note(f"btrfska recover: {line}"),
        )
    except (NoValidSuperblock, UnsupportedFormat) as exc:
        _note(f"btrfska recover: refused: {exc}")
        return EXIT_REFUSED
    except (db.CatalogError, RecoveryError, OutputError, RootNotCataloged, OSError) as exc:
        _note(f"btrfska: error: {exc}")
        return EXIT_ERROR
    print(f"btrfska recover: wrote {done.output_dir} (recovery {done.recovery_id})")
    if not done.image_checked:
        print("image not compared with the database's hash (--no-rehash)")
    for root in done.roots:
        print(
            f"root {root.source}: state {root.state_id}, tree {root.tree_id} at {root.bytenr} "
            f"generation {root.generation} level {root.level}, "
            f"{len(done.gaps[f'{root.source} tree {root.tree_id}'])} gaps"
        )
    counts = ", ".join(f"{name} {done.counts.get(name, 0)}" for name in STATUSES)
    print(f"artifacts: {counts}; {done.bytes_written} bytes written")
    incomplete = sum(
        done.counts.get(name, 0) for name in ("partial", "refused_encrypted", "failed")
    )
    return EXIT_ERROR if incomplete else 0


def add_parser(sub) -> None:
    parser = sub.add_parser(
        "recover",
        help="extract the files of a tree as a cataloged root saw them",
        description="Extract the files of one tree as the current, a backup or a discovered "
        "root saw them. Metadata comes from the evidence database, file data from the image, one "
        "extent at a time. Files are written only below the new directory --out; the image is "
        "never written. Exit status 1 when any file is partial, refused or failed.",
    )
    parser.add_argument("image", help="path to the raw Btrfs image the database was built from")
    parser.add_argument("--db", required=True, help="evidence database of that image")
    parser.add_argument("--out", required=True, help="output directory; must not exist")
    parser.add_argument(
        "--root",
        action="append",
        type=_root,
        help="current, backup:GEN or state:ID (see `catalog info`); repeatable; default current",
    )
    parser.add_argument(
        "--tree",
        type=_tree,
        default=ondisk.FS_TREE_OBJECTID,
        help="tree id: 5 for the top-level fs tree (default), 256 and above for a subvolume, "
        "or `all` for every file tree the root names",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="write a file again for every root that holds it unchanged",
    )
    parser.add_argument(
        "--no-rehash",
        action="store_true",
        help="do not compare the image's SHA-256 with the one in the database",
    )
    parser.set_defaults(func=cmd_recover)
