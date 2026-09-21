"""`btrfska catalog build`, `info` and `query` (registered by btrfska/cli.py)."""

import argparse
import json
import sys

from btrfska.catalog import db, query
from btrfska.catalog.build import MAX_STATES, TABLES, build_catalog, row_counts
from btrfska.scan.kernel_numpy import MAX_WORKERS
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat

EXIT_ERROR = 1
EXIT_REFUSED = 2


def _note(line: str) -> None:
    print(line, file=sys.stderr)


def _workers(text: str) -> int:
    value = int(text)
    if not 1 <= value <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WORKERS}")
    return value


def cmd_build(args: argparse.Namespace) -> int:
    try:
        built = build_catalog(
            args.image,
            args.db,
            full_sweep=args.full_sweep,
            workers=args.workers,
            allow_unsupported=args.allow_unsupported,
            rehash=not args.no_rehash,
            max_states=args.max_states,
        )
    except NoValidSuperblock:
        _note("NO_VALID_SUPERBLOCK")
        return EXIT_REFUSED
    except UnsupportedFormat as exc:
        _note("gate: REFUSED")
        for line in exc.verdict.report_lines():
            _note(line)
        return EXIT_REFUSED
    except db.CatalogError as exc:
        _note(f"btrfska: error: {exc}")
        return EXIT_ERROR
    summary = built.scan_summary
    print(f"btrfska catalog: wrote {built.path}")
    print(f"image sha256 {built.image_sha256}")
    if built.image_unchanged is None:
        print("image not hashed again after the pass (--no-rehash)")
    else:
        print(f"image unchanged after the pass: {'yes' if built.image_unchanged else 'NO'}")
    print(
        f"candidates: {summary['candidates']} (valid {summary['valid']}); live {summary['live']}, "
        f"backup_reachable {summary['backup_reachable']}, unreferenced {summary['unreferenced']}"
    )
    print(f"root tree candidates: {built.root_tree_candidates} ({built.states} states evaluated)")
    print("rows: " + ", ".join(f"{name} {count}" for name, count in built.rows.items()))
    return 0 if built.image_unchanged is not False else EXIT_ERROR


def cmd_info(args: argparse.Namespace) -> int:
    try:
        conn = db.open_readonly(args.db)
    except db.CatalogError as exc:
        _note(f"btrfska: error: {exc}")
        return EXIT_ERROR
    with conn:
        run = dict(conn.execute("SELECT * FROM scan_runs").fetchone())
        counts = row_counts(conn)
        classes = dict(
            conn.execute("SELECT status, COUNT(*) FROM nodes GROUP BY status").fetchall()
        )
        blocks = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    conn.close()
    run.pop("scan_summary")
    if args.json:
        print(json.dumps({"scan_run": run, "rows": counts, "classes": classes, "blocks": blocks}))
        return 0
    for key, value in run.items():
        print(f"{key}: {value}")
    print("rows: " + ", ".join(f"{name} {counts[name]}" for name in TABLES))
    print("nodes by status: " + ", ".join(f"{k} {v}" for k, v in sorted(classes.items())))
    print(f"distinct valid blocks: {blocks}")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    try:
        conn = db.open_readonly(args.db)
    except db.CatalogError as exc:
        _note(f"btrfska: error: {exc}")
        return EXIT_ERROR
    with conn:
        if args.query == "parents-of":
            rows = query.parents_of(conn, args.bytenr, args.generation)
        elif args.query == "owners-of":
            rows = query.owners_of(conn, args.bytenr)
        elif args.query == "trees-covering":
            rows = query.trees_covering(conn, args.objectid, args.type, args.offset)
        else:
            rows = query.items_in_generation(conn, args.generation, args.type, args.limit)
    conn.close()
    for row in rows:
        print(json.dumps(row))
    _note(f"btrfska catalog query {args.query}: {len(rows)} rows")
    return 0


def _u64(text: str) -> int:
    value = int(text, 0)
    if not 0 <= value < 1 << 64:
        raise argparse.ArgumentTypeError("must be an unsigned 64-bit integer")
    return value


def add_parser(sub) -> None:
    """Register `catalog` and its subcommands on the top-level subparsers object."""
    catalog = sub.add_parser(
        "catalog",
        help="build and inspect the evidence database of an image",
        description="Build the evidence database of an image in one read-only pass, or inspect "
        "one. The schema is documented in docs/evidence-db.md.",
    )
    commands = catalog.add_subparsers(dest="catalog_command", required=True)

    build = commands.add_parser(
        "build",
        help="scan IMAGE once and write its evidence database",
        description="Scan IMAGE once, read-only, and write its evidence database to --db. The "
        "path must not exist: a database is never overwritten. The image's SHA-256 is recorded "
        "before and after the pass.",
    )
    build.add_argument("image", help="path to a raw Btrfs image")
    build.add_argument("--db", required=True, help="database file to create (must not exist)")
    build.add_argument("--full-sweep", action="store_true", help="scan DATA chunks too")
    build.add_argument(
        "--workers",
        type=_workers,
        default=1,
        help=f"worker processes for the scan, 1 to {MAX_WORKERS} (default 1)",
    )
    build.add_argument(
        "--max-states",
        type=int,
        default=MAX_STATES,
        metavar="N",
        help=f"evaluate at most the N newest root trees as states (default {MAX_STATES}); more "
        "candidates than that are reported in `problems`",
    )
    build.add_argument(
        "--no-rehash",
        action="store_true",
        help="do not hash the image a second time after the pass (recorded as unknown)",
    )
    build.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (the run is flagged)",
    )
    build.set_defaults(func=cmd_build)

    info = commands.add_parser(
        "info",
        help="print the scan run and row counts of a database",
        description="Open DB read-only and print its scan run (chain of custody) and row counts.",
    )
    info.add_argument("db", help="an evidence database written by `catalog build`")
    info.add_argument("--json", action="store_true", help="one JSON object on stdout")
    info.set_defaults(func=cmd_info)

    ask = commands.add_parser(
        "query",
        help="reverse queries answered from the database alone",
        description="Reverse queries over an evidence database. The image is not needed. One "
        "JSON object per line on stdout; the row count on stderr.",
    )
    ask.add_argument("db", help="an evidence database written by `catalog build`")
    queries = ask.add_subparsers(dest="query", required=True)
    parents = queries.add_parser(
        "parents-of", help="what references a tree block: nodes, ROOT_ITEMs, the superblock"
    )
    parents.add_argument("bytenr", type=_u64, help="logical address of the tree block")
    parents.add_argument("--generation", type=_u64, help="only references to this generation")
    owners = queries.add_parser(
        "owners-of", help="what uses an extent: file extents, extent back-references, tree blocks"
    )
    owners.add_argument("bytenr", type=_u64, help="logical address of the extent")
    covering = queries.add_parser(
        "trees-covering", help="the leaves whose key range holds a key, in every generation"
    )
    covering.add_argument("objectid", type=_u64)
    covering.add_argument("type", type=_u64, help="key type number, for example 1 for INODE_ITEM")
    covering.add_argument("offset", type=_u64)
    in_gen = queries.add_parser(
        "items-in-generation", help="the items of every leaf written in a generation"
    )
    in_gen.add_argument("generation", type=_u64)
    in_gen.add_argument("--type", type=_u64, help="only items of this key type number")
    in_gen.add_argument("--limit", type=int, help="at most this many rows")
    ask.set_defaults(func=cmd_query)
