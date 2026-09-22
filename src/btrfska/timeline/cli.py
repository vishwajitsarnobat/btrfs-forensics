"""`btrfska timeline`: what happened to every inode, from the evidence database."""

import argparse
import json
import sys

from btrfska.catalog import db
from btrfska.substrate import ondisk
from btrfska.timeline.build import Timeline, hashes

EXIT_ERROR = 1
MAX_GAPS_SHOWN = 5


def _tree(text: str) -> int | None:
    if text == "all":
        return None
    if text.isdigit():
        return int(text)
    raise argparse.ArgumentTypeError(f"invalid tree {text!r}: expected a tree id or all")


def _when(event: dict) -> str:
    if event["transaction"] is not None:
        return f"gen {event['transaction']}"
    first, last = event["generations"] or (None, None)
    if first is None:
        return "gen ?"
    return f"gen {last}" if first + 1 >= last else f"gen {first + 1}..{last}"


def _line(event: dict) -> str:
    kind = event["event"]
    seen = ""
    if event.get("between"):
        seen = f"between {event['between'][0]} and {event['between'][1]}"
    elif "first_seen" in event:
        seen = f"first seen in {event['first_seen']['source']}"
    detail = ""
    if kind in ("rename", "move"):
        detail = f"{event['from']['path']} -> {event['to']['path']}"
    elif kind in ("link", "unlink"):
        detail = f"{event['name']['name']} in directory {event['name']['parent']}"
    elif kind == "modify":
        ranges = ", ".join(
            f"{d['change']} {d['offset']}+{d['length']}" for d in event["delta"][:4]
        ) + (", …" if len(event["delta"]) > 4 else "")
        detail = f"{event['size_before']} -> {event['size']} bytes ({ranges})"
    elif kind == "attr":
        detail = ", ".join(
            f"{name} {event['before'][name]:o} -> {event['after'][name]:o}" if name == "mode"
            else f"{name} {event['before'][name]} -> {event['after'][name]}"
            for name in event["before"] if event["before"][name] != event["after"][name]
        )  # fmt: skip
    elif kind == "create":
        detail = f"{event['kind']}, {event['size']} bytes"
        if event["reused_inode_number"]:
            detail += "; the inode number was used before by another file"
    marks = "".join(
        f" [{mark}]" for mark, on in (
            ("order within the generation assumed", event.get("order_assumed")),
            ("uncommitted", event.get("uncommitted_only")),
            ("from the log alone", event.get("log_only")),
            ("inconsistent", event.get("inconsistent")),
        ) if on
    )  # fmt: skip
    sha = f" sha256 {event['sha256'][:16]}…" if event.get("sha256") else ""
    return f"    {_when(event):<14} {kind:<16} {detail}{sha}{marks}  ({seen})"


def cmd_timeline(args: argparse.Namespace) -> int:
    try:
        conn = db.open_readonly(args.db)
    except db.CatalogError as exc:
        print(f"btrfska: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        timeline = Timeline(conn, tree_id=args.tree, uncommitted=args.uncommitted)
        known = hashes(conn)
        events = list(timeline.subvolume_events())
        for tree_id in sorted(timeline.trees):
            for event in timeline.events(tree_id):
                if args.inode in (None, event["objectid"]):
                    key = (tree_id, event["objectid"], event["created"], event["extent_signature"])
                    events.append(event | {"sha256": known.get(key)})
    finally:
        conn.close()
    if args.json:
        for event in events:
            print(json.dumps(event, separators=(",", ":")))
    else:
        _render(events)
    for line in timeline.gaps[:MAX_GAPS_SHOWN]:
        print(f"btrfska timeline: gap: {line}", file=sys.stderr)
    if len(timeline.gaps) > MAX_GAPS_SHOWN:
        more = len(timeline.gaps) - MAX_GAPS_SHOWN
        print(f"btrfska timeline: and {more} more gaps (each makes a walk incomplete: a file "
              "absent from it is `not_seen`, never `delete`)", file=sys.stderr)  # fmt: skip
    states = {tree.seen.source for shown in timeline.trees.values() for tree in shown}
    print(
        f"btrfska timeline: {len(events)} events, {len(timeline.trees)} trees, "
        f"{len(states)} sources, {len(timeline.gaps)} gaps",
        file=sys.stderr,
    )
    return 0


def _render(events: list[dict]) -> None:
    tree = identity = None
    for event in events:
        if event["event"] == "subvolume_deleted":
            print(f"tree {event['tree_id']}: subvolume deleted between {event['between'][0]} "
                  f"and {event['between'][1]} (gen {event['generations'][0] + 1}.."
                  f"{event['generations'][1]})")  # fmt: skip
            continue
        if event["tree_id"] != tree:
            tree, identity = event["tree_id"], None
            print(f"tree {tree}")
        if (event["objectid"], event["created"]) != identity:
            identity = (event["objectid"], event["created"])
            where = event["path"] or (
                "/" if event["objectid"] == ondisk.FIRST_FREE_OBJECTID else "?"
            )
            print(f"  inode {identity[0]} created in generation {identity[1]}: {where}")
        print(_line(event))


def add_parser(sub) -> None:
    parser = sub.add_parser(
        "timeline",
        help="what happened to every inode, across every cataloged state",
        description="Per-inode lifecycle from the evidence database: create, modify (with the "
        "byte ranges whose extents changed), rename, move, link, unlink, attr, touch, delete. "
        "Every state the catalog holds is compared, not only the backup roots. An inode is "
        "identified by tree, number and creation generation, because numbers are reused. "
        "Nothing is written; the image is not needed.",
    )
    parser.add_argument("db", help="evidence database (btrfska catalog build)")
    parser.add_argument(
        "--tree", type=_tree, default=None,
        help="a tree id (5 is the top-level fs tree) or all (default)",
    )  # fmt: skip
    parser.add_argument("--inode", type=int, help="only this inode number")
    parser.add_argument(
        "--uncommitted",
        action="store_true",
        help="also use fragments and lone leaves (recover --graph's sources): versions that were "
        "never committed, marked as such; they never prove a delete",
    )
    parser.add_argument("--json", action="store_true", help="one JSON object per event")
    parser.set_defaults(func=cmd_timeline)
