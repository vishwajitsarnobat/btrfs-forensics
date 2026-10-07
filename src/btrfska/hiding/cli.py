"""`btrfska hiding`: where data is hidden on the image (registered by btrfska/cli.py)."""

import argparse
import json
import sys

from btrfska.hiding.detect import detect, report_lines
from btrfska.scan.roots import discover_image
from btrfska.substrate.fs import NoValidSuperblock, UnsupportedFormat, open_filesystem
from btrfska.substrate.image import open_image

EXIT_REFUSED = 2


def _note(line: str) -> None:
    print(line, file=sys.stderr)


def cmd_hiding(args: argparse.Namespace) -> int:
    with open_image(args.image) as img:
        try:
            fs = open_filesystem(img, allow_unsupported=args.allow_unsupported)
        except NoValidSuperblock:
            _note("NO_VALID_SUPERBLOCK")
            return EXIT_REFUSED
        except UnsupportedFormat as exc:
            _note("gate: REFUSED")
            for line in exc.verdict.report_lines():
                _note(line)
            return EXIT_REFUSED

        def history():
            # Only when bytes past the last device extent are not zero: a scan for the chunk
            # trees of earlier states (plan.md M5a), as `btrfska roots` runs it.
            return [entry.chunk_map for entry in discover_image(img, fs).discovery.chunk_maps]

        findings, summary = detect(img, fs, history)
    flagged = {"unsupported_format": fs.unsupported_format}
    if args.json:
        for finding in findings:
            print(json.dumps(finding.record() | flagged, separators=(",", ":")))
        record = {"record": "hiding_summary"} | flagged | summary
        print(json.dumps(record, separators=(",", ":")))
    for line in report_lines(findings, summary):
        if not args.json:
            print(line)
        elif not line.startswith(("finding ", "  ")):  # the findings are the JSON records
            print(line, file=sys.stderr)
    return 0


def add_parser(sub) -> None:
    parser = sub.add_parser(
        "hiding",
        help="find data hidden in reserved fields, slack, odd names and outside the filesystem",
        description="Check every place a known technique hides data in btrfs: superblock "
        "reserved bytes and padding (ranges from the feature flags), sys_chunk_array slack, "
        "superblock slots, the boot area, backup-root divergence, node slack, diverging block "
        "copies, inode reserved bytes, nanosecond timestamps, STRING_ITEMs, file slack, device "
        "slack and invisible names. Each finding names its offset, its bytes and why a clean "
        "filesystem does not look like that. A summary goes to stdout, or to stderr with --json.",
    )
    parser.add_argument("image", help="path to a raw Btrfs image")
    parser.add_argument(
        "--json", action="store_true", help="one JSON line per finding, then a summary record"
    )
    parser.add_argument(
        "--allow-unsupported",
        action="store_true",
        help="continue past unsupported or unknown incompat features (records are flagged)",
    )
    parser.set_defaults(func=cmd_hiding)
