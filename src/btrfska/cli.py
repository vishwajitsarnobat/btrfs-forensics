"""Command-line interface."""

import argparse
import sys

from btrfska import __version__
from btrfska.substrate.image import open_image


def cmd_info(args: argparse.Namespace) -> int:
    with open_image(args.image) as img:
        print(f"image:  {img.path}")
        print(f"size:   {img.size} bytes")
        print(f"sha256: {img.sha256()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="btrfska",
        description="Read-only forensic analysis of raw Btrfs images.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="print image size and sha256")
    info.add_argument("image", help="path to a raw Btrfs image")
    info.set_defaults(func=cmd_info)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"btrfska: error: {exc}", file=sys.stderr)
        return 1
