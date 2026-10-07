"""The M7 corpus matrix (docs/plan.md M7a): which configurations are built, as manifest rows.

    uv run python corpus/matrix.py            # print the rows of both tiers
    uv run python corpus/matrix.py --write    # rewrite corpus/matrix.tsv and corpus/large.tsv

The design follows plan.md M7: a full factorial only where an axis interacts with recovery
(discard x operation, block-group tree x balance, reclaim x discard), and otherwise one factor at
a time from the base configuration. Every row runs `corpus/vm/scenarios/matrix.sh`, with only the
axes that differ from the base on its command line, so each image is a recipe.

Two tiers. `matrix` (corpus/matrix.tsv, 512 MiB and 8 GiB images) is built by
`corpus/build.py --tier matrix` and used by the experiments; it is not part of `./setup.sh` or CI,
which build the default tier (corpus/manifest.tsv) only. `large` (corpus/large.tsv, the 100 GiB
image) is built locally only, by `corpus/build.py --tier large`: a CI runner has about 14 GB of
disk. The rows of corpus/manifest.tsv stay as they are, because several experiments take "every
manifest image" as their image set.
"""

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = "corpus/vm/scenarios/matrix.sh"
MKFS = "btrfs-progs v6.6.3 (pinned)"
KERNEL = "7.0.0-31-generic"
COLUMNS = ["name", "command", "mkfs", "guest_kernel", "note"]

# The axes and their values, in the order matrix.sh documents them. The first value is the base.
AXES = {
    "OP": ["delete", "overwrite", "stress", "snapshot", "balance", "defrag"],
    "SIZE": ["512M", "8G", "100G"],
    "COMPRESS": ["none", "zstd", "lzo", "zlib"],
    "CSUM": ["crc32c", "xxhash", "sha256", "blake2b"],
    "BGT": ["off", "on"],
    "DISCARD_MODE": ["none", "async", "idle", "sync", "nodiscard"],
    "RECLAIM": ["off", "on"],
    "LAYOUT": ["single", "mixed", "raid1"],
}
BASE = {axis: values[0] for axis, values in AXES.items()}
# MIXED_GROUPS is a small-filesystem layout: mkfs.btrfs recommends it below 1 GiB.
MIXED_SIZE = "256M"


def row(name: str, note: str, **axes: str) -> dict:
    """A manifest row for one configuration: `axes` are the values that differ from the base."""
    for axis, value in axes.items():
        if value not in AXES.get(axis, [value]) and not (axis == "SIZE" and value == MIXED_SIZE):
            raise ValueError(f"{name}: {axis}={value} is not on the matrix")
    settings = " ".join(f"{axis}={value}" for axis, value in axes.items() if BASE[axis] != value)
    command = f"{settings} {SCRIPT} {name}".strip()
    return {"name": name, "command": command, "mkfs": MKFS, "guest_kernel": KERNEL, "note": note}


def configuration(row_: dict) -> dict[str, str]:
    """Every axis of a row, read back from its command: the base value where none is given."""
    axes = dict(BASE)
    for word in row_["command"].split():
        axis, _, value = word.partition("=")
        if axis in axes and value:
            axes[axis] = value
    return axes


def matrix_rows() -> list[dict]:
    rows = []
    # discard x operation, full factorial: the base configuration otherwise
    for op in AXES["OP"]:
        for discard in AXES["DISCARD_MODE"]:
            note = f"discard x operation: {op}, discard {discard}"
            if (op, discard) == ("delete", "none"):
                note += "; the base configuration of every one-factor row"
            rows.append(row(f"mx_{op}_{discard}", note, OP=op, DISCARD_MODE=discard))
    # block-group tree x balance: off x {delete, balance} are mx_delete_none and mx_balance_none
    for op in ("delete", "balance"):
        rows.append(
            row(f"mx_bgt_{op}", f"block-group tree x balance: tree on, {op}", BGT="on", OP=op)
        )
    # reclaim x discard: reclaim off x discard are the mx_delete_* rows
    for discard in AXES["DISCARD_MODE"]:
        note = f"reclaim x discard: reclaim on, discard {discard}"
        rows.append(row(f"mx_reclaim_{discard}", note, RECLAIM="on", DISCARD_MODE=discard))
    # one factor at a time from the base
    for compress in AXES["COMPRESS"][1:]:
        rows.append(
            row(f"mx_{compress}", f"one factor: compress-force={compress}", COMPRESS=compress)
        )
    for csum in AXES["CSUM"][1:]:
        rows.append(row(f"mx_{csum}", f"one factor: checksum {csum}", CSUM=csum))
    rows.append(row("mx_8g", "one factor: an 8 GiB filesystem (sparse image)", SIZE="8G"))
    rows.append(row("mx_mixed", "one factor: MIXED_GROUPS, a 256 MiB filesystem",
                    LAYOUT="mixed", SIZE=MIXED_SIZE))  # fmt: skip
    rows.append(row("mx_raid1", "one factor: two devices, data and metadata RAID1; the second "
                    "device is mx_raid1.dev2.img", LAYOUT="raid1"))  # fmt: skip
    return rows


def large_rows() -> list[dict]:
    return [
        row("mx_100g", "one factor: a 100 GiB filesystem (sparse image; local only)", SIZE="100G")
    ]


TIERS = {"matrix": ("matrix.tsv", matrix_rows), "large": ("large.tsv", large_rows)}


def tsv(rows: list[dict]) -> str:
    lines = ["\t".join(COLUMNS)] + ["\t".join(r[c] for c in COLUMNS) for r in rows]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite the tier manifests")
    args = parser.parse_args(argv)
    for file, rows in TIERS.values():
        text = tsv(rows())
        if args.write:
            (REPO / "corpus" / file).write_text(text)
            print(f"wrote corpus/{file} ({len(rows())} rows)")
        else:
            print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
