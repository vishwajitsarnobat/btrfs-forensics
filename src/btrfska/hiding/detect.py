"""Hiding detection (plan.md M6d): where data can be hidden in btrfs, and whether it is.

The target list is Toolan & Humphries 2026 (FSI:DI 58:302198; research.md §8.3, §10.13), Göbel
et al. 2024 (file slack, nanosecond timestamps; docs/research/fishy-btrfs.md §2), Wani et al.
2020 (boot area, file slack, volume slack; research.md §8.4) and Schwietert & Hilgert 2025
(hidden snapshots, pooled-storage slack), plus backup-root divergence after
SecurityRonin/btrfs-forensic (`BTRFS-BACKUP-ROOT-DIVERGENCE`, forensic/src/lib.rs at e6cd73f).

Each rule reports bytes or fields that mkfs.btrfs and the kernel do not produce, so on a
filesystem written only by them it reports nothing. Why that holds is part of each rule, with
the kernel source at v7.0 cited by file and line (here and in areas.py and trees.py):

- `superblock_reserved`: non-zero bytes in `reserved[199]` (0x264-0x32A), in a feature-gated
  field whose incompat flag is clear (metadata_uuid, nr_global_roots, remap_root*), or in the
  padding of a backup root slot; every superblock copy, valid or not. The reserved ranges are a
  function of the feature flags, not constants (research.md §10.13).
- `superblock_padding`: non-zero bytes in `padding[565]` (0xDCB-0xFFF), every copy.
- `sys_chunk_array_slack`: bytes beyond `sys_chunk_array_size` that are neither zero nor one of
  the two shapes removing a system chunk leaves (volumes.c:3204).
- `superblock_slot`: a superblock slot inside the device that holds non-zero bytes but no
  superblock magic (every commit writes every mirror that fits: disk-io.c:3789-3808).
- `pre_superblock`: non-zero bytes in the first 64 KiB, or in the rest of the first MiB after the
  primary superblock (the kernel allocates from 1 MiB: fs.h:108, volumes.c:1664-1671); a boot
  sector signature is named, since GRUB 2 embeds itself there.
- `backup_root_divergence`: a backup root newer than the superblock, no slot of the superblock's
  generation, that slot disagreeing with the superblock fields it was written with, slot
  generations that repeat or are not consecutive, or a mirror of the same generation with other
  backup roots (disk-io.c:1594-1673, 4065-4069; transaction.c:392-393).
- `node_slack`: a valid tree block of the current state whose slack is not zero and does not read
  as stale items (substrate/slack.py; the kernel zeroes slack before every write, extent_io.c:2215,
  EXP-005). Slack that reads as stale items is what mkfs.btrfs leaves (EXP-005 §6.1) and is only
  counted.
- `copy_divergence`: two copies of one tree block that both pass every check but differ.
- `inode_reserved`: non-zero bytes in `reserved[4]` of an INODE_ITEM.
- `timestamp_nsec`: an INODE_ITEM nanosecond field of 10^9 or more, or all four of them readable
  as printable ASCII.
- `string_item`: an item of type STRING_ITEM (253) in any leaf.
- `file_slack`: non-zero bytes past the end of a regular file in its last sector, with the
  verdict of the data checksum on that sector (plan.md M6a's tail logic).
- `device_slack`: non-zero bytes past this device's last device extent, or past its total_bytes.
- `hidden_name`: a directory entry, a subvolume or snapshot included, whose name holds invisible or
  control characters, bytes that are not UTF-8, or only whitespace (Schwietert & Hilgert's U+FEFF
  snapshot; their image holds it as a plain directory, not a subvolume).

The trees examined are those of the current state; superseded blocks are not examined (a scan
finds them; `catalog build` describes their slack in `contents`). Everything is read through
`substrate/image.py`; nothing is written.
"""

from btrfska.hiding import areas, trees
from btrfska.hiding.findings import Finding
from btrfska.substrate.roots import find_root_set

TECHNIQUES = (
    "superblock_reserved",
    "superblock_padding",
    "sys_chunk_array_slack",
    "superblock_slot",
    "pre_superblock",
    "backup_root_divergence",
    "node_slack",
    "copy_divergence",
    "inode_reserved",
    "timestamp_nsec",
    "string_item",
    "file_slack",
    "device_slack",
    "hidden_name",
)


def detect(img, fs, history=None) -> tuple[list[Finding], dict]:
    """Every finding on the image, in TECHNIQUES order, and the summary of what was examined.

    `history` returns the historical chunk maps (scan/chunkmaps.py) when device slack needs them;
    see areas.device_slack_findings. Without it, bytes a removed chunk left past the last device
    extent are reported."""
    found, checked = areas.superblock_findings(img, fs.fields)
    found += areas.boot_area_findings(img)
    found += areas.backup_root_findings(fs.selection)
    root_set = find_root_set(fs.fields, "current")
    in_trees, census, extents = trees.tree_findings(img, fs, root_set)
    found += in_trees
    device, device_checked = areas.device_slack_findings(img, fs.fields, extents, history)
    found += device
    order = {name: index for index, name in enumerate(TECHNIQUES)}
    found.sort(key=lambda finding: (order[finding.technique], finding.physical))
    counts = dict.fromkeys(TECHNIQUES, 0)
    for finding in found:
        counts[finding.technique] += 1
    summary = {
        "techniques": list(TECHNIQUES),
        "findings": len(found),
        "by_technique": counts,
        "superblock": checked,
        "trees": census,
        "device": device_checked | {"extents": len(extents)},
    }
    return found, summary


def report_lines(findings: list[Finding], summary: dict) -> list[str]:
    """The text `btrfska hiding` prints and `catalog build --hiding` stores as problems."""
    t = summary["trees"]
    lines = [
        f"hiding: {len(summary['techniques'])} techniques checked, {summary['findings']} findings"
        f"; {summary['superblock']['copies']} superblock copies, {t['trees']} trees, "
        f"{t['blocks']} blocks ({t['copies']} copies), {t['inodes']} inodes, "
        f"{t['files_checked']} file tails, {t['subvolumes']} subvolumes",
    ]
    if t["stale_slack"]:
        lines.append(
            f"hiding: {t['stale_slack']} block copies with slack that reads as stale items (left "
            "by mkfs.btrfs or another writer that does not clear slack; not findings)"
        )
    tails = summary["superblock"]["stale_array_tails"]
    if tails:
        shown = ", ".join(f"{count} {shape}" for shape, count in sorted(tails.items()))
        lines.append(
            f"hiding: sys_chunk_array tails left by removed system chunks ({shown}; not findings)"
        )
    for finding in findings:
        lines.append(f"finding {finding.technique}: {finding.where}: {finding.nonzero} bytes")
        lines.append(f"  evidence: {finding.evidence}")
        if finding.text.strip(". "):
            lines.append(f"  bytes: {finding.text!r}")
    return lines
