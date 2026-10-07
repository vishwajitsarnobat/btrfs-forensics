"""Hiding places inside the trees of the current state, and in the files they describe.

Every tree the current root tree names is walked (root, chunk and log trees included), as
`scan` walks the current state (scan/classify.py `walk_root_set`). Each valid block is examined
once, each of its valid physical copies on its own; the per-file rule streams each subvolume's
items in key order. The rules and their citations are in detect.py.
"""

import stat
import unicodedata
from collections import deque
from dataclasses import dataclass, field

from btrfska.hiding.findings import Finding, area_finding, preview
from btrfska.substrate import csum, items, ondisk, slack
from btrfska.substrate.chunks import MappingError
from btrfska.substrate.datacsum import tree_from_image
from btrfska.substrate.node import is_subvolume_tree
from btrfska.substrate.roots import RootNotFound, RootSet, TreeRoot, resolve_tree, subvolumes
from btrfska.substrate.tree import walk

K = ondisk.ITEM_KEYS
HEADER = ondisk.HEADER.size
LOG = ondisk.TREE_LOG_OBJECTID
_INODE = ondisk.INODE_ITEM
RESERVED = (_INODE.offset("sequence") + 8, _INODE.offset("atime_sec"))  # reserved[4], 32 bytes
NSEC_FIELDS = ("atime_nsec", "ctime_nsec", "mtime_nsec", "otime_nsec")
NSEC_PER_SEC = 10**9
# Unicode categories that render as nothing, or as something else, in a listing.
ODD_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn", "Zl", "Zp", "Cs"})
MAX_STALE_LISTED = 16  # blocks whose slack reads as stale items, listed in the summary
MAX_PROBLEMS = 32


@dataclass
class Census:
    """What the tree rules examined, for the summary."""

    trees: int = 0
    blocks: int = 0
    copies: int = 0
    nonzero_slack: int = 0
    stale_slack: list = field(default_factory=list)  # (bytenr, generation, owner, level)
    stale_slack_count: int = 0
    inodes: int = 0
    log_reserved: int = 0  # log-tree inode items with non-zero reserved bytes (not findings)
    files_checked: int = 0  # regular files whose last sector holds bytes past the end
    subvolumes: int = 0
    problems: list = field(default_factory=list)

    def problem(self, text: str) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(text)

    def summary(self) -> dict:
        return {
            "trees": self.trees,
            "blocks": self.blocks,
            "copies": self.copies,
            "nonzero_slack": self.nonzero_slack,
            "stale_slack": self.stale_slack_count,
            "stale_slack_blocks": [list(entry) for entry in self.stale_slack],
            "inodes": self.inodes,
            "log_inode_reserved": self.log_reserved,
            "files_checked": self.files_checked,
            "subvolumes": self.subvolumes,
            "problems": self.problems,
        }


def _log_root(fields: dict) -> TreeRoot | None:
    if not fields["log_root"]:
        return None
    return TreeRoot(
        LOG, fields["log_root"], fields["log_root_level"], fields["generation"] + 1,
        "superblock log_root", log=True,
    )  # fmt: skip


def _trees(reader, root_set: RootSet, fields: dict, census: Census):
    """(tree, visits) for every tree of the current state, each tree once."""
    queue = deque(
        (tree, tree.tree_id == ondisk.ROOT_TREE_OBJECTID) for tree in root_set.trees.values()
    )
    if (log_root := _log_root(fields)) is not None:
        queue.append((log_root, True))
    seen = set()
    while queue:
        tree, names_trees = queue.popleft()
        if (tree.bytenr, tree.log) in seen:
            continue
        seen.add((tree.bytenr, tree.log))
        census.trees += 1
        children = []

        def visits(tree=tree, names_trees=names_trees, children=children):
            for visit in walk(reader, tree.bytenr, tree.expect()):
                node = visit.node
                if not node.valid:
                    census.problem(f"tree {tree.tree_id} node {node.logical} is invalid")
                    continue
                if names_trees and node.level == 0:
                    for item in node.items:
                        if item.key.type != K["ROOT_ITEM"]:
                            continue
                        if tree.log and item.key.objectid != LOG:
                            continue
                        try:
                            parsed = items.root_item(item.data)
                        except items.ItemError:
                            continue
                        children.append(
                            TreeRoot(
                                item.key.objectid,
                                parsed["bytenr"],
                                parsed["level"],
                                parsed["generation"],
                                f"ROOT_ITEM {item.key}",
                                log=tree.log,
                            )  # fmt: skip
                        )
                yield visit

        yield tree, visits()
        queue.extend((child, False) for child in children)


def _block_findings(img, node, ctx, census: Census) -> list[Finding]:
    """Slack of every valid copy, and copies of one block that differ although both are valid."""
    found = []
    good = [copy for copy in node.copies if copy.ok]
    blocks = {c.physical: img.mmap[c.physical : c.physical + ctx.nodesize] for c in good}
    census.copies += len(good)
    for copy in good:
        block = blocks[copy.physical]
        report = slack.describe(block, ctx.nodesize, ctx.sectorsize)
        if not report.nonzero:
            continue
        census.nonzero_slack += 1
        if report.slack_class == slack.STALE:
            census.stale_slack_count += 1
            if len(census.stale_slack) < MAX_STALE_LISTED:
                census.stale_slack.append((node.logical, node.generation, node.owner, node.level))
            continue
        kind = "internal node" if node.level else "leaf"
        start, end = report.start, report.start + report.length
        finding = area_finding(
            "node_slack", copy.physical + start, block[start:end],
            f"{kind} {node.logical} (owner {node.owner}, generation {node.generation}) mirror "
            f"{copy.mirror} at {copy.physical}, slack bytes {start}-{end - 1}",
            "the block's checksum holds, yet its slack is not zero and does not begin with a stale "
            "item: the kernel zeroes the slack of every tree block it writes (extent_io.c:2215 "
            "prepare_eb_write, since v4.9; EXP-005), and what mkfs.btrfs leaves there reads as "
            "stale items",
            bytenr=node.logical, generation=node.generation, owner=node.owner, level=node.level,
            mirror=copy.mirror,
        )  # fmt: skip
        found.append(finding)
    first = good[0] if good else None
    for copy in good[1:]:
        a, b = bytes(blocks[first.physical]), bytes(blocks[copy.physical])
        if a == b:
            continue
        differing = [i for i in range(len(a)) if a[i] != b[i]]
        hex_, text = preview(b[differing[0] : differing[0] + 32])
        found.append(
            Finding(
                "copy_divergence",
                copy.physical,
                ctx.nodesize,
                len(differing),
                f"block {node.logical} (owner {node.owner}, generation {node.generation}): mirror "
                f"{copy.mirror} at {copy.physical} differs from mirror {first.mirror} at "
                f"{first.physical}",
                f"both copies pass every check but {len(differing)} bytes differ, from byte "
                f"{differing[0]}: the kernel writes every copy of a tree block from one buffer "
                "(bio.c:581-587 submits one clone of the same bio per mirror, :533-558), so one "
                "copy was rewritten and its checksum recomputed",
                hex_,
                text,
                {
                    "bytenr": node.logical,
                    "mirrors": [first.mirror, copy.mirror],
                    "first_difference": differing[0],
                },
            )  # fmt: skip
        )
    return found


def _printable(value: int) -> bool:
    return all(0x20 <= byte < 0x7F for byte in value.to_bytes(4, "little"))


def _item_findings(node, physical: int, tree, census: Census) -> list[Finding]:
    """INODE_ITEM reserved bytes and nanoseconds, and STRING_ITEMs, in one leaf (chosen copy).

    The reserved bytes of a log tree's inode items are not a finding: the log inserts an empty
    item and sets its fields one by one (tree-log.c:4613-4672, :4720, :4989-4993), so whatever
    the new leaf's buffer held stays in them. Log replay copies such an item into the subvolume
    tree whole (tree-log.c:668 in overwrite_item), where it stays until the inode's next update.
    """
    tree_id = tree.tree_id
    found = []
    for item in node.items:
        at = physical + HEADER + item.offset
        where = f"tree {tree_id} leaf {node.logical} slot {item.slot}, item {item.key}"
        if item.key.type == ondisk.ITEM_KEYS["STRING_ITEM"]:
            hex_, text = preview(item.data)
            found.append(
                Finding(
                    "string_item",
                    at,
                    item.size,
                    item.size - item.data.count(0),
                    where,
                    "an item of type STRING_ITEM (253), which btrfs_tree.h:373-377 defines 'for "
                    "debugging' and no code of the kernel or btrfs-progs creates",
                    hex_,
                    text,
                    {"tree": tree_id, "bytenr": node.logical, "slot": item.slot},
                )  # fmt: skip
            )
            continue
        if item.key.type != K["INODE_ITEM"] or item.size < _INODE.size:
            continue
        census.inodes += 1
        reserved = item.data[slice(*RESERVED)]
        if tree.log:
            census.log_reserved += bool(any(reserved))
            reserved = b""
        finding = area_finding(
            "inode_reserved", at + RESERVED[0], reserved, f"{where}, reserved bytes",
            "reserved[4] of the inode item (btrfs_tree.h:903) is zeroed when the kernel creates "
            "the item (inode.c:6775-6777) and never set afterwards: updates write named fields "
            "(inode.c:4272-4306) or a copy kept in a zero-allocated delayed node "
            "(delayed-inode.c:150, :1035)",
            tree=tree_id, inode=item.key.objectid, bytenr=node.logical, slot=item.slot,
        )  # fmt: skip
        if finding is not None:
            found.append(finding)
        fields = _INODE.unpack_from(item.data)
        values = {name: fields[name] for name in NSEC_FIELDS}
        over = {name: value for name, value in values.items() if value >= NSEC_PER_SEC}
        if over:
            reason = (
                f"{', '.join(f'{n} {v}' for n, v in over.items())} >= 10^9: a nanosecond field is "
                "below 10^9 whatever the kernel writes (fs/utimes.c:13-19 refuses more from user "
                "space, fs/inode.c:2793 timestamp_truncate keeps it below NSEC_PER_SEC)"
            )
        elif len(set(values.values())) == 4 and all(map(_printable, values.values())):
            reason = (
                "the four nanosecond fields are four different values that all read as printable "
                "ASCII: about 0.6 % of values below 10^9 do, so four independent ones do with a "
                "probability near 10^-9 per inode (equal values are not counted: the kernel often "
                "writes one time into several fields)"
            )
        else:
            continue
        start = _INODE.offset("atime_nsec")
        raw = b"".join(value.to_bytes(4, "little") for value in values.values())
        hex_, text = preview(raw)
        found.append(
            Finding(
                "timestamp_nsec",
                at + start,
                _INODE.size - start,
                len(over) or 4,
                f"{where}, nanosecond fields",
                reason,
                raw.hex(),
                text,
                {
                    "tree": tree_id,
                    "inode": item.key.objectid,
                    "bytenr": node.logical,
                    "slot": item.slot,
                    "nsec": values,
                },
            )  # fmt: skip
        )
    return found


class _Files:
    """Bytes past the end of each regular file in its last sector, streamed per tree.

    The kernel zeroes the rest of the last page before it writes a file's end
    (extent_io.c:1857-1858) and checksums the sector after that, so on a clean filesystem these
    bytes are zero. The check covers uncompressed regular extents: an inline extent has no
    sector of its own, a prealloc extent holds nothing written, and a compressed extent's bytes
    past the end are not a sector of the file.
    """

    def __init__(self, img, fs, csums, census: Census):
        self.img, self.fs, self.csums, self.census = img, fs, csums, census
        self.sectorsize = fs.reader.ctx.sectorsize
        self.seen: set[int] = set()

    def tree(self, tree_id: int):
        inode = {"objectid": None}
        found = []

        def item(entry):
            key = entry.key
            if key.type == K["INODE_ITEM"]:
                try:
                    fields = items.inode_item(entry.data)
                except items.ItemError:
                    inode["objectid"] = None
                    return
                inode.update(objectid=key.objectid, size=fields["size"], mode=fields["mode"],
                             flags=fields["flags"])  # fmt: skip
            elif key.type == K["EXTENT_DATA"] and key.objectid == inode["objectid"]:
                size = inode["size"]
                if not stat.S_ISREG(inode["mode"]) or not size % self.sectorsize:
                    return
                try:
                    extent = items.file_extent(entry.data)
                except items.ItemError:
                    return
                if (extent["type"] != ondisk.FILE_EXTENT_REG or extent["compression"]
                        or extent["encryption"] or not extent["disk_bytenr"]):  # fmt: skip
                    return
                last = (size - 1) // self.sectorsize * self.sectorsize
                if not key.offset <= last < key.offset + extent["num_bytes"]:
                    return
                logical = extent["disk_bytenr"] + extent["offset"] + last - key.offset
                finding = self.sector(tree_id, key.objectid, size, logical, inode["flags"])
                if finding is not None:
                    found.append(finding)

        return item, found

    def sector(self, tree_id: int, objectid: int, size: int, logical: int, flags: int):
        if logical in self.seen:
            return None
        self.seen.add(logical)
        self.census.files_checked += 1
        ss, tail = self.sectorsize, size % self.sectorsize
        try:
            copies = self.fs.chunk_map.copies(logical, ss)
        except MappingError as exc:
            self.census.problem(f"file slack: tree {tree_id} inode {objectid}: {exc}")
            return None
        for copy in copies:
            if copy.missing_device or copy.physical + ss > self.img.size:
                continue
            data = bytes(self.img.mmap[copy.physical : copy.physical + ss])
            if not any(data[tail:]):
                continue
            verdict = self.verdict(logical, data, tail, flags)
            return area_finding(
                "file_slack", copy.physical + tail, data[tail:],
                f"tree {tree_id} inode {objectid} (size {size}): last sector at logical "
                f"{logical}, mirror {copy.mirror} at {copy.physical}, bytes {tail}-{ss - 1}",
                "bytes past the end of the file in its last sector are not zero, and the kernel "
                "zeroes them before it writes the sector (extent_io.c:1857-1858); data checksum: "
                + verdict,
                tree=tree_id, inode=objectid, size=size, logical=logical, mirror=copy.mirror,
                csum=verdict.split(":")[0],
            )  # fmt: skip
        return None

    def verdict(self, logical: int, data: bytes, tail: int, flags: int) -> str:
        if flags & ondisk.INODE_NODATASUM:
            return "none (the inode has NODATASUM)"
        tree = self.csums
        if tree is None:
            return "unavailable (no csum tree)"
        found = tree.lookup(logical)
        if not found:
            return "none (the csum tree has no checksum for the sector)"
        csum_type = self.fs.reader.ctx.csum_type
        as_is = csum.compute(csum_type, data)
        zeroed = csum.compute(csum_type, data[:tail] + bytes(len(data) - tail))
        if any(as_is[: len(s)] == s for s in found):
            return ("covers_hidden: the stored checksum matches the sector with these bytes, so "
                    "it was recomputed after they were written")  # fmt: skip
        if any(zeroed[: len(s)] == s for s in found):
            return ("matches_zeroed: the stored checksum matches only with these bytes zeroed, as "
                    "the kernel wrote the sector (plan.md M6a, tail_rewritten)")  # fmt: skip
        return "mismatch: the stored checksum matches neither"


def _odd(name: str) -> list[str]:
    """Why a name is odd in a listing: characters that show as nothing or as something else."""
    reasons = []
    if any(0xDC80 <= ord(ch) <= 0xDCFF for ch in name):
        reasons.append("bytes that are not UTF-8")
    odd = sorted(
        {
            f"U+{ord(ch):04X} {unicodedata.category(ch)}"
            for ch in name
            if unicodedata.category(ch) in ODD_CATEGORIES and not 0xDC80 <= ord(ch) <= 0xDCFF
        }
    )
    if odd:
        reasons.append("invisible or control characters " + ", ".join(odd))
    if name and not name.strip():
        reasons.append("only whitespace")
    return reasons


def _odd_entries(tree_id: int, item, physical: int) -> list:
    try:
        parsed = items.dir_items(item.data)
    except items.ItemError:
        return []
    return [
        _Entry(tree_id, item.key.objectid, entry["name"],
               (entry["location"].objectid, entry["location"].type), entry["type"],
               physical + HEADER + item.offset, tuple(reasons))
        for entry in parsed if (reasons := _odd(entry["name"]))
    ]  # fmt: skip


@dataclass(frozen=True)
class _Entry:
    tree_id: int
    parent: int  # the directory's inode number
    name: str
    location: tuple[int, int]  # (objectid, key type) the entry points to
    file_type: int
    physical: int  # the DIR_INDEX item's data in the chosen copy
    reasons: tuple[str, ...]


_KINDS = {ondisk.FT_DIR: "directory", ondisk.FT_REG_FILE: "file", ondisk.FT_SYMLINK: "symlink"}


def _name_findings(reader, root_set, directories: dict, entries: list, census: Census):
    """Directory entries whose name would not show as itself in a listing: a file, a directory,
    or a subvolume or snapshot (an entry that points to a ROOT_ITEM). The kernel accepts any name
    without '/' other than '.' and '..' (ioctl.c:1126-1135 for subvolumes and snapshots; the VFS
    the same for files), so such a name is legal; mkfs.btrfs and the kernel never make one, and a
    person does not type one by accident."""
    subvols, problems = subvolumes(reader, root_set)
    for problem in problems:
        census.problem(f"subvolumes: {problem}")
    by_id = {sv.id: sv for sv in subvols}
    census.subvolumes = len(subvols)

    def path(tree_id: int, ino: int, depth: int = 0) -> list[str]:
        parts, dirs, visited = [], directories.get(tree_id, {}), set()
        # The top directory refers to itself as '..'; a cycle of forged refs ends the same way.
        while ino in dirs and ino not in visited and dirs[ino][0] != ino:
            visited.add(ino)
            parent, name = dirs[ino]
            parts.append(name)
            ino = parent
        subvol = by_id.get(tree_id)
        prefix = []
        if subvol is not None and subvol.parent is not None and depth < 64:
            prefix = path(subvol.parent, subvol.dirid, depth + 1) + [subvol.name or "?"]
        return prefix + list(reversed(parts))

    found = []
    for entry in entries:
        parts = path(entry.tree_id, entry.parent) + [entry.name]
        shown = "/" + "/".join(p.encode("unicode_escape").decode("ascii") for p in parts)
        subvolume = entry.location[1] == K["ROOT_ITEM"]
        kind = "subvolume" if subvolume else _KINDS.get(entry.file_type, "entry")
        hidden_dirs = [part for part in parts[:-1] if part.startswith(".")]
        evidence = f"the name has {'; '.join(entry.reasons)}"
        if hidden_dirs:
            plural = "ies" if len(hidden_dirs) > 1 else "y"
            evidence += f"; it sits in hidden director{plural} {', '.join(hidden_dirs)}"
        raw = entry.name.encode("utf-8", "surrogateescape")
        hex_, text = preview(raw)
        found.append(
            Finding(
                "hidden_name",
                entry.physical,
                len(raw),
                len(raw),
                f"tree {entry.tree_id}, {kind} {shown} ({'subvolume' if subvolume else 'inode'} "
                f"{entry.location[0]}, in directory {entry.parent})",
                evidence,
                raw.hex(),
                text,
                {
                    "tree": entry.tree_id,
                    "kind": kind,
                    "path": shown,
                    "name_hex": raw.hex(),
                    "directory": entry.parent,
                    "target": entry.location[0],
                    "subvolume": entry.location[0] if subvolume else None,
                },
            )  # fmt: skip
        )
    return found


def tree_findings(img, fs, root_set: RootSet) -> tuple[list[Finding], dict, list[tuple]]:
    """Findings of the tree rules, the census, and this device's (start, length) device
    extents from the dev tree."""
    census = Census()
    ctx = fs.reader.ctx
    found, seen = [], set()
    try:
        csum_root = resolve_tree(fs.reader, root_set, "csum")
    except RootNotFound:
        csum_root = None
    csums = tree_from_image(fs.reader, csum_root, "current") if csum_root else None
    files = _Files(img, fs, csums, census)
    directories: dict[int, dict] = {}
    devid = ondisk.DEV_ITEM.unpack_from(fs.fields["dev_item"])["devid"]
    extents, entries = [], []
    for tree, visits in _trees(fs.reader, root_set, fs.fields, census):
        streams = is_subvolume_tree(tree.tree_id) and not tree.log
        on_item, file_findings = files.tree(tree.tree_id) if streams else (None, [])
        dirs = directories.setdefault(tree.tree_id, {}) if streams else None
        directory_inodes = set()
        for visit in visits:
            node = visit.node
            fresh = node.logical not in seen
            if fresh:
                seen.add(node.logical)
                census.blocks += 1
                found += _block_findings(img, node, ctx, census)
            if node.level:
                continue
            physical = node.copies[node.chosen].physical
            if fresh:
                found += _item_findings(node, physical, tree, census)
            for item in node.items:
                if on_item is not None:
                    on_item(item)
                key = item.key
                if dirs is not None and key.type == K["INODE_ITEM"] and item.size >= _INODE.size:
                    if stat.S_ISDIR(_INODE.unpack_from(item.data)["mode"]):
                        directory_inodes.add(key.objectid)
                elif (dirs is not None and key.type == K["INODE_REF"]
                        and key.objectid in directory_inodes):  # fmt: skip
                    try:
                        ref = items.inode_refs(item.data)[0]
                    except items.ItemError:
                        continue
                    dirs[key.objectid] = (key.offset, ref["name"])
                elif dirs is not None and key.type == K["DIR_INDEX"] and fresh:
                    entries += _odd_entries(tree.tree_id, item, physical)
                elif (tree.tree_id == ondisk.DEV_TREE_OBJECTID and fresh
                        and key.type == K["DEV_EXTENT"] and key.objectid == devid):  # fmt: skip
                    if item.size >= ondisk.DEV_EXTENT.size:
                        length = ondisk.DEV_EXTENT.unpack_from(item.data)["length"]
                        extents.append((key.offset, length))
        found += file_findings
    found += _name_findings(fs.reader, root_set, directories, entries, census)
    return found, census.summary(), extents
