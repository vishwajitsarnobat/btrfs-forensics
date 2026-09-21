"""Log trees in recovery (plan.md M5e-1): which subvolume a log tree logged, and a read-only
replay of it over the state it was written against.

A log root tree (owner -6) holds one ROOT_ITEM per logged subvolume: key objectid -6, key offset
the subvolume's id, naming that subvolume's log tree (tree-log.c). What a log tree holds was
fsynced within a transaction; the next commit drops the log, and a crash leaves the superblock's
`log_root` pointing at it for the next mount to replay.

Replay follows the kernel (tree-log.c replay_one_extent, replay_one_buffer): a logged extent
replaces whatever the base tree holds in its range, a base extent that is only partly covered
keeps its other part, the logged INODE_ITEM gives the size, and nothing past the sector of the
new end is kept. A fast fsync logs only what changed, so **in a log tree a range without an
extent item is not a hole**: without a base it is not known.
"""

import json
import sqlite3
import struct
from dataclasses import replace

from btrfska.catalog.schema import s64, u64
from btrfska.recover.dbtree import Root, RootNotCataloged, resolve_roots
from btrfska.recover.inodes import InodeRecord, Name
from btrfska.substrate import items, ondisk
from btrfska.substrate.node import Item, Key

LOG = ondisk.TREE_LOG_OBJECTID
K = ondisk.ITEM_KEYS
_NUM_BYTES = ondisk.FILE_EXTENT_ITEM.offset("num_bytes")
_OFFSET = ondisk.FILE_EXTENT_ITEM.offset("offset")


def log_roots(conn: sqlite3.Connection) -> list[Root]:
    """Every subvolume log tree that a scanned log root tree names, newest first."""
    rows = conn.execute(
        "SELECT DISTINCT r.key_offset, r.bytenr, r.generation, r.level, b.bytenr FROM root_items r"
        " JOIN content_blocks b USING (content_id) WHERE r.tree_id = ? AND b.owner = ?"
        " ORDER BY r.generation DESC, r.bytenr",
        (s64(LOG), s64(LOG)),
    ).fetchall()
    return [
        Root(f"log:{u64(bytenr)}@{u64(generation)}", None, LOG, u64(bytenr), u64(generation),
             level, kind="log_tree", subvolume=u64(subvolume), named_by=u64(leaf))
        for subvolume, bytenr, generation, level, leaf in rows
    ]  # fmt: skip


def base_root(conn: sqlite3.Connection, log: Root) -> Root | None:
    """The subvolume's tree in the newest cataloged state older than the log."""
    states = conn.execute(
        "SELECT state_id, known_as FROM states WHERE generation < ?"
        " ORDER BY generation DESC, state_id",
        (s64(log.generation),),
    ).fetchall()
    for state_id, known_as in states:
        try:
            found = resolve_roots(conn, f"state:{state_id}", log.subvolume)[0]
        except RootNotCataloged:
            continue
        names = json.loads(known_as)  # name the state as the superblock does, when it does
        label = "current" if "current" in names else (names[0] if names else found.source)
        return replace(found, source=label)
    return None


def _piece(item: Item, leaf, start: int, end: int):
    """The part [start, end) of a regular or prealloc base extent, as an item of its own."""
    shift = start - item.key.offset
    data = bytearray(item.data)
    (old_offset,) = struct.unpack_from("<Q", data, _OFFSET)
    struct.pack_into("<Q", data, _OFFSET, old_offset + shift)
    struct.pack_into("<Q", data, _NUM_BYTES, end - start)
    key = Key(item.key.objectid, item.key.type, start)
    return replace(item, key=key, data=bytes(data)), leaf


def overlay(base: list, logged: list, size: int, sectorsize: int) -> tuple[list, list[str]]:
    """Base extents with the logged ones laid over them, as (item, leaf) in file order."""
    problems: list[str] = []
    limit = -(-size // sectorsize) * sectorsize
    covered = []
    for item, _ in logged:
        try:
            extent = items.file_extent(item.data)
        except items.ItemError:
            continue  # the extent reader reports it
        inline = extent["type"] == ondisk.FILE_EXTENT_INLINE
        length = extent["ram_bytes"] if inline else extent["num_bytes"]
        covered.append((item.key.offset, item.key.offset + length))
    kept = []
    for item, leaf in base:
        try:
            extent = items.file_extent(item.data)
        except items.ItemError:
            problems.append(f"base extent at {item.key.offset} does not parse: left out")
            continue
        if extent["type"] == ondisk.FILE_EXTENT_INLINE:
            if not covered and item.key.offset < limit:
                kept.append((item, leaf))
            continue  # a logged extent replaces an inline file as a whole
        parts = [(item.key.offset, min(item.key.offset + extent["num_bytes"], limit))]
        parts = [part for part in parts if part[0] < part[1]]  # nothing of it lies before the end
        for start, end in covered:
            parts = [
                piece
                for low, high in parts
                for piece in ((low, min(high, start)), (max(low, end), high))
                if piece[0] < piece[1]
            ]
        for low, high in parts:
            whole = (low, high) == (item.key.offset, item.key.offset + extent["num_bytes"])
            kept.append((item, leaf) if whole else _piece(item, leaf, low, high))
    merged = kept + [pair for pair in logged if pair[0].key.offset < max(limit, 1)]
    return sorted(merged, key=lambda pair: pair[0].key.offset), problems


def replay(
    logged: dict[int, InodeRecord], base: dict[int, InodeRecord] | None, base_root_: Root | None,
    log: Root, sectorsize: int,
) -> tuple[dict[int, InodeRecord], dict[int, Name]]:  # fmt: skip
    """The log's inodes as they would be after a replay, and the names of the base tree's
    directories for their paths. Every record says in `joins` what it rests on."""
    attribution = {
        "kind": "log_root",
        "subvolume": log.subvolume,
        "log_root_leaf": log.named_by,
        "evidence": f"a ROOT_ITEM of a log root tree (key objectid -6, offset {log.subvolume}) "
        f"in leaf {log.named_by} names this log tree; the key offset is the subvolume it logged",
    }
    found: dict[int, InodeRecord] = {}
    for objectid, record in logged.items():
        record.joins.append(attribution)
        inode = record.inode
        if inode is None:
            found[objectid] = record
            continue
        if inode["generation"] == 0:
            record.problems.append(
                "logged with generation 0: the kernel's exists-only mode, which carries names "
                "and no content"
            )
            record.extents, record.exists_only = [], True
            found[objectid] = record
            continue
        old = None if base is None else base.get(objectid)
        if old is not None and (
            old.inode is None or old.inode["generation"] != inode["generation"]
        ):
            old = None  # the number was reused: another file
        if old is None:
            record.log_only = True
            found[objectid] = record
            continue
        extents, problems = overlay(old.extents, record.extents, inode["size"], sectorsize)
        record.extents = extents
        record.origins = [o for o in old.origins if o.role == "extent_data"] + record.origins
        record.problems += problems
        if not record.names:
            record.names = list(old.names)
        record.joins.append(
            {
                "kind": "log_replay",
                "base": base_root_.source,
                "base_state": base_root_.state_id,
                "base_root": base_root_.bytenr,
                "evidence": "the same inode number and creation generation in the subvolume's "
                f"tree of {base_root_.source}, the newest cataloged state older than the log; "
                "logged extents replace what the base holds in their range, the logged "
                "INODE_ITEM gives the size",
            }
        )
        found[objectid] = record
    names = {}
    for objectid, record in (base or {}).items():
        if objectid not in found and record.kind == "dir" and record.names:
            names[objectid] = record.names[0]
    return found, names


def describe(log: Root) -> str:
    return json.dumps({"log": log.source, "subvolume": log.subvolume})
