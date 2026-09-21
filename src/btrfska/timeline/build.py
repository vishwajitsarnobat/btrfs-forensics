"""Per-inode lifecycle timelines from the evidence database (plan.md M5d, claim C3).

Every cataloged state (the current root, the backup roots, the roots only the scan found) names
file trees; each is walked in the database, as recovery walks it, and every inode gives an
*observation*. Consecutive equal observations of one identity collapse into a *version*; events
are the differences between consecutive versions, plus `create` for the first and `delete` when
a later state of the same tree, walked without a gap, no longer holds the identity.

Identity is (tree, inode number, creation generation). btrfs reuses inode numbers, so the number
alone joins different files (`sandbox.img` inode 257 is two).

Generations order everything and are as trustworthy as the checksummed blocks they come from.
Wall-clock times are copied from the inode items and are data a user can set. Content deltas
compare extent items (address, offset, length, compression, inline bytes); no file data is read.

With `uncommitted`, fragments, lone leaves and dropped log leaves (recover/graph.py's sources)
add observations. They sort before the committed state of their generation, are marked, and
never produce a `delete`: absence from a block that was never a state proves nothing.
"""

import hashlib
import json
import sqlite3
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from btrfska.catalog.schema import s64, u64
from btrfska.recover.dbtree import (
    Root,
    fragment_roots,
    orphan_leaves,
    resolve_roots,
    tree_leaves,
)
from btrfska.recover.inodes import ROOT_DIR, InodeRecord, collect, paths
from btrfska.substrate import items, ondisk

MAX_FRAGMENTS = 4096
SECTOR = 4096  # the smallest sector size: a larger one only makes the past-the-end test stricter
_ATTRS = ("mode", "uid", "gid")


@dataclass(frozen=True)
class Seen:
    """Where an observation was made."""

    source: str  # current, backup:GEN, state:ID, fragment:BYTENR@GEN or orphan_node:BYTENR
    generation: int  # of the state's root tree, or of the block for an uncommitted source
    committed: bool

    @property
    def order(self) -> tuple[int, int]:
        return self.generation, int(self.committed)


@dataclass(frozen=True)
class Observation:
    tree_id: int
    objectid: int
    created: int  # the INODE_ITEM's generation: the transaction that created the inode
    transid: int
    kind: str
    size: int
    attrs: tuple[int, int, int]  # mode, uid, gid
    nlink: int
    names: tuple[tuple[int, bytes], ...]  # (parent, name), sorted
    path: str
    attached: bool
    # (file offset, length, what lies there, offset into it; None for a hole), in file order
    extents: tuple[tuple, ...]
    signature: str  # recover's extent signature: equal signatures mean equal content
    times: dict  # otime, mtime, ctime as [sec, nsec]
    inconsistent: bool  # an extent is newer than the INODE_ITEM (EXP-008): no version of the file
    past_end: bool  # data reaches past the sector of the end of the file (the same, uncommitted)

    def same_version(self, other: Observation) -> bool:
        mine = (self.transid, self.size, self.attrs, self.nlink, self.names, self.signature)
        return mine == (other.transid, other.size, other.attrs, other.nlink, other.names,
                        other.signature)  # fmt: skip


@dataclass
class Version:
    observation: Observation
    seen: list[Seen] = field(default_factory=list)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _signature(record: InodeRecord) -> str:
    """As recover/engine.py computes `artifacts.extent_signature`."""
    digest = hashlib.sha256()
    digest.update(struct.pack("<q", -1 if record.inode is None else record.inode["size"]))
    for item, _ in record.extents:
        digest.update(struct.pack("<QI", item.key.offset, len(item.data)))
        digest.update(item.data)
    return digest.hexdigest()


def _extents(record: InodeRecord) -> tuple[tuple[tuple, ...], int]:
    """((file offset, length, descriptor), ...) and the newest extent generation."""
    found, newest = [], 0
    for item, _ in record.extents:
        try:
            extent = items.file_extent(item.data)
        except items.ItemError:
            what = ("unparsable", hashlib.sha256(item.data).hexdigest())
            found.append((item.key.offset, 0, what, 0))
            continue
        newest = max(newest, extent["generation"])
        if extent["type"] == ondisk.FILE_EXTENT_INLINE:
            data = item.data[ondisk.FILE_EXTENT_INLINE_DATA_START :]
            what = ("inline", extent["compression"], hashlib.sha256(data).hexdigest())
            found.append((item.key.offset, extent["ram_bytes"], what, 0))
        elif extent["disk_bytenr"] == 0:
            found.append((item.key.offset, extent["num_bytes"], ("hole",), None))
        else:
            what = (items.EXTENT_TYPE_NAMES.get(extent["type"], "?"), extent["disk_bytenr"],
                    extent["compression"])  # fmt: skip
            found.append((item.key.offset, extent["num_bytes"], what, extent["offset"]))
    return tuple(found), newest


def _observe(tree_id: int, inodes: dict[int, InodeRecord]) -> Iterator[Observation]:
    located = paths(inodes)
    for objectid, record in inodes.items():
        inode = record.inode
        if inode is None:
            continue  # items without an INODE_ITEM have no identity
        extents, newest = _extents(record)
        parts, attached = located.get(objectid, ((), objectid == ROOT_DIR))
        yield Observation(
            tree_id=tree_id, objectid=objectid, created=inode["generation"],
            transid=inode["transid"], kind=record.kind, size=inode["size"],
            attrs=tuple(inode[name] for name in _ATTRS), nlink=inode["nlink"],
            names=tuple(sorted((n.parent, n.name) for n in record.names)),
            path=_text(b"/".join(parts)), attached=attached, extents=extents,
            signature=_signature(record),
            times={
                name: [inode[f"{name}_sec"], inode[f"{name}_nsec"]]
                for name in ("otime", "mtime", "ctime")
            },
            inconsistent=newest > inode["transid"],
            past_end=any(
                into is not None and what[0] != "prealloc"
                and offset + length > -(-inode["size"] // SECTOR) * SECTOR
                for offset, length, what, into in extents
            ),
        )  # fmt: skip


@dataclass
class _TreeAt:
    """One file tree as one source shows it."""

    seen: Seen
    complete: bool  # walked without a gap
    observations: dict[tuple[int, int], Observation]  # (objectid, created) -> observation


def _states(conn: sqlite3.Connection) -> list[tuple[int, int, str, bool]]:
    """(state id, generation, label, whether its whole root tree was found), oldest first."""
    rows = conn.execute(
        "SELECT state_id, generation, known_as, root_tree_missing FROM states"
    ).fetchall()
    found = []
    for state_id, generation, known_as, missing in rows:
        names = json.loads(known_as)
        label = "current" if "current" in names else (names[0] if names else f"state:{state_id}")
        found.append((state_id, u64(generation), label, not missing))
    return sorted(found, key=lambda row: (row[1], row[0]))


class Timeline:
    """The versions of every inode identity of the wanted trees, and the events between them."""

    def __init__(self, conn: sqlite3.Connection, *, tree_id: int | None = None,
                 uncommitted: bool = False) -> None:  # fmt: skip
        self.conn, self.tree_id = conn, tree_id
        self.trees: dict[int, list[_TreeAt]] = {}  # tree id -> what each source shows, in order
        self.gaps: list[str] = []
        self._walked: dict[tuple, tuple[bool, dict]] = {}
        for state_id, generation, label, _ in _states(conn):
            for root in resolve_roots(conn, f"state:{state_id}", None):
                if tree_id in (None, root.tree_id):
                    self._add(root, Seen(label, generation, True))
        if uncommitted:
            self._add_uncommitted()
        for shown in self.trees.values():
            shown.sort(key=lambda tree: tree.seen.order)

    def _add(self, root: Root, seen: Seen, tree_id: int | None = None) -> None:
        """Walk `root` and file what it shows under `tree_id` (the root's own tree, or for a log
        tree the subvolume it logged)."""
        tree_id = root.tree_id if tree_id is None else tree_id
        key = (tree_id, root.bytenr, root.generation, root.level)
        if key not in self._walked:
            leaves, gaps = tree_leaves(self.conn, root)
            self.gaps += [f"{seen.source} tree {tree_id}: {line}" for line in gaps]
            inodes = collect(self.conn, leaves)
            observations = {(o.objectid, o.created): o for o in _observe(tree_id, inodes)}
            self._walked[key] = (not gaps, observations)
        complete, observations = self._walked[key]
        self.trees.setdefault(tree_id, []).append(_TreeAt(seen, complete, observations))

    def _add_uncommitted(self) -> None:
        _, tops = fragment_roots(self.conn, MAX_FRAGMENTS)
        covered: set[int] = set()
        for root in tops:
            if self.tree_id in (None, root.tree_id):
                leaves, _ = tree_leaves(self.conn, root)
                covered.update(leaf.content_id for leaf in leaves)
                self._add(root, Seen(root.source, root.generation, False))
        for root, leaf in orphan_leaves(self.conn):
            if leaf.content_id in covered or root.tree_id == ondisk.TREE_LOG_OBJECTID:
                continue  # a log leaf alone does not say which subvolume it logged: see below
            if self.tree_id in (None, root.tree_id):
                self._add(root, Seen(root.source, root.generation, False))
        # Log trees, dropped or live: the ROOT_ITEMs of a log root tree (objectid -6, key offset =
        # the subvolume) name each subvolume's log tree. What a log holds was fsynced within a
        # transaction; the next commit drops the log.
        log = ondisk.TREE_LOG_OBJECTID
        rows = self.conn.execute(
            "SELECT DISTINCT r.key_offset, r.bytenr, r.generation, r.level FROM root_items r"
            " JOIN content_blocks b USING (content_id) WHERE r.tree_id = ? AND b.owner = ?",
            (s64(log), s64(log)),
        ).fetchall()
        for subvolume, bytenr, generation, level in rows:
            subvolume, bytenr, generation = u64(subvolume), u64(bytenr), u64(generation)
            if self.tree_id in (None, subvolume):
                source = f"log:{bytenr}@{generation}"
                root = Root(source, None, log, bytenr, generation, level, kind="orphan_graph")
                self._add(root, Seen(source, generation, False), subvolume)

    # ---- versions and events ---------------------------------------------------------------
    def versions(self, tree_id: int) -> dict[tuple[int, int], list[Version]]:
        found: dict[tuple[int, int], list[Version]] = {}
        for shown in self.trees.get(tree_id, ()):
            for identity, observation in shown.observations.items():
                history = found.setdefault(identity, [])
                if history and history[-1].observation.same_version(observation):
                    history[-1].seen.append(shown.seen)
                else:
                    history.append(Version(observation, [shown.seen]))
        return found

    def events(self, tree_id: int) -> Iterator[dict]:
        """Every event of one tree, by inode identity and then in order."""
        shown = self.trees.get(tree_id, [])
        committed = [tree for tree in shown if tree.seen.committed]
        by_number: dict[int, list[int]] = {}
        versions = self.versions(tree_id)
        for objectid, created in sorted(versions):
            by_number.setdefault(objectid, []).append(created)
        for (objectid, created), history in sorted(versions.items()):
            base = {"tree_id": tree_id, "objectid": objectid, "created": created}
            earlier = [c for c in by_number[objectid] if c < created]
            first = history[0]
            yield (
                base
                | _event("create", first, None)
                | {
                    "transaction": created,
                    "reused_inode_number": bool(earlier),
                    "previous_creation_generations": earlier,
                }
            )
            for before, after in zip(history, history[1:], strict=False):
                for kind, detail in _changes(before.observation, after.observation):
                    yield (
                        base
                        | _event(kind, after, before)
                        | detail
                        | {"transaction": after.observation.transid}
                    )
            yield from self._ending(base, history, committed, (objectid, created))

    def _ending(self, base: dict, history: list[Version], committed: list[_TreeAt], identity):
        sightings = [(s, v) for v in history for s in v.seen if s.committed]
        if not sightings:
            last = history[-1].seen[-1]
            yield (
                base
                | _event("never_committed", history[-1], None)
                | {
                    "transaction": None,
                    "generations": [last.generation - 1, last.generation],
                }
            )
            return
        final, last = max(sightings, key=lambda pair: pair[0].order)
        later = [tree for tree in committed if tree.seen.order > final.order]
        bounds = None
        for tree in later:
            if tree.complete:
                bounds = ("delete", tree.seen, {})
                break
        if bounds is None and later:
            reason = "every later walk of this tree has gaps: absence proves nothing"
            bounds = ("not_seen", later[0].seen, {"reason": reason})
        if bounds is not None:
            kind, after, extra = bounds
            yield (
                base
                | _event(kind, last, last)
                | extra
                | {
                    "transaction": None,
                    "between": [final.source, after.source],
                    "generations": [final.generation, after.generation],
                }
            )

    def subvolume_events(self) -> Iterator[dict]:
        """`subvolume_deleted` for a tree that a later state, whose whole root tree was found,
        no longer names."""
        states = _states(self.conn)
        for tree_id, shown in sorted(self.trees.items()):
            committed = [tree.seen for tree in shown if tree.seen.committed]
            if not committed:
                continue
            last = max(committed, key=lambda seen: seen.order)
            after = next((s for s in states if s[1] > last.generation and s[3]), None)
            if after is not None:
                yield {
                    "event": "subvolume_deleted", "tree_id": tree_id, "objectid": None,
                    "created": None, "transaction": None, "between": [last.source, after[2]],
                    "generations": [last.generation, after[1]],
                }  # fmt: skip


def _seen(version: Version) -> dict:
    return {
        "first_seen": {"source": version.seen[0].source, "generation": version.seen[0].generation},
        "last_seen": {"source": version.seen[-1].source, "generation": version.seen[-1].generation},
        "seen_in": len(version.seen),
        "uncommitted_only": not any(s.committed for s in version.seen),
    }


def _event(kind: str, version: Version, before: Version | None) -> dict:
    o = version.observation
    return {
        "event": kind,
        "path": o.path,
        "attached": o.attached,
        "kind": o.kind,
        "size": o.size,
        "transid": o.transid,
        "extent_signature": o.signature,
        "inconsistent": o.inconsistent or (o.past_end and _seen(version)["uncommitted_only"]),
        "times": o.times,
        "between": None if before is None or kind in ("delete", "not_seen") else [
            before.seen[-1].source, version.seen[0].source,
        ],
        "generations": None if before is None or kind in ("delete", "not_seen") else [
            before.seen[-1].generation, version.seen[0].generation,
        ],
    } | _seen(version)  # fmt: skip


def _changes(before: Observation, after: Observation) -> Iterator[tuple[str, dict]]:
    old, new = set(before.names), set(after.names)
    gone, come = sorted(old - new), sorted(new - old)
    if len(gone) == 1 and len(come) == 1:
        (old_parent, old_name), (new_parent, new_name) = gone[0], come[0]
        kind = "rename" if old_parent == new_parent else "move"
        yield (
            kind,
            {
                "from": {"parent": old_parent, "name": _text(old_name), "path": before.path},
                "to": {"parent": new_parent, "name": _text(new_name), "path": after.path},
            },
        )
    else:
        for parent, name in come:
            yield "link", {"name": {"parent": parent, "name": _text(name)}}
        for parent, name in gone:
            yield "unlink", {"name": {"parent": parent, "name": _text(name)}}
    # a directory's size follows its entries, whose own events say what changed
    changed = before.signature != after.signature and after.kind != "dir"
    if changed:
        yield "modify", {"size_before": before.size, "delta": delta(before.extents, after.extents)}
    if before.attrs != after.attrs:
        yield (
            "attr",
            {
                "before": dict(zip(_ATTRS, before.attrs, strict=True)),
                "after": dict(zip(_ATTRS, after.attrs, strict=True)),
            },
        )
    if before.names == after.names and not changed and before.attrs == after.attrs:
        yield "touch", {}  # the inode item changed and nothing above: times, link count, entries


def delta(before: tuple[tuple, ...], after: tuple[tuple, ...]) -> list[dict]:
    """The byte ranges whose extent differs, as added, removed or replaced; merged when
    adjacent and alike. Extents are compared by what they point at, not by reading data."""
    points = sorted({edge for offset, length, _, _ in (*before, *after)
                     for edge in (offset, offset + length)})  # fmt: skip

    def at(extents, position):
        """What the byte at `position` is: the extent and the offset into it."""
        for offset, length, what, into in extents:
            if offset <= position < offset + length:
                return what, None if into is None else into + position - offset
        return None

    found: list[dict] = []
    for start, end in zip(points, points[1:], strict=False):
        old, new = at(before, start), at(after, start)
        if old == new:
            continue
        change = "added" if old is None else "removed" if new is None else "replaced"
        if (
            found
            and found[-1]["change"] == change
            and found[-1]["offset"] + found[-1]["length"] == start
        ):
            found[-1]["length"] += end - start
        else:
            found.append({"offset": start, "length": end - start, "change": change})
    return found


def hashes(conn: sqlite3.Connection) -> dict[tuple, str]:
    """(tree, inode, creation generation, extent signature) -> SHA-256, from complete artifacts."""
    rows = conn.execute(
        "SELECT tree_id, objectid, inode_generation, extent_signature, sha256 FROM artifacts"
        " WHERE status = 'complete' AND sha256 IS NOT NULL AND extent_signature IS NOT NULL"
    )
    return {(u64(row[0]), u64(row[1]), u64(row[2]), row[3]): row[4] for row in rows}
