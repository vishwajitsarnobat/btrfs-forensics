"""Anchored recovery: the files of one tree as one cataloged root saw them (plan.md M4b).

`recover` takes an image, the evidence database built from it and a new output directory. For
every root asked for it walks the tree in the database (`dbtree`), assembles the inodes
(`inodes`), and writes each regular file one extent at a time (`substrate.extents.FileAssembly`
into `output.FileSink`), so memory does not grow with file size. The image is read through
`substrate/image.py` only; files are written through `recover/output.py` only; rows are appended
through `catalog/db.py` only.

A file is `complete` only when every byte of it was read. Anything less is written as
`NAME.partial` with holes where extents failed, and says which. A file with an encrypted extent
is refused: nothing is written, and the caller gets a report line. Symlinks and special files are
recorded, never created. Every artifact gets one `artifacts` row, one `provenance` row per item
it was built from, and one line of `manifest.jsonl`.
"""

import hashlib
import json
import os
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from btrfska import __version__
from btrfska.catalog import db
from btrfska.catalog.schema import s64
from btrfska.recover.dbtree import (
    Leaf,
    Root,
    RootNotCataloged,
    every_state,
    former_names,
    fragment_roots,
    orphan_leaves,
    resolve_roots,
    tree_leaves,
)
from btrfska.recover.graph import ancestors, confirmed_by_dir_index, continue_file, pointer_join
from btrfska.recover.inodes import (
    ORPHAN_ITEMS,
    ROOT_DIR,
    InodeRecord,
    collect,
    extent_signature,
    paths,
    safe_component,
)
from btrfska.recover.logs import base_inodes, base_root, log_roots, replay
from btrfska.recover.maps import Readers
from btrfska.recover.output import PARTIAL, FileSink, OutputError, OutputTree
from btrfska.substrate import items, ondisk
from btrfska.substrate.extents import FileAssembly, stream_extent
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import NodeReader

MAX_FRAGMENTS = 4096  # fragments read per recovery, newest first; more is reported
MAX_NOTED = 16  # findings of the extent reader copied into one artifact's problems
MAX_SYMLINK = 4096  # PATH_MAX: a longer target is not a symlink the kernel would have made


class RecoveryError(ValueError):
    """The recovery cannot start: wrong image for the database, unusable output, unknown root."""


@dataclass(frozen=True)
class Recovered:
    """What one run did, for the caller to report."""

    recovery_id: int
    output_dir: str
    image_checked: bool
    roots: tuple[Root, ...]
    gaps: dict[str, tuple[str, ...]]  # per "SOURCE tree ID": blocks the walk could not follow
    counts: dict[str, int]  # artifacts by status
    bytes_written: int
    orphan_leaves: int = 0  # file-tree leaves no cataloged state reaches, read one by one
    by_source: dict[tuple[str, str], int] | None = None  # (source kind, status) -> artifacts
    fragments: int = 0  # fragments read (`graph`), and how many there are
    fragments_found: int = 0


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _encrypted(record: InodeRecord) -> str | None:
    """The first encrypted extent of a file, as a report phrase; None when there is none."""
    for item, leaf in record.extents:
        try:
            extent = items.file_extent(item.data)
        except items.ItemError:
            continue  # reported when the extent is read
        if extent["encryption"]:
            return (
                f"encrypted extent (encryption {extent['encryption']}) at file offset "
                f"{item.key.offset}, leaf {leaf.bytenr} slot {item.slot}"
            )
    return None


def _times(inode: dict | None) -> tuple[int, int] | None:
    if inode is None:
        return None
    stamps = []
    for name in ("atime", "mtime"):
        sec, nsec = inode[f"{name}_sec"], inode[f"{name}_nsec"]
        if sec >= 1 << 62 or nsec >= 1_000_000_000:  # nothing a clock ever produced
            return None
        stamps.append(sec * 1_000_000_000 + nsec)
    return stamps[0], stamps[1]


class _Run:
    def __init__(self, conn, reader: NodeReader, out: OutputTree, note, *, no_holes, dedup):
        self.conn, self.reader, self.out, self.note = conn, reader, out, note
        self.no_holes, self.dedup = no_holes, dedup
        self.used: set[tuple[bytes, ...]] = set()
        self.first_copy: dict[tuple[int, int, int | None, str], int] = {}
        self.counts: Counter[str] = Counter()
        self.by_source: Counter[tuple[str, str]] = Counter()  # (source kind, status)
        self.bytes_written = 0
        self.last_objectid: int | None = None  # of the orphan leaf being read, else None
        self.uncommitted = False  # the root being read is no committed tree (orphan sources)
        self.lone_log_leaf = False  # a leaf of a log tree read on its own, without any base

    # ---- output names -------------------------------------------------------------------
    def _claim(self, parts: tuple[bytes, ...], objectid: int) -> tuple[bytes, ...]:
        """`parts`, or a sibling name when it, or its `.partial`, is already taken."""
        candidate, attempt = parts, 0
        while candidate in self.used or (*candidate[:-1], candidate[-1] + PARTIAL) in self.used:
            attempt += 1
            suffix = f"~inode{objectid}" + (f".{attempt}" if attempt > 1 else "")
            candidate = (*parts[:-1], parts[-1] + suffix.encode())
        self.used.add(candidate)
        self.used.add((*candidate[:-1], candidate[-1] + PARTIAL))
        return candidate

    @staticmethod
    def _base(root: Root) -> tuple[bytes, ...]:
        log = root.tree_id == ondisk.TREE_LOG_OBJECTID
        tree = b"tree_log" if log else f"tree_{root.tree_id}".encode()
        if root.kind == "log_tree":
            where = f"log_{root.bytenr}_gen{root.generation}".encode()
            return b"log_trees", f"subvol_{root.subvolume}".encode(), where
        if root.kind == "orphan_graph":
            return b"orphan_graph", tree, f"fragment_{root.bytenr}_gen{root.generation}".encode()
        if root.kind == "orphan_node":
            return b"orphan_nodes", tree, f"leaf_{root.bytenr}_gen{root.generation}".encode()
        return root.source.replace(":", "_").encode(), tree

    def start_root(self, root: Root) -> None:
        """The root's own directory, which exists even when the tree holds nothing."""
        base = self._base(root)
        self.used.update(base[:n] for n in range(1, len(base) + 1))
        if root.kind == "anchored_root":  # orphan sources get a directory only with a file
            self.out.make_dir(base, None, None)

    # ---- one file -----------------------------------------------------------------------
    def _write(self, sink: FileSink, record: InodeRecord) -> tuple[list, list, list]:
        """Stream the file into `sink`: (extent reads with their SHA-256, missing, problems)."""
        size = None if record.inode is None else record.inode["size"]
        found = [(item, leaf.bytenr) for item, leaf in record.extents]
        assembly = FileAssembly(self.reader, found, size, no_holes=self.no_holes)
        reads, missing = [], []
        # The last inode of an orphan leaf: its remaining extent items may be in the next leaf,
        # and with NO_HOLES a range without an item looks exactly like a hole.
        cut = record.objectid == self.last_objectid
        for extent, pieces in assembly:
            tail = size is not None and extent.file_offset + extent.length == size
            if cut and tail and extent.kind == "implicit_hole":
                missing.append([extent.file_offset, extent.length, "continues_elsewhere"])
            elif (record.log_only or self.lone_log_leaf) and extent.kind == "implicit_hole":
                # A fast fsync logs only what changed: without the base tree this range is not
                # a hole, it is unknown.
                missing.append([extent.file_offset, extent.length, "not_logged"])
            if extent.length == 0 and size is not None and extent.file_offset >= size:
                reads.append((extent, None))  # clipped away: it lies wholly past the end
                continue
            if extent.file_offset != sink.written:  # an overlap: FileAssembly reports it
                missing.append([extent.file_offset, extent.length, "overlap"])
                reads.append((extent, None))
                continue
            if extent.error_kind is not None:
                missing.append([extent.file_offset, extent.length, extent.error_kind])
                sink.zeros(extent.length)
                reads.append((extent, None))
                continue
            if pieces is None:
                sink.zeros(extent.length)
                reads.append((extent, None))
                continue
            digest = hashlib.sha256()
            for piece in pieces:
                sink.write(piece)
                digest.update(piece)
            reads.append((extent, digest.hexdigest()))
        problems = [*assembly.problems, *assembly.errors]
        transid = None if record.inode is None else record.inode["transid"]
        newest = max((e.generation or 0 for e, _ in reads), default=0)
        if transid is not None and newest > transid:
            # A committed tree never holds this: the INODE_ITEM is updated by the commit at the
            # latest. A leaf written within a transaction can: the data is already the new one,
            # size and times are still the old ones. What was written is neither version.
            missing.append([0, sink.written, "inode_item_older_than_extent"])
            problems.append(
                f"an extent of generation {newest} is newer than the INODE_ITEM (transid "
                f"{transid}): the leaf was written before the inode item was updated, so the "
                "size and times are those of the previous version"
            )
        beyond = [
            e for e, _ in reads if e.kind in ("inline", "regular")
            and any(p.startswith("clipped from") for p in e.problems)
        ]  # fmt: skip
        if self.uncommitted and beyond and not (transid is not None and newest > transid):
            # The same thing within one transaction: the generations agree, the sizes do not.
            # A commit never leaves data past the sector of the end of the file.
            missing.append([0, sink.written, "inode_item_older_than_extent"])
            problems.append(
                f"the extent at file offset {beyond[0].file_offset} reaches past the end of the "
                "file: in a block that was never committed, the INODE_ITEM is from an earlier "
                "moment of the transaction than the extent"
            )
        noted = list(dict.fromkeys(p for extent, _ in reads for p in extent.problems))
        problems += noted[:MAX_NOTED]
        if len(noted) > MAX_NOTED:
            problems.append(f"and {len(noted) - MAX_NOTED} more findings of the extent reader")
        if size is None:
            problems.append("no INODE_ITEM: the file's size is unknown")
        elif sink.written != size:
            missing.append(
                [sink.written, size - sink.written, "continues_elsewhere" if cut else "short"]
            )
        return reads, missing, problems

    def _symlink_target(self, record: InodeRecord) -> tuple[str | None, list[str]]:
        if len(record.extents) != 1:
            return None, [f"a symlink with {len(record.extents)} extents"]
        item, leaf = record.extents[0]
        extent, pieces = stream_extent(self.reader, item, leaf.bytenr)
        if pieces is None or extent.kind != "inline":
            return None, [f"symlink target not readable: {extent.kind} {extent.error_kind}"]
        target = b"".join(pieces)[:MAX_SYMLINK]
        return _text(target), []

    @staticmethod
    def _source_kind(root: Root, record: InodeRecord) -> str:
        if record.orphan_item and root.kind == "anchored_root":
            return "orphan_item"
        if root.kind == "log_tree":
            return "log_tree"
        # a lone leaf read with --graph: `orphan_graph` only for what a join contributed to
        return "orphan_graph" if root.kind != "anchored_root" and record.joins else root.kind

    # ---- one artifact -------------------------------------------------------------------
    def artifact(self, recovery_id: int, root: Root, record: InodeRecord, where):
        parts, attached = where
        kind, inode = record.kind, record.inode
        problems = list(record.problems)
        for name in record.names[:1]:
            _, changed = safe_component(name.name, record.objectid)
            if changed:
                problems.append(changed)
        names = [
            {"parent": n.parent, "name": _text(n.name), "name_hex": n.name.hex(),
             "index": n.index, "extended": n.extended}
            for n in record.names
        ]  # fmt: skip
        if record.orphan_item:
            parts, names = self._orphan_item(root, record, names, problems)
        row = {
            "recovery_id": recovery_id,
            # how the inode was reached: a lone leaf stays `orphan_node` even when it lists the
            # inode under ORPHAN_ITEM (the path and the problems still say so)
            "source_kind": self._source_kind(root, record),
            "source": root.source,
            "state_id": root.state_id,
            "tree_id": s64(root.tree_id if root.subvolume is None else root.subvolume),
            "root_bytenr": s64(root.bytenr),
            "root_generation": s64(root.generation),
            "objectid": s64(record.objectid),
            "inode_generation": None if inode is None else s64(inode["generation"]),
            "inode_transid": None if inode is None else s64(inode["transid"]),
            "kind": kind,
            "attached": int(attached),
            "names": json.dumps(names),
            "size": None if inode is None else s64(inode["size"]),
            "mode": None if inode is None else inode["mode"],
            "xattrs": json.dumps(
                [{"name": _text(name), "value_hex": value.hex()} for name, value in record.xattrs]
            ),
            "symlink_target": None,
            "status": "recorded",
            "bytes_written": 0,
            "sha256": None,
            "extent_signature": None,
            "duplicate_of": None,
            "output_path": None,
            "chunk_maps": "[]",
            "joined": json.dumps(record.joins),
        }
        reads, missing, same = [], [], None
        mode = None if inode is None else inode["mode"]
        base = self._base(root)

        if kind == "dir" and root.kind == "orphan_node":
            pass  # recorded: a directory inode in a lone leaf says nothing about its content
        elif kind == "dir":
            parts = self._claim((*base, *parts), record.objectid)
            try:
                self.out.make_dir(parts, mode, _times(inode))
                row["status"], row["output_path"] = "complete", _text(b"/".join(parts))
            except OutputError as exc:
                row["status"] = "failed"
                problems.append(str(exc))
        elif kind == "symlink":
            row["symlink_target"], found = self._symlink_target(record)
            problems += found
        elif record.exists_only:
            pass  # recorded: the log says that the inode exists, and nothing of its content
        elif kind in ("file", "unknown") and (kind == "file" or record.extents):
            signature = row["extent_signature"] = extent_signature(record)
            tree = root.tree_id if root.subvolume is None else root.subvolume
            same = (tree, record.objectid, row["inode_generation"], signature)
            refusal = _encrypted(record)
            if refusal:
                row["status"] = "refused_encrypted"
                problems.append(refusal)
                self.note(f"refused: inode {record.objectid} of {root.source}: {refusal}")
            elif self.dedup and same in self.first_copy:
                row["status"], row["duplicate_of"] = "duplicate", self.first_copy[same]
            else:
                parts = self._claim((*base, *parts), record.objectid)
                try:
                    sink = self.out.create(parts)
                except (OutputError, OSError) as exc:
                    row["status"] = "failed"
                    problems.append(f"cannot create the output file: {exc}")
                else:
                    reads, missing, found = self._write(sink, record)
                    problems += found
                    through = [e.chunk_map for e, _ in reads if e.chunk_map and not e.error_kind]
                    row["chunk_maps"] = json.dumps(list(dict.fromkeys(through)))
                    digest = sink.close(mode, _times(inode))
                    row["bytes_written"] = sink.written
                    self.bytes_written += sink.written
                    row["status"] = "partial" if missing or inode is None else "complete"
                    if row["status"] == "complete":
                        try:
                            self.out.promote(parts)
                            row["sha256"] = digest
                        except OSError as exc:  # the name is taken after all, or no hard links
                            row["status"] = "failed"
                            problems.append(f"read completely, but left as {PARTIAL!r}: {exc}")
                    if row["status"] != "complete":
                        parts = (*parts[:-1], parts[-1] + PARTIAL)
                    row["output_path"] = _text(b"/".join(parts))
        tree_path = parts[len(base) :] if row["output_path"] else where[0]
        if record.orphan_item and not row["output_path"]:
            tree_path = parts
        row["path"], row["path_raw"] = _text(b"/".join(tree_path)), b"/".join(tree_path)
        row["missing"], row["problems"] = json.dumps(missing), json.dumps(problems)

        columns = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        cursor = self.conn.execute(
            f"INSERT INTO artifacts ({columns}) VALUES ({marks})", tuple(row.values())
        )
        artifact_id = cursor.lastrowid
        if row["status"] == "complete" and same is not None:
            self.first_copy.setdefault(same, artifact_id)
        self.counts[row["status"]] += 1
        self.by_source[row["source_kind"], row["status"]] += 1
        self._provenance(artifact_id, record, reads)
        self.out.record(
            {k: v for k, v in row.items() if k != "path_raw"}
            | {
                "artifact_id": artifact_id,
                "tree_id": root.tree_id,
                "objectid": record.objectid,
                "root_bytenr": root.bytenr,
                "root_generation": root.generation,
                "names": json.loads(row["names"]),
                "xattrs": json.loads(row["xattrs"]),
                "missing": missing,
                "problems": problems,
                "inode": inode,
            }
        )

    def _orphan_item(self, root: Root, record: InodeRecord, names: list, problems: list):
        """Where an ORPHAN_ITEM inode is written, and its names with the former ones added."""
        inode = record.inode
        problems.append("the tree lists this inode under ORPHAN_ITEM: unlinked, not cleaned up")
        if inode is not None and inode["nlink"]:
            problems.append(f"listed under ORPHAN_ITEM although nlink is {inode['nlink']}")
        label = str(record.objectid).encode()
        if inode is not None and not record.names:
            seen = set()
            for parent, name, index, extended, generation in former_names(
                self.conn, root.tree_id, record.objectid, inode["generation"]
            ):
                if (parent, name) in seen:
                    continue
                seen.add((parent, name))
                names.append(
                    {"parent": parent, "name": _text(name), "name_hex": name.hex(), "index": index,
                     "extended": extended, "former": True, "leaf_generation": generation}
                )  # fmt: skip
                if len(seen) == 1:
                    label += b"_" + safe_component(name, record.objectid)[0]
        return (ORPHAN_ITEMS, label), names

    def _provenance(self, artifact_id: int, record: InodeRecord, reads: list) -> None:
        by_item = {(extent.leaf, extent.slot): (extent, digest) for extent, digest in reads}
        rows = []
        for seq, origin in enumerate(record.origins):
            leaf = origin.leaf
            extent, digest = by_item.get((leaf.bytenr, origin.slot), (None, None))
            if origin.role != "extent_data":
                extent = None
            rows.append(
                (
                    artifact_id, seq, origin.role, leaf.content_id, origin.slot, s64(leaf.bytenr),
                    s64(leaf.generation), leaf.physical, leaf.status,
                    None if extent is None else s64(extent.file_offset),
                    None if extent is None else extent.length,
                    digest,
                    None if extent is None else extent.error_kind,
                    None if extent is None else json.dumps(asdict(extent)),
                )
            )  # fmt: skip
        self.conn.executemany(
            "INSERT INTO provenance (artifact_id, seq, role, content_id, slot, bytenr, generation,"
            " physical, block_status, file_offset, length, extent_sha256, error_kind, read_record)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def _join_lone_leaf(conn, run: _Run, root: Root, leaf: Leaf, inodes: dict, sectorsize: int):
    """The joins of recover/graph.py for one lone leaf: the file its end cuts, and the names of
    directories it does not hold. Returns those names; joins and refusals go into the records."""
    last = inodes.get(run.last_objectid)
    if last is not None:
        joined, outcome = continue_file(conn, root.tree_id, leaf, last, sectorsize)
        if joined is not None:
            joined.joins.append(outcome)
            inodes[last.objectid] = joined
            run.last_objectid = None  # the file is whole: nothing continues elsewhere
        elif outcome is not None:
            last.problems.append(f"not joined with another leaf: {outcome}")
    named, joins, refused = ancestors(conn, root.tree_id, inodes)
    for record in inodes.values():
        current, seen, found = (record.names[0].parent if record.names else None), set(), []
        while current is not None and current != ROOT_DIR and current not in inodes:
            if current in seen or current not in named:
                if current in refused:
                    record.problems.append(f"no path: {refused[current]}")
                found = []  # the chain does not reach the root directory: nothing was gained
                break
            seen.add(current)
            for join in joins.get(current, ()):
                if len(seen) == 1:  # the file's own directory: does it list the file?
                    confirmed = confirmed_by_dir_index(
                        conn, root.tree_id, current, record.objectid, record.names[0].name
                    )
                    join = join | {"dir_index_names_this_file": confirmed}
                found.append(join)
            current = named[current].parent
        record.joins.extend(found)
    return named


def recover_roots(
    conn: sqlite3.Connection,
    readers: Readers | NodeReader,
    out: OutputTree,
    recovery_id: int,
    roots: tuple[Root, ...],
    *,
    no_holes: bool,
    dedup: bool = True,
    orphans: tuple[tuple[Root, Leaf], ...] = (),
    fragments: tuple[Root, ...] = (),
    graph: bool = False,
    logs: tuple[Root, ...] = (),
    note: Callable[[str], None] = lambda line: None,
):
    """Recover every root, then every orphan leaf, into `out`: the run (counts, bytes) and the
    gaps per root. Anchored roots come first, so that an orphan leaf's copy of a file a root
    also gives is recognised as the duplicate. `readers` chooses the chunk maps per root
    (recover/maps.py); a plain NodeReader reads every root through its one map."""
    if isinstance(readers, NodeReader):
        readers = Readers(conn, readers, own=False)
    run = _Run(conn, readers.current, out, note, no_holes=no_holes, dedup=dedup)
    gaps = {}
    sectorsize = readers.current.ctx.sectorsize
    covered: set[int] = set()  # leaves read under a fragment are not read again on their own
    for root, leaf in (*((root, None) for root in (*roots, *fragments, *logs)), *orphans):
        if leaf is not None and leaf.content_id in covered:
            continue
        run.start_root(root)
        run.reader = readers.reader(root)
        run.uncommitted = root.kind != "anchored_root"
        run.lone_log_leaf = leaf is not None and root.tree_id == ondisk.TREE_LOG_OBJECTID
        named: dict = {}
        if leaf is None:
            leaves, found = tree_leaves(conn, root)
            gaps[f"{root.source} tree {root.tree_id}"] = tuple(found)
            for line in found:
                note(f"gap: {root.source} tree {root.tree_id}: {line}")
        else:
            leaves = [leaf]
        inodes = collect(conn, leaves)
        run.last_objectid = max(inodes, default=None) if leaf is not None else None
        if root.kind == "log_tree":
            covered.update(found_leaf.content_id for found_leaf in leaves)
            below = base_root(conn, root)
            base, base_gaps = (None, []) if below is None else base_inodes(conn, below)
            inodes, named = replay(inodes, base, below, root, sectorsize, len(base_gaps))
        elif root.kind == "orphan_graph":
            covered.update(found_leaf.content_id for found_leaf in leaves)
            join = pointer_join(root.bytenr, root.generation, root.level, len(leaves),
                                len(gaps[f"{root.source} tree {root.tree_id}"]))  # fmt: skip
            for record in inodes.values():
                record.joins.append(join)
        elif graph and leaf is not None:
            named = _join_lone_leaf(conn, run, root, leaf, inodes, sectorsize)
        located = paths(inodes, named)
        for objectid in sorted(located):
            run.artifact(recovery_id, root, inodes[objectid], located[objectid])
        conn.commit()
    return run, gaps


def resolve_all(
    conn: sqlite3.Connection, roots: tuple[str, ...], tree_id: int | None, note
) -> tuple[Root, ...]:
    """The trees to read under `roots`, where `all` stands for every cataloged state. A state
    that `all` brought in and that does not name the wanted tree is skipped with a note (an old
    root tree from before the subvolume existed, or one whose leaf naming it is lost); a root
    the user named must have it."""
    specs = list(dict.fromkeys(roots))
    brought_in: set[str] = set()
    if "all" in specs:
        at = specs.index("all")
        states = every_state(conn)
        brought_in = {s for s in states if s not in specs}
        specs[at : at + 1] = [s for s in states if s in brought_in]
    resolved: list[Root] = []
    for spec in specs:
        try:
            resolved += resolve_roots(conn, spec, tree_id)
        except RootNotCataloged as exc:
            if spec not in brought_in:
                raise
            note(f"skipped: {exc}")
    return tuple(resolved)


def recover(
    image: str | os.PathLike[str],
    database: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    *,
    roots: tuple[str, ...] = ("current",),
    tree_id: int | None = ondisk.FS_TREE_OBJECTID,
    dedup: bool = True,
    orphans: bool = False,
    graph: bool = False,
    logs: bool = False,
    maps: str = "own",
    rehash: bool = True,
    note: Callable[[str], None] = lambda line: None,
) -> Recovered:
    """Recover tree `tree_id` under each of `roots` into the new directory `output_dir`.

    `tree_id` None means every file tree each root names (the fs tree and all subvolumes). A root
    `all` stands for every cataloged state. `orphans` adds, after the roots, every file-tree leaf
    that no cataloged state reaches, each read on its own. `graph` reads them joined where a join
    is justified (recover/graph.py): fragments first, then the leaves under none. `logs` reads
    every log tree through the log root that names it, replayed over its base state
    (recover/logs.py). `maps` is `own`
    (file data is read through the chunk map of each root's own time, recover/maps.py) or
    `current` (the current chunk map only).
    Raises RecoveryError, db.CatalogError, output.OutputError or dbtree.RootNotCataloged before
    anything is written. `note` receives report lines (refusals, gaps).
    """
    conn = db.open_for_recovery(database)
    try:
        scan = conn.execute(
            "SELECT image_size, image_sha256_before, unsupported_format FROM scan_runs"
        ).fetchone()
        resolved = resolve_all(conn, tuple(roots), tree_id, note)
        total_fragments, tops = fragment_roots(conn, MAX_FRAGMENTS) if graph else (0, [])
        tops = tuple(root for root in tops if tree_id in (None, root.tree_id))
        log_trees = tuple(
            root for root in (log_roots(conn) if logs else ()) if tree_id in (None, root.subvolume)
        )
        lone = tuple(
            (root, leaf)
            for root, leaf in (orphan_leaves(conn) if orphans or graph else ())
            # a log leaf does not say which subvolume it logged, so it goes with any --tree
            if tree_id in (None, root.tree_id) or root.tree_id == ondisk.TREE_LOG_OBJECTID
        )
        with open_image(image) as img:
            if img.size != scan["image_size"]:
                raise RecoveryError(
                    f"{image} has {img.size} bytes; the database was built from an image of "
                    f"{scan['image_size']}"
                )
            if rehash and img.sha256() != scan["image_sha256_before"]:
                raise RecoveryError(f"{image} is not the image the database was built from")
            fs = open_filesystem(img, allow_unsupported=bool(scan["unsupported_format"]))
            no_holes = bool(fs.fields["incompat_flags"] & ondisk.INCOMPAT["NO_HOLES"])
            with OutputTree(output_dir) as out:
                options = {"roots": list(dict.fromkeys(roots)), "tree_id": tree_id or "all",
                           "dedup": dedup, "orphans": orphans, "graph": graph, "logs": logs,
                           "maps": maps}  # fmt: skip
                recovery_id = conn.execute(
                    "INSERT INTO recovery_runs (tool_version, started_utc, image_path,"
                    " image_checked, output_dir, options) VALUES (?, ?, ?, ?, ?, ?)",
                    (__version__, _now(), os.fspath(image), int(rehash), os.fspath(output_dir),
                     json.dumps(options)),
                ).lastrowid  # fmt: skip
                run, gaps = recover_roots(
                    conn, Readers(conn, fs.reader, own=maps == "own"), out, recovery_id, resolved,
                    no_holes=no_holes, dedup=dedup, orphans=lone, fragments=tops, graph=graph,
                    logs=log_trees, note=note,
                )  # fmt: skip
                if total_fragments > MAX_FRAGMENTS:
                    note(f"{total_fragments} fragments, only the newest {MAX_FRAGMENTS} read")
                summary = {
                    "artifacts": dict(run.counts),
                    "by_source": {
                        f"{kind} {status}": n for (kind, status), n in run.by_source.items()
                    },
                    "orphan_leaves": len(lone),
                    "fragments": len(tops),
                    "fragments_found": total_fragments,
                    "log_trees": len(log_trees),
                    "bytes_written": run.bytes_written,
                    "gaps": {source: list(lines) for source, lines in gaps.items()},
                }
                conn.execute(
                    "UPDATE recovery_runs SET finished_utc = ?, summary = ? WHERE recovery_id = ?",
                    (_now(), json.dumps(summary), recovery_id),
                )
                conn.commit()
        return Recovered(recovery_id, os.fspath(output_dir), rehash, resolved, gaps,
                         dict(run.counts), run.bytes_written, len(lone),
                         dict(run.by_source), len(tops), total_fragments)  # fmt: skip
    finally:
        conn.close()
