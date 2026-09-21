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
import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from btrfska import __version__
from btrfska.catalog import db
from btrfska.catalog.schema import s64
from btrfska.recover.dbtree import (
    Root,
    RootNotCataloged,
    resolve_root,
    resolve_roots,
    tree_leaves,
)
from btrfska.recover.inodes import InodeRecord, collect, paths, safe_component
from btrfska.recover.output import PARTIAL, FileSink, OutputError, OutputTree
from btrfska.substrate import items, ondisk
from btrfska.substrate.extents import FileAssembly, stream_extent
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import NodeReader

SOURCE_KIND = "anchored_root"
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


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _signature(record: InodeRecord) -> str:
    """Identifies a file's content without reading it: i_size and every EXTENT_DATA item."""
    digest = hashlib.sha256()
    size = -1 if record.inode is None else record.inode["size"]
    digest.update(struct.pack("<q", size))
    for item, _ in record.extents:
        digest.update(struct.pack("<QI", item.key.offset, len(item.data)))
        digest.update(item.data)
    return digest.hexdigest()


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
        self.bytes_written = 0

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
    def _base(root: Root) -> tuple[bytes, bytes]:
        return root.source.replace(":", "_").encode(), f"tree_{root.tree_id}".encode()

    def start_root(self, root: Root) -> None:
        """The root's own directory, which exists even when the tree holds nothing."""
        base = self._base(root)
        self.used.update({base[:1], base})
        self.out.make_dir(base, None, None)

    # ---- one file -----------------------------------------------------------------------
    def _write(self, sink: FileSink, record: InodeRecord) -> tuple[list, list, list]:
        """Stream the file into `sink`: (extent reads with their SHA-256, missing, problems)."""
        size = None if record.inode is None else record.inode["size"]
        found = [(item, leaf.bytenr) for item, leaf in record.extents]
        assembly = FileAssembly(self.reader, found, size, no_holes=self.no_holes)
        reads, missing = [], []
        for extent, pieces in assembly:
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
        if size is None:
            problems.append("no INODE_ITEM: the file's size is unknown")
        elif sink.written != size:
            missing.append([sink.written, size - sink.written, "short"])
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

    # ---- one artifact -------------------------------------------------------------------
    def artifact(self, recovery_id: int, root: Root, record: InodeRecord, where, in_current):
        parts, attached = where
        kind, inode = record.kind, record.inode
        problems = list(record.problems)
        for name in record.names[:1]:
            _, changed = safe_component(name.name, record.objectid)
            if changed:
                problems.append(changed)
        row = {
            "recovery_id": recovery_id,
            "source_kind": SOURCE_KIND,
            "source": root.source,
            "state_id": root.state_id,
            "tree_id": s64(root.tree_id),
            "root_bytenr": s64(root.bytenr),
            "root_generation": s64(root.generation),
            "objectid": s64(record.objectid),
            "inode_generation": None if inode is None else s64(inode["generation"]),
            "inode_transid": None if inode is None else s64(inode["transid"]),
            "kind": kind,
            "attached": int(attached),
            "names": json.dumps(
                [
                    {
                        "parent": n.parent,
                        "name": _text(n.name),
                        "name_hex": n.name.hex(),
                        "index": n.index,
                        "extended": n.extended,
                    }
                    for n in record.names
                ]
            ),  # fmt: skip
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
            "in_current": in_current,
        }
        reads, missing, same = [], [], None
        mode = None if inode is None else inode["mode"]
        base = self._base(root)

        if kind == "dir":
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
        elif kind in ("file", "unknown") and (kind == "file" or record.extents):
            signature = row["extent_signature"] = _signature(record)
            same = (root.tree_id, record.objectid, row["inode_generation"], signature)
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
                    digest = sink.close(mode, _times(inode))
                    row["bytes_written"] = sink.written
                    self.bytes_written += sink.written
                    if missing or inode is None:
                        row["status"] = "partial"
                        parts = (*parts[:-1], parts[-1] + PARTIAL)
                    else:
                        self.out.promote(parts)
                        row["status"], row["sha256"] = "complete", digest
                    row["output_path"] = _text(b"/".join(parts))
        row["path"], row["path_raw"] = _text(b"/".join(where[0])), b"/".join(where[0])
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


def _current_inodes(conn: sqlite3.Connection, tree_id: int) -> set[tuple[int, int]] | None:
    """(objectid, creation generation) of every inode of the current tree; None if unknown."""
    try:
        current = resolve_root(conn, "current", tree_id)
    except RootNotCataloged:
        return None
    leaves, gaps = tree_leaves(conn, current)
    if gaps:
        return None
    return {
        (objectid, record.inode["generation"])
        for objectid, record in collect(conn, leaves).items()
        if record.inode is not None
    }


def recover_roots(
    conn: sqlite3.Connection,
    reader: NodeReader,
    out: OutputTree,
    recovery_id: int,
    roots: tuple[Root, ...],
    *,
    no_holes: bool,
    dedup: bool = True,
    note: Callable[[str], None] = lambda line: None,
):
    """Recover every root into `out`; the run (counts, bytes) and the gaps per root source."""
    run = _Run(conn, reader, out, note, no_holes=no_holes, dedup=dedup)
    current = {tree: _current_inodes(conn, tree) for tree in {root.tree_id for root in roots}}
    gaps = {}
    for root in roots:
        run.start_root(root)
        leaves, found = tree_leaves(conn, root)
        gaps[f"{root.source} tree {root.tree_id}"] = tuple(found)
        for line in found:
            note(f"gap: {root.source} tree {root.tree_id}: {line}")
        inodes = collect(conn, leaves)
        located = paths(inodes)
        for objectid in sorted(located):
            record = inodes[objectid]
            in_current = None
            if current[root.tree_id] is not None and record.inode is not None:
                present = (objectid, record.inode["generation"]) in current[root.tree_id]
                in_current = int(present)
            run.artifact(recovery_id, root, record, located[objectid], in_current)
        conn.commit()
    return run, gaps


def recover(
    image: str | os.PathLike[str],
    database: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    *,
    roots: tuple[str, ...] = ("current",),
    tree_id: int | None = ondisk.FS_TREE_OBJECTID,
    dedup: bool = True,
    rehash: bool = True,
    note: Callable[[str], None] = lambda line: None,
) -> Recovered:
    """Recover tree `tree_id` under each of `roots` into the new directory `output_dir`.

    `tree_id` None means every file tree each root names (the fs tree and all subvolumes).
    Raises RecoveryError, db.CatalogError, output.OutputError or dbtree.RootNotCataloged before
    anything is written. `note` receives report lines (refusals, gaps).
    """
    conn = db.open_for_recovery(database)
    try:
        scan = conn.execute(
            "SELECT image_size, image_sha256_before, unsupported_format FROM scan_runs"
        ).fetchone()
        resolved = tuple(
            root for spec in dict.fromkeys(roots) for root in resolve_roots(conn, spec, tree_id)
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
                           "dedup": dedup}  # fmt: skip
                recovery_id = conn.execute(
                    "INSERT INTO recovery_runs (tool_version, started_utc, image_path,"
                    " image_checked, output_dir, options) VALUES (?, ?, ?, ?, ?, ?)",
                    (__version__, _now(), os.fspath(image), int(rehash), os.fspath(output_dir),
                     json.dumps(options)),
                ).lastrowid  # fmt: skip
                run, gaps = recover_roots(
                    conn, fs.reader, out, recovery_id, resolved,
                    no_holes=no_holes, dedup=dedup, note=note,
                )  # fmt: skip
                summary = {
                    "artifacts": dict(run.counts),
                    "bytes_written": run.bytes_written,
                    "gaps": {source: list(lines) for source, lines in gaps.items()},
                }
                conn.execute(
                    "UPDATE recovery_runs SET finished_utc = ?, summary = ? WHERE recovery_id = ?",
                    (_now(), json.dumps(summary), recovery_id),
                )
                conn.commit()
        return Recovered(recovery_id, os.fspath(output_dir), rehash, resolved, gaps,
                         dict(run.counts), run.bytes_written)  # fmt: skip
    finally:
        conn.close()
