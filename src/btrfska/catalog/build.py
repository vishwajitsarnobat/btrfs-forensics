"""Build the evidence database of one image in one pass (plan.md M3, docs/evidence-db.md).

The image is opened read-only through `substrate/image.py` and scanned once. Each candidate the
scan kernel yields is classified, written to `nodes` and `node_checks`, and handed on to the block
index that old-root discovery works from, so classification, discovery and the database all come
from the same stream. `scan` and `roots` each scan the image on their own; this does not.

The database is created by `catalog/db.py`, which refuses an existing path. The image's SHA-256 is
taken before the pass and, unless `rehash` is off, again after it; both are recorded in `scan_runs`
as the chain of custody. A pass that fails leaves no database behind.
"""

import json
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime

from btrfska import __version__
from btrfska.catalog import db
from btrfska.catalog.content import ContentWriter
from btrfska.catalog.schema import SCHEMA_VERSION, s64
from btrfska.scan.classify import Classified, scan_image
from btrfska.scan.kernel_numpy import NodeRecord
from btrfska.scan.regions import Region
from btrfska.scan.roots import Discovery, discover, index_records, known_roots
from btrfska.substrate import csum, superblock
from btrfska.substrate.chunks import ChunkMap, type_name
from btrfska.substrate.fs import Filesystem, open_filesystem
from btrfska.substrate.image import open_image

BATCH = 2000  # node rows buffered between inserts


@dataclass(frozen=True)
class Built:
    """What one build wrote, for the caller to report."""

    path: str
    image_sha256: str
    image_unchanged: bool | None  # None: the image was not hashed again
    scan_summary: dict
    states: int
    root_tree_candidates: int
    rows: dict[str, int]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _jsonable(value):
    """Dataclasses (scan regions) inside a summary, as plain dicts."""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def _flag(value: bool | None) -> int | None:
    return None if value is None else int(value)


def _insert_run(conn: sqlite3.Connection, img, fs: Filesystem, sha: str, options: dict) -> None:
    fields = fs.fields
    conn.execute(
        "INSERT INTO scan_runs (run_id, schema_version, tool_version, started_utc, image_path,"
        " image_size, image_sha256_before, full_sweep, workers, gate_status, gate_unsupported,"
        " unsupported_format, fsid, tree_fsid, generation, nodesize, sectorsize, csum_type,"
        " csum_name, incompat_flags, compat_ro_flags)"
        " VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCHEMA_VERSION,
            __version__,
            _now(),
            os.fspath(img.path),
            img.size,
            sha,
            int(options["full_sweep"]),
            options["workers"],
            fs.verdict.status,
            json.dumps(list(fs.verdict.unsupported)),
            int(fs.unsupported_format),
            fields["fsid"].hex(),
            superblock.tree_fsid(fields).hex(),
            s64(fields["generation"]),
            fields["nodesize"],
            fields["sectorsize"],
            fields["csum_type"],
            csum.csum_name(fields["csum_type"]),
            s64(fields["incompat_flags"]),
            s64(fields["compat_ro_flags"]),
        ),
    )


def _insert_superblocks(conn: sqlite3.Connection, selection: superblock.Selection) -> None:
    foreign = {copy.mirror for copy in selection.foreign}
    chosen = selection.selected.mirror if selection.selected else None
    conn.executemany(
        "INSERT INTO superblocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                copy.mirror,
                copy.offset,
                int(copy.present),
                int(copy.valid),
                int(copy.mirror == chosen),
                int(copy.mirror in foreign),
                int(copy.magic_ok),
                int(copy.bytenr_ok),
                int(copy.csum_ok),
                int(copy.geometry_ok),
                s64(copy.fields["generation"]) if copy.present else None,
                copy.fields["fsid"].hex() if copy.present else None,
                json.dumps(list(copy.problems)),
            )
            for copy in selection.copies
        ],
    )
    _insert_problems(conn, "superblock", selection.disagreements)


def _insert_problems(conn: sqlite3.Connection, source: str, details) -> None:
    conn.executemany(
        "INSERT INTO problems (source, detail) VALUES (?, ?)", [(source, d) for d in details]
    )


def _insert_chunks(conn: sqlite3.Connection, chunk_map: ChunkMap) -> None:
    for accepted, chunks in ((1, chunk_map.chunks), (0, chunk_map.rejected)):
        for chunk in chunks:
            cursor = conn.execute(
                "INSERT INTO chunks (map_source, accepted, logical, length, type, type_name,"
                " num_stripes, sub_stripes, origin, problems)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    chunk_map.source,
                    accepted,
                    s64(chunk.logical),
                    s64(chunk.length),
                    s64(chunk.type),
                    type_name(chunk.type),
                    chunk.num_stripes,
                    chunk.sub_stripes,
                    chunk.origin,
                    json.dumps(list(chunk.problems)),
                ),
            )
            conn.executemany(
                "INSERT INTO stripes VALUES (?, ?, ?, ?, ?)",
                [
                    (cursor.lastrowid, i, s64(s.devid), s64(s.offset), s.dev_uuid.hex())
                    for i, s in enumerate(chunk.stripes)
                ],
            )
    _insert_problems(conn, "chunk_map", chunk_map.problems)


def _insert_regions(conn: sqlite3.Connection, scanned, skipped) -> dict[Region, int]:
    ids: dict[Region, int] = {}
    for flag, regions in ((1, scanned), (0, skipped)):
        for region in regions:
            cursor = conn.execute(
                "INSERT INTO regions (scanned, kind, start_offset, end_offset, chunk_logical,"
                " stripe_index) VALUES (?, ?, ?, ?, ?, ?)",
                (flag, region.kind, region.start, region.end, s64(region.chunk), region.stripe),
            )
            ids[region] = cursor.lastrowid
    return ids


class _NodeWriter:
    """Buffers `nodes` and `node_checks` rows; node ids are assigned here, in physical order."""

    def __init__(self, conn: sqlite3.Connection, regions: dict[Region, int]) -> None:
        self.conn, self.regions = conn, regions
        self.nodes: list[tuple] = []
        self.checks: list[tuple] = []
        self.count = 0

    def add(self, item: Classified, content_id: int | None) -> None:
        record = item.record
        self.count += 1
        self.nodes.append(
            (
                self.count,
                record.physical,
                self.regions[record.region],
                s64(record.bytenr),
                s64(record.generation),
                s64(record.owner),
                record.level,
                record.nritems,
                int(record.valid),
                item.status,
                int(item.orphan),
                int(item.outside_map),
                int(item.legacy_orphan),
                int(item.log_tree),
                int(record.bytenr_mapped),
                int(record.maps_here),
                json.dumps(list(record.problems)),
                content_id,
            )
        )
        self.checks.extend((self.count, c.name, _flag(c.ok), c.detail) for c in record.checks)
        if len(self.nodes) >= BATCH:
            self.flush()

    def flush(self) -> None:
        self.conn.executemany(
            f"INSERT INTO nodes VALUES ({', '.join('?' * 18)})",
            self.nodes,
        )
        self.conn.executemany("INSERT INTO node_checks VALUES (?, ?, ?, ?)", self.checks)
        self.nodes.clear()
        self.checks.clear()


def _insert_discovery(conn: sqlite3.Connection, found: Discovery) -> None:
    conn.executemany(
        "INSERT INTO known_roots (source, tree, tree_id, bytenr, generation, level, indexed,"
        " candidate) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                r.root.source,
                r.root.tree,
                s64(r.root.tree_id),
                s64(r.root.bytenr),
                s64(r.root.generation),
                r.root.level,
                int(r.indexed),
                int(r.candidate),
            )
            for r in found.rediscovered
        ],
    )
    for state in found.states:
        root = state.chunk_root
        cursor = conn.execute(
            "INSERT INTO states (bytenr, generation, level, known_as, root_tree_blocks,"
            " root_tree_missing, found, referenced, completeness, missing, chunk_root_bytenr,"
            " chunk_root_generation, chunk_root_level, chunk_root_source, chunk_root_differs,"
            " maps_current, maps_historical, maps_neither, level_consistent, problems)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                s64(state.bytenr),
                s64(state.generation),
                state.level,
                json.dumps(list(state.known_as)),
                state.root_tree_blocks,
                state.root_tree_missing,
                state.found,
                state.referenced,
                state.completeness,
                json.dumps(state.missing, sort_keys=True),
                s64(root.bytenr) if root else None,
                s64(root.generation) if root else None,
                root.level if root else None,
                root.source if root else None,
                _flag(root.differs_from_current) if root else None,
                state.maps_current,
                state.maps_historical,
                state.maps_neither,
                int(state.level_consistent),
                json.dumps(list(state.problems)),
            ),
        )
        state_id = cursor.lastrowid
        conn.executemany(
            "INSERT INTO state_copies VALUES (?, ?)", [(state_id, p) for p in state.copies]
        )
        conn.executemany(
            "INSERT INTO state_trees VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    state_id,
                    position,
                    s64(t.tree_id),
                    s64(t.key_offset),
                    s64(t.bytenr),
                    s64(t.generation),
                    t.level,
                    s64(t.leaf),
                    t.slot,
                    t.status,
                    t.blocks,
                    t.missing,
                )
                for position, t in enumerate(state.trees)
            ],
        )
    conn.executemany(
        "INSERT INTO walk_failures (source, tree_id, bytenr, failure_class) VALUES (?, ?, ?, ?)",
        [(src, s64(tree), s64(bytenr), cls) for src, tree, bytenr, cls in found.walk_failures],
    )


TABLES = (
    "scan_runs", "superblocks", "problems", "chunks", "stripes", "regions", "nodes",
    "node_checks", "known_roots", "states", "state_copies", "state_trees", "walk_failures",
    "contents", "items", "item_problems", "key_ptrs", "inodes", "inode_refs", "dir_entries",
    "file_extents", "root_items", "extents", "extent_backrefs", "stale_items", "stale_key_ptrs",
)  # fmt: skip


def row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}


def build_catalog(
    image_path,
    db_path,
    *,
    full_sweep: bool = False,
    workers: int = 1,
    allow_unsupported: bool = False,
    rehash: bool = True,
) -> Built:
    """Scan `image_path` once and write its evidence database to `db_path` (which must not exist).

    Raises what `open_filesystem` raises (no valid superblock, refused format) before any file is
    created, and `db.CatalogError` for an unusable database path.
    """
    options = {"full_sweep": full_sweep, "workers": workers}
    with open_image(image_path) as img:
        before = img.sha256()
        fs = open_filesystem(img, allow_unsupported=allow_unsupported)
        conn = db.create(db_path)
        try:
            with conn:
                _insert_run(conn, img, fs, before, options)
                _insert_superblocks(conn, fs.selection)
                _insert_chunks(conn, fs.chunk_map)
                scan = scan_image(img, fs, full_sweep=full_sweep, workers=workers)
                _insert_problems(conn, "scan_plan", scan.plan.problems)
                _insert_problems(conn, "walk", scan.reach.problems)
                writer = _NodeWriter(
                    conn, _insert_regions(conn, scan.plan.regions, scan.plan.skipped)
                )

                ctx = fs.reader.ctx
                contents = ContentWriter(conn, ctx.nodesize, ctx.sectorsize)

                def written() -> Iterator[NodeRecord]:
                    for item in scan.classified:
                        record, content_id = item.record, None
                        if record.checks:  # the whole block lies inside the image
                            block = img.mmap[record.physical : record.physical + ctx.nodesize]
                            content_id = contents.add(block, record.valid)
                        writer.add(item, content_id)
                        yield record

                index = index_records(written(), ctx)
                contents.flush()
                writer.flush()
                found = discover(
                    img, index, ctx=ctx, chunk_map=fs.chunk_map, known=known_roots(fs.fields),
                    log_live=scan.reach.log_logical, walk_failures=scan.reach.walk_failures,
                )  # fmt: skip
                _insert_discovery(conn, found)
                after = img.sha256() if rehash else None
                conn.execute(
                    "UPDATE scan_runs"
                    " SET finished_utc = ?, image_sha256_after = ?, scan_summary = ?",
                    (_now(), after, json.dumps(scan.summary, sort_keys=True, default=_jsonable)),
                )
            rows = row_counts(conn)
        except BaseException:
            conn.close()
            db.discard(db_path)
            raise
        conn.close()
    return Built(
        path=os.fspath(db_path),
        image_sha256=before,
        image_unchanged=None if after is None else after == before,
        scan_summary=scan.summary,
        states=len(found.states),
        root_tree_candidates=found.root_tree_candidates,
        rows=rows,
    )
