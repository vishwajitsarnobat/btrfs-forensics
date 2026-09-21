"""The evidence database schema (docs/evidence-db.md documents every table and column).

One database describes one pass over one image. `SCHEMA_VERSION` changes with any change to the
DDL below; the document lists what each version changed (plan.md M3).

Integers. SQLite integers are signed 64-bit, while btrfs objectids, offsets and generations are
u64. Every on-disk u64 is stored as its two's-complement signed value (`s64`): values of 2^63 and
above appear negative, which is how btrfs names the high objectids (-6 is the log tree). `u64`
converts back. Byte offsets into an image are always below 2^63 and are stored as they are.

Key order. Signed storage keeps a value but not its order: objectid -6 sorts before 0, while btrfs
sorts it last. Every key is therefore also stored as `key_sort`, the 17 bytes objectid
(big-endian), type, offset (big-endian). SQLite compares BLOBs bytewise, so `key_sort` orders keys
exactly as btrfs_comp_cpu_keys does; range and ordering queries use it.
"""

import struct

SCHEMA_VERSION = 4

# The tables a recovery appends to after the build (plan.md M4b). Every other table is written
# by the one pass of `catalog build` and never again; catalog/db.py enforces that.
RECOVERY_TABLES = ("recovery_runs", "artifacts", "provenance")

_U64 = 1 << 64
_S64_MAX = (1 << 63) - 1


def s64(value: int | None) -> int | None:
    """An on-disk u64 as the signed integer SQLite stores."""
    if value is None:
        return None
    if not 0 <= value < _U64:
        raise ValueError(f"{value} is not a u64")
    return value - _U64 if value > _S64_MAX else value


def u64(value: int | None) -> int | None:
    """The on-disk u64 a stored signed integer stands for."""
    if value is None:
        return None
    return value + _U64 if value < 0 else value


def key_sort(objectid: int, type_: int, offset: int) -> bytes:
    """A key as 17 bytes whose bytewise order is the btrfs key order."""
    return struct.pack(">QBQ", objectid, type_, offset)


def key_from_sort(blob: bytes) -> tuple[int, int, int]:
    return struct.unpack(">QBQ", blob)


DDL = """
CREATE TABLE scan_runs (
    run_id               INTEGER PRIMARY KEY CHECK (run_id = 1),
    schema_version       INTEGER NOT NULL,
    tool_version         TEXT    NOT NULL,
    started_utc          TEXT    NOT NULL,
    finished_utc         TEXT,
    image_path           TEXT    NOT NULL,
    image_size           INTEGER NOT NULL,
    image_sha256_before  TEXT    NOT NULL,
    image_sha256_after   TEXT,
    full_sweep           INTEGER NOT NULL,
    workers              INTEGER NOT NULL,
    gate_status          TEXT    NOT NULL,
    gate_unsupported     TEXT    NOT NULL,
    unsupported_format   INTEGER NOT NULL,
    fsid                 TEXT    NOT NULL,
    tree_fsid            TEXT    NOT NULL,
    generation           INTEGER NOT NULL,
    nodesize             INTEGER NOT NULL,
    sectorsize           INTEGER NOT NULL,
    csum_type            INTEGER NOT NULL,
    csum_name            TEXT    NOT NULL,
    incompat_flags       INTEGER NOT NULL,
    compat_ro_flags      INTEGER NOT NULL,
    scan_summary         TEXT
);

CREATE TABLE superblocks (
    mirror          INTEGER PRIMARY KEY,
    image_offset    INTEGER NOT NULL,
    present         INTEGER NOT NULL,
    valid           INTEGER NOT NULL,
    selected        INTEGER NOT NULL,
    foreign_fs      INTEGER NOT NULL,
    magic_ok        INTEGER NOT NULL,
    bytenr_ok       INTEGER NOT NULL,
    csum_ok         INTEGER NOT NULL,
    geometry_ok     INTEGER NOT NULL,
    generation      INTEGER,
    fsid            TEXT,
    problems        TEXT    NOT NULL
);

CREATE TABLE problems (
    problem_id  INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    detail      TEXT NOT NULL
);

CREATE TABLE chunks (
    chunk_id     INTEGER PRIMARY KEY,
    map_source   TEXT    NOT NULL,
    accepted     INTEGER NOT NULL,
    logical      INTEGER NOT NULL,
    length       INTEGER NOT NULL,
    type         INTEGER NOT NULL,
    type_name    TEXT    NOT NULL,
    num_stripes  INTEGER NOT NULL,
    sub_stripes  INTEGER NOT NULL,
    origin       TEXT    NOT NULL,
    problems     TEXT    NOT NULL
);

CREATE TABLE stripes (
    chunk_id      INTEGER NOT NULL REFERENCES chunks(chunk_id),
    stripe_index  INTEGER NOT NULL,
    devid         INTEGER NOT NULL,
    physical      INTEGER NOT NULL,
    dev_uuid      TEXT    NOT NULL,
    PRIMARY KEY (chunk_id, stripe_index)
);

CREATE TABLE regions (
    region_id      INTEGER PRIMARY KEY,
    scanned        INTEGER NOT NULL,
    kind           TEXT    NOT NULL,
    start_offset   INTEGER NOT NULL,
    end_offset     INTEGER NOT NULL,
    chunk_logical  INTEGER,
    stripe_index   INTEGER
);

CREATE TABLE contents (
    content_id  INTEGER PRIMARY KEY,
    sha256      TEXT    NOT NULL UNIQUE,
    level       INTEGER NOT NULL,
    nritems     INTEGER NOT NULL,
    parsed      INTEGER NOT NULL,
    first_key   BLOB,
    last_key    BLOB,
    slack_start    INTEGER,
    slack_len      INTEGER,
    slack_nonzero  INTEGER,
    slack_class    TEXT
);
CREATE INDEX contents_by_range ON contents (level, first_key, last_key);

CREATE TABLE nodes (
    node_id        INTEGER PRIMARY KEY,
    physical       INTEGER NOT NULL UNIQUE,
    region_id      INTEGER NOT NULL REFERENCES regions(region_id),
    bytenr         INTEGER,
    generation     INTEGER,
    owner          INTEGER,
    level          INTEGER,
    nritems        INTEGER,
    valid          INTEGER NOT NULL,
    status         TEXT    NOT NULL,
    orphan         INTEGER NOT NULL,
    outside_map    INTEGER NOT NULL,
    legacy_orphan  INTEGER NOT NULL,
    log_tree       INTEGER NOT NULL,
    bytenr_mapped  INTEGER NOT NULL,
    maps_here      INTEGER NOT NULL,
    problems       TEXT    NOT NULL,
    content_id     INTEGER REFERENCES contents(content_id)
);
CREATE INDEX nodes_by_block ON nodes (bytenr, generation);
CREATE INDEX nodes_by_content ON nodes (content_id);
CREATE INDEX nodes_by_owner ON nodes (owner, generation, level);

CREATE TABLE node_checks (
    node_id  INTEGER NOT NULL REFERENCES nodes(node_id),
    name     TEXT    NOT NULL,
    ok       INTEGER,
    detail   TEXT    NOT NULL,
    PRIMARY KEY (node_id, name)
);

CREATE TABLE known_roots (
    known_root_id  INTEGER PRIMARY KEY,
    source         TEXT    NOT NULL,
    tree           TEXT    NOT NULL,
    tree_id        INTEGER NOT NULL,
    bytenr         INTEGER NOT NULL,
    generation     INTEGER,
    level          INTEGER,
    indexed        INTEGER NOT NULL,
    candidate      INTEGER NOT NULL
);

CREATE TABLE states (
    state_id               INTEGER PRIMARY KEY,
    bytenr                 INTEGER NOT NULL,
    generation             INTEGER NOT NULL,
    level                  INTEGER NOT NULL,
    known_as               TEXT    NOT NULL,
    root_tree_blocks       INTEGER NOT NULL,
    root_tree_missing      INTEGER NOT NULL,
    found                  INTEGER NOT NULL,
    referenced             INTEGER NOT NULL,
    completeness           REAL    NOT NULL,
    missing                TEXT    NOT NULL,
    chunk_root_bytenr      INTEGER,
    chunk_root_generation  INTEGER,
    chunk_root_level       INTEGER,
    chunk_root_source      TEXT,
    chunk_root_differs     INTEGER,
    maps_current           INTEGER NOT NULL,
    maps_historical        INTEGER,
    maps_neither           INTEGER NOT NULL,
    level_consistent       INTEGER NOT NULL,
    problems               TEXT    NOT NULL
);

CREATE TABLE state_copies (
    state_id  INTEGER NOT NULL REFERENCES states(state_id),
    physical  INTEGER NOT NULL,
    PRIMARY KEY (state_id, physical)
);

CREATE TABLE state_trees (
    state_id    INTEGER NOT NULL REFERENCES states(state_id),
    position    INTEGER NOT NULL,
    tree_id     INTEGER NOT NULL,
    key_offset  INTEGER NOT NULL,
    bytenr      INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    level       INTEGER NOT NULL,
    leaf        INTEGER NOT NULL,
    slot        INTEGER NOT NULL,
    status      TEXT    NOT NULL,
    blocks      INTEGER NOT NULL,
    missing     INTEGER NOT NULL,
    PRIMARY KEY (state_id, position)
);

CREATE TABLE walk_failures (
    walk_failure_id  INTEGER PRIMARY KEY,
    source           TEXT    NOT NULL,
    tree_id          INTEGER NOT NULL,
    bytenr           INTEGER NOT NULL,
    failure_class    TEXT    NOT NULL
);

CREATE TABLE items (
    content_id    INTEGER NOT NULL REFERENCES contents(content_id),
    slot          INTEGER NOT NULL,
    key_objectid  INTEGER NOT NULL,
    key_type      INTEGER NOT NULL,
    key_offset    INTEGER NOT NULL,
    key_sort      BLOB    NOT NULL,
    type_name     TEXT    NOT NULL,
    data_offset   INTEGER NOT NULL,
    data_size     INTEGER NOT NULL,
    data          BLOB    NOT NULL,
    PRIMARY KEY (content_id, slot)
);
CREATE INDEX items_by_key ON items (key_sort);
CREATE INDEX items_by_type ON items (key_type, key_objectid);

CREATE TABLE item_problems (
    content_id  INTEGER NOT NULL REFERENCES contents(content_id),
    slot        INTEGER,
    detail      TEXT    NOT NULL
);

CREATE TABLE key_ptrs (
    content_id      INTEGER NOT NULL REFERENCES contents(content_id),
    slot            INTEGER NOT NULL,
    key_objectid    INTEGER NOT NULL,
    key_type        INTEGER NOT NULL,
    key_offset      INTEGER NOT NULL,
    key_sort        BLOB    NOT NULL,
    blockptr        INTEGER NOT NULL,
    ptr_generation  INTEGER NOT NULL,
    PRIMARY KEY (content_id, slot)
);
CREATE INDEX key_ptrs_by_child ON key_ptrs (blockptr, ptr_generation);

CREATE TABLE inodes (
    content_id  INTEGER NOT NULL,
    slot        INTEGER NOT NULL,
    objectid    INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    transid     INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    nbytes      INTEGER NOT NULL,
    nlink       INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    gid         INTEGER NOT NULL,
    mode        INTEGER NOT NULL,
    rdev        INTEGER NOT NULL,
    flags       INTEGER NOT NULL,
    sequence    INTEGER NOT NULL,
    atime_sec   INTEGER NOT NULL,
    atime_nsec  INTEGER NOT NULL,
    ctime_sec   INTEGER NOT NULL,
    ctime_nsec  INTEGER NOT NULL,
    mtime_sec   INTEGER NOT NULL,
    mtime_nsec  INTEGER NOT NULL,
    otime_sec   INTEGER NOT NULL,
    otime_nsec  INTEGER NOT NULL,
    PRIMARY KEY (content_id, slot),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX inodes_by_objectid ON inodes (objectid);

CREATE TABLE inode_refs (
    content_id       INTEGER NOT NULL,
    slot             INTEGER NOT NULL,
    entry            INTEGER NOT NULL,
    objectid         INTEGER NOT NULL,
    parent_objectid  INTEGER NOT NULL,
    dir_index        INTEGER NOT NULL,
    name             TEXT    NOT NULL,
    name_raw         BLOB    NOT NULL,
    extended         INTEGER NOT NULL,
    PRIMARY KEY (content_id, slot, entry),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX inode_refs_by_objectid ON inode_refs (objectid);

CREATE TABLE dir_entries (
    content_id      INTEGER NOT NULL,
    slot            INTEGER NOT NULL,
    entry           INTEGER NOT NULL,
    kind            TEXT    NOT NULL,
    dir_objectid    INTEGER NOT NULL,
    key_offset      INTEGER NOT NULL,
    child_objectid  INTEGER NOT NULL,
    child_key_type  INTEGER NOT NULL,
    child_offset    INTEGER NOT NULL,
    file_type       INTEGER NOT NULL,
    transid         INTEGER NOT NULL,
    data_len        INTEGER NOT NULL,
    name            TEXT    NOT NULL,
    name_raw        BLOB    NOT NULL,
    PRIMARY KEY (content_id, slot, entry),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX dir_entries_by_dir ON dir_entries (dir_objectid);
CREATE INDEX dir_entries_by_child ON dir_entries (child_objectid);

CREATE TABLE file_extents (
    content_id      INTEGER NOT NULL,
    slot            INTEGER NOT NULL,
    objectid        INTEGER NOT NULL,
    file_offset     INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    ram_bytes       INTEGER NOT NULL,
    compression     INTEGER NOT NULL,
    encryption      INTEGER NOT NULL,
    other_encoding  INTEGER NOT NULL,
    extent_type     INTEGER NOT NULL,
    extent_kind     TEXT    NOT NULL,
    disk_bytenr     INTEGER,
    disk_num_bytes  INTEGER,
    extent_offset   INTEGER,
    num_bytes       INTEGER,
    inline_size     INTEGER,
    PRIMARY KEY (content_id, slot),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX file_extents_by_inode ON file_extents (objectid, file_offset);
CREATE INDEX file_extents_by_extent ON file_extents (disk_bytenr);

CREATE TABLE root_items (
    content_id     INTEGER NOT NULL,
    slot           INTEGER NOT NULL,
    tree_id        INTEGER NOT NULL,
    key_offset     INTEGER NOT NULL,
    bytenr         INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    level          INTEGER NOT NULL,
    root_dirid     INTEGER NOT NULL,
    refs           INTEGER NOT NULL,
    flags          INTEGER NOT NULL,
    last_snapshot  INTEGER NOT NULL,
    bytes_used     INTEGER NOT NULL,
    drop_level     INTEGER NOT NULL,
    uuid           TEXT,
    parent_uuid    TEXT,
    received_uuid  TEXT,
    ctransid       INTEGER,
    otransid       INTEGER,
    otime_sec      INTEGER,
    PRIMARY KEY (content_id, slot),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX root_items_by_root ON root_items (bytenr, generation);
CREATE INDEX root_items_by_tree ON root_items (tree_id);

CREATE TABLE extents (
    content_id  INTEGER NOT NULL,
    slot        INTEGER NOT NULL,
    bytenr      INTEGER NOT NULL,
    num_bytes   INTEGER,
    refs        INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    flags       INTEGER NOT NULL,
    tree_block  INTEGER NOT NULL,
    level       INTEGER,
    PRIMARY KEY (content_id, slot),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX extents_by_bytenr ON extents (bytenr);

CREATE TABLE extent_backrefs (
    content_id     INTEGER NOT NULL,
    slot           INTEGER NOT NULL,
    entry          INTEGER NOT NULL,
    extent_bytenr  INTEGER NOT NULL,
    ref_type       INTEGER NOT NULL,
    ref_type_name  TEXT    NOT NULL,
    inline         INTEGER NOT NULL,
    root           INTEGER,
    parent         INTEGER,
    objectid       INTEGER,
    file_offset    INTEGER,
    ref_count      INTEGER,
    PRIMARY KEY (content_id, slot, entry),
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX extent_backrefs_by_extent ON extent_backrefs (extent_bytenr);

CREATE TABLE stale_items (
    content_id    INTEGER NOT NULL REFERENCES contents(content_id),
    position      INTEGER NOT NULL,
    slot          INTEGER NOT NULL,
    key_objectid  INTEGER NOT NULL,
    key_type      INTEGER NOT NULL,
    key_offset    INTEGER NOT NULL,
    key_sort      BLOB    NOT NULL,
    type_name     TEXT    NOT NULL,
    data_offset   INTEGER NOT NULL,
    data_size     INTEGER NOT NULL,
    data_state    TEXT    NOT NULL,
    data          BLOB,
    PRIMARY KEY (content_id, position)
);
CREATE INDEX stale_items_by_type ON stale_items (key_type, key_objectid);

CREATE TABLE stale_key_ptrs (
    content_id      INTEGER NOT NULL REFERENCES contents(content_id),
    position        INTEGER NOT NULL,
    slot            INTEGER NOT NULL,
    key_objectid    INTEGER NOT NULL,
    key_type        INTEGER NOT NULL,
    key_offset      INTEGER NOT NULL,
    key_sort        BLOB    NOT NULL,
    blockptr        INTEGER NOT NULL,
    ptr_generation  INTEGER NOT NULL,
    PRIMARY KEY (content_id, position)
);

CREATE TABLE recovery_runs (
    recovery_id    INTEGER PRIMARY KEY,
    tool_version   TEXT    NOT NULL,
    started_utc    TEXT    NOT NULL,
    finished_utc   TEXT,
    image_path     TEXT    NOT NULL,
    image_checked  INTEGER NOT NULL,
    output_dir     TEXT    NOT NULL,
    options        TEXT    NOT NULL,
    summary        TEXT
);

CREATE TABLE artifacts (
    artifact_id       INTEGER PRIMARY KEY,
    recovery_id       INTEGER NOT NULL REFERENCES recovery_runs(recovery_id),
    source_kind       TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    state_id          INTEGER REFERENCES states(state_id),
    tree_id           INTEGER NOT NULL,
    root_bytenr       INTEGER,
    root_generation   INTEGER,
    objectid          INTEGER NOT NULL,
    inode_generation  INTEGER,
    inode_transid     INTEGER,
    kind              TEXT    NOT NULL,
    path              TEXT    NOT NULL,
    path_raw          BLOB    NOT NULL,
    attached          INTEGER NOT NULL,
    names             TEXT    NOT NULL,
    size              INTEGER,
    mode              INTEGER,
    xattrs            TEXT    NOT NULL,
    symlink_target    TEXT,
    status            TEXT    NOT NULL,
    bytes_written     INTEGER NOT NULL,
    sha256            TEXT,
    extent_signature  TEXT,
    duplicate_of      INTEGER REFERENCES artifacts(artifact_id),
    output_path       TEXT,
    in_current        INTEGER,
    missing           TEXT    NOT NULL,
    problems          TEXT    NOT NULL
);
CREATE INDEX artifacts_by_inode ON artifacts (tree_id, objectid);
CREATE INDEX artifacts_by_sha256 ON artifacts (sha256);

CREATE TABLE provenance (
    provenance_id  INTEGER PRIMARY KEY,
    artifact_id    INTEGER NOT NULL REFERENCES artifacts(artifact_id),
    seq            INTEGER NOT NULL,
    role           TEXT    NOT NULL,
    content_id     INTEGER NOT NULL,
    slot           INTEGER NOT NULL,
    bytenr         INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    physical       INTEGER NOT NULL,
    block_status   TEXT    NOT NULL,
    file_offset    INTEGER,
    length         INTEGER,
    extent_sha256  TEXT,
    error_kind     TEXT,
    read_record    TEXT,
    FOREIGN KEY (content_id, slot) REFERENCES items(content_id, slot)
);
CREATE INDEX provenance_by_artifact ON provenance (artifact_id, seq);
CREATE INDEX provenance_by_item ON provenance (content_id, slot);

CREATE VIEW content_blocks AS
SELECT content_id, bytenr, generation, level, owner,
       COUNT(*)      AS copies,
       MIN(physical) AS first_physical,
       MAX(status = 'live')             AS live,
       MAX(status = 'backup_reachable') AS backup_reachable,
       MIN(outside_map)                 AS outside_map
FROM nodes
WHERE valid = 1 AND content_id IS NOT NULL
GROUP BY content_id, bytenr, generation, level, owner;

CREATE VIEW tree_edges AS
SELECT p.bytenr AS parent_bytenr, p.generation AS parent_generation, p.level AS parent_level,
       p.owner AS owner, k.slot AS slot, k.key_objectid, k.key_type, k.key_offset,
       k.blockptr AS child_bytenr, k.ptr_generation AS child_generation,
       EXISTS (
           SELECT 1 FROM nodes c
           WHERE c.valid = 1 AND c.bytenr = k.blockptr AND c.generation = k.ptr_generation
             AND c.level = p.level - 1
       ) AS child_found
FROM key_ptrs k
JOIN content_blocks p USING (content_id);

CREATE VIEW blocks AS
SELECT bytenr, generation, level, owner,
       COUNT(*)      AS copies,
       MIN(physical) AS first_physical,
       MAX(status = 'live')             AS live,
       MAX(status = 'backup_reachable') AS backup_reachable,
       MIN(outside_map)                 AS outside_map
FROM nodes
WHERE valid = 1
GROUP BY bytenr, generation, level, owner;
"""
