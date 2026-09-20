"""The evidence database schema (docs/evidence-db.md documents every table and column).

One database describes one pass over one image. `SCHEMA_VERSION` changes with any change to the
DDL below; the document lists what each version changed (plan.md M3).

Integers. SQLite integers are signed 64-bit, while btrfs objectids, offsets and generations are
u64. Every on-disk u64 is stored as its two's-complement signed value (`s64`): values of 2^63 and
above appear negative, which is how btrfs names the high objectids (-6 is the log tree). `u64`
converts back. Byte offsets into an image are always below 2^63 and are stored as they are.
"""

SCHEMA_VERSION = 1

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
    problems       TEXT    NOT NULL
);
CREATE INDEX nodes_by_block ON nodes (bytenr, generation);
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
