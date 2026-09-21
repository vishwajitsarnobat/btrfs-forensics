"""Reverse queries over an evidence database (plan.md M3b). None of them needs the image.

Every function takes a read-only connection from `catalog.db.open_readonly` and returns plain
dicts. Integers come back as the on-disk u64 values (the database stores them signed; see
schema.py), so an owner reads 18446744073709551610, as `btrfska walk` prints it, not -6.

- `parents_of`: what points to a tree block: the internal nodes whose key pointers name it, the
  ROOT_ITEMs that name it as a tree root, and the superblock or backup slots that do.
- `owners_of`: what uses an extent: file extents of any generation that point to it, the extent
  tree's back-references to it, and, for a tree block, the blocks scanned at that address.
- `trees_covering`: the leaves whose key range holds a key, and whether they hold exactly that key.
- `items_in_generation`: the items of every leaf written in a generation.
"""

import sqlite3

from btrfska.catalog.schema import key_sort, s64, u64

_BLOCK = (
    "b.bytenr, b.generation, b.level, b.owner, b.copies, b.live, b.backup_reachable, b.outside_map"
)


def _rows(cursor: sqlite3.Cursor) -> list[dict]:
    """Rows as dicts, with stored signed integers turned back into u64."""
    names = [column[0] for column in cursor.description]
    out = []
    for row in cursor:
        record = {}
        for name, value in zip(names, row, strict=True):
            if isinstance(value, int) and not isinstance(value, bool) and value < 0:
                value = u64(value)
            elif isinstance(value, bytes):
                value = value.hex()
            record[name] = value
        out.append(record)
    return out


def _reach(row: dict) -> dict:
    """Fold the three reachability flags of a block into one word."""
    live, backup = row.pop("live"), row.pop("backup_reachable")
    row["reach"] = "live" if live else "backup_reachable" if backup else "unreferenced"
    row["outside_map"] = bool(row["outside_map"])
    return row


def parents_of(conn: sqlite3.Connection, bytenr: int, generation: int | None = None) -> list[dict]:
    """Everything that references the tree block at `bytenr` (of `generation`, when given)."""
    gen = () if generation is None else (s64(generation),)
    nodes = _rows(
        conn.execute(
            "SELECT 'node' AS referrer, parent_bytenr AS bytenr, parent_generation AS generation,"
            " parent_level AS level, owner, slot, child_generation, child_found,"
            " key_objectid, key_type, key_offset"
            " FROM tree_edges WHERE child_bytenr = ?"
            + (" AND child_generation = ?" if gen else "")
            + " ORDER BY parent_generation DESC, parent_bytenr, slot",
            (s64(bytenr), *gen),
        )
    )
    for row in nodes:
        row["child_found"] = bool(row["child_found"])
    root_items = _rows(
        conn.execute(
            f"SELECT 'root_item' AS referrer, {_BLOCK}, r.slot, r.tree_id, r.key_offset,"
            " r.generation AS child_generation, r.level AS child_level"
            " FROM root_items r JOIN content_blocks b USING (content_id) WHERE r.bytenr = ?"
            + (" AND r.generation = ?" if gen else "")
            + " ORDER BY b.generation DESC, b.bytenr",
            (s64(bytenr), *gen),
        )
    )
    known = _rows(
        conn.execute(
            "SELECT 'superblock' AS referrer, source, tree, tree_id,"
            " generation AS child_generation, level AS child_level, indexed"
            " FROM known_roots WHERE bytenr = ?"
            + (" AND generation = ?" if gen else "")
            + " ORDER BY known_root_id",
            (s64(bytenr), *gen),
        )
    )
    return [*nodes, *map(_reach, root_items), *known]


def owners_of(conn: sqlite3.Connection, bytenr: int) -> list[dict]:
    """Everything that uses the extent starting at logical address `bytenr`."""
    files = _rows(
        conn.execute(
            f"SELECT 'file_extent' AS referrer, {_BLOCK}, f.slot, f.objectid AS inode,"
            " f.file_offset, f.generation AS extent_generation, f.extent_kind, f.compression,"
            " f.disk_num_bytes, f.extent_offset, f.num_bytes, f.ram_bytes"
            " FROM file_extents f JOIN content_blocks b USING (content_id)"
            " WHERE f.disk_bytenr = ? ORDER BY b.generation DESC, b.owner, f.objectid",
            (s64(bytenr),),
        )
    )
    backrefs = _rows(
        conn.execute(
            f"SELECT 'extent_backref' AS referrer, {_BLOCK}, r.slot, r.ref_type_name, r.inline,"
            " r.root, r.parent, r.objectid AS inode, r.file_offset, r.ref_count"
            " FROM extent_backrefs r JOIN content_blocks b USING (content_id)"
            " WHERE r.extent_bytenr = ? ORDER BY b.generation DESC, r.slot, r.entry",
            (s64(bytenr),),
        )
    )
    for row in backrefs:
        row["inline"] = bool(row["inline"])
    blocks = _rows(
        conn.execute(
            "SELECT 'tree_block' AS referrer, bytenr, generation, level, owner, copies, live,"
            " backup_reachable, outside_map FROM blocks WHERE bytenr = ? ORDER BY generation DESC",
            (s64(bytenr),),
        )
    )
    return [*map(_reach, files), *map(_reach, backrefs), *map(_reach, blocks)]


def trees_covering(
    conn: sqlite3.Connection, objectid: int, key_type: int, offset: int
) -> list[dict]:
    """The leaves whose first and last key enclose the key; `exact` when the key is an item."""
    wanted = key_sort(objectid, key_type, offset)
    rows = _rows(
        conn.execute(
            f"SELECT {_BLOCK}, c.nritems,"
            " EXISTS (SELECT 1 FROM items i WHERE i.content_id = c.content_id AND i.key_sort = ?)"
            " AS exact"
            " FROM contents c JOIN content_blocks b USING (content_id)"
            " WHERE c.level = 0 AND c.first_key <= ? AND c.last_key >= ?"
            " ORDER BY b.owner, b.generation DESC, b.bytenr",
            (wanted, wanted, wanted),
        )
    )
    for row in rows:
        row["exact"] = bool(row["exact"])
    return [_reach(row) for row in rows]


def items_in_generation(
    conn: sqlite3.Connection,
    generation: int,
    key_type: int | None = None,
    limit: int | None = None,
) -> list[dict]:
    """The items of every leaf whose header generation is `generation`, in tree and key order."""
    sql = (
        f"SELECT {_BLOCK}, i.slot, i.key_objectid, i.key_type, i.type_name, i.key_offset,"
        " i.data_size FROM items i JOIN content_blocks b USING (content_id)"
        " WHERE b.generation = ?"
    )
    args: list = [s64(generation)]
    if key_type is not None:
        sql += " AND i.key_type = ?"
        args.append(key_type)
    sql += " ORDER BY b.owner, b.bytenr, i.slot"
    if limit is not None:
        sql += " LIMIT ?"
        args.append(limit)
    return [_reach(row) for row in _rows(conn.execute(sql, args))]
