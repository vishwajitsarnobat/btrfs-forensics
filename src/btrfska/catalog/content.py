"""Block contents for the evidence database: items, key pointers and the parsed item tables.

A block's content is identified by the SHA-256 of its nodesize bytes, so the byte-identical
copies of DUP and RAID1 profiles are parsed and stored once, while a copy that differs gets its
own row and stays visible. Items are parsed from a content as soon as one node holding it is
valid; the bytes of a content that never validates are hashed but not interpreted.

A payload that does not fit its structure never stops the build: the raw item is kept in `items`
and the reason goes to `item_problems`.
"""

import hashlib
import sqlite3

from btrfska.catalog.schema import key_sort, s64
from btrfska.substrate import items as item_parsers
from btrfska.substrate import ondisk
from btrfska.substrate.node import Item, parse_items, parse_key_ptrs

K = ondisk.ITEM_KEYS
_DIR_KINDS = {K["DIR_ITEM"]: "DIR_ITEM", K["DIR_INDEX"]: "DIR_INDEX", K["XATTR_ITEM"]: "XATTR_ITEM"}
_REF_KEYS = frozenset(
    K[name]
    for name in (
        "TREE_BLOCK_REF",
        "SHARED_BLOCK_REF",
        "EXTENT_DATA_REF",
        "SHARED_DATA_REF",
        "EXTENT_OWNER_REF",
    )
)
_INODE_COLUMNS = (
    "generation", "transid", "size", "nbytes", "nlink", "uid", "gid", "mode", "rdev", "flags",
    "sequence", "atime_sec", "atime_nsec", "ctime_sec", "ctime_nsec", "mtime_sec", "mtime_nsec",
    "otime_sec", "otime_nsec",
)  # fmt: skip
BATCH = 5000

_INSERT = {
    "items": 10,
    "item_problems": 3,
    "key_ptrs": 8,
    "inodes": 3 + len(_INODE_COLUMNS),
    "inode_refs": 9,
    "dir_entries": 14,
    "file_extents": 16,
    "root_items": 19,
    "extents": 9,
    "extent_backrefs": 12,
}


def _text(name: str) -> tuple[str, bytes]:
    """A name as SQLite text (undecodable bytes replaced) and as the exact bytes on disk."""
    raw = name.encode("utf-8", "surrogateescape")
    return raw.decode("utf-8", "replace"), raw


class ContentWriter:
    """Assigns content ids and writes every table that hangs off `contents`."""

    def __init__(self, conn: sqlite3.Connection, nodesize: int) -> None:
        self.conn, self.nodesize = conn, nodesize
        self.ids: dict[bytes, int] = {}
        self.parsed: set[int] = set()
        self.rows: dict[str, list[tuple]] = {table: [] for table in _INSERT}
        self.pending = 0

    def add(self, block, valid: bool) -> int:
        """The content id of `block` (nodesize bytes); parses it the first time it is valid."""
        digest = hashlib.sha256(block).digest()
        content_id = self.ids.get(digest)
        if content_id is None:
            header = ondisk.HEADER.unpack_from(block)
            cursor = self.conn.execute(
                "INSERT INTO contents (sha256, level, nritems, parsed) VALUES (?, ?, ?, 0)",
                (digest.hex(), header["level"], header["nritems"]),
            )
            content_id = self.ids[digest] = cursor.lastrowid
        if valid and content_id not in self.parsed:
            self.parsed.add(content_id)
            self._parse(content_id, block)
        return content_id

    def _parse(self, content_id: int, block) -> None:
        header = ondisk.HEADER.unpack_from(block)
        if header["level"] == 0:
            entries, problems = parse_items(block, self.nodesize)
            for item in entries:
                self._item(content_id, item)
            keys = [item.key for item in entries]
        else:
            entries, problems = parse_key_ptrs(block, self.nodesize)
            for ptr in entries:
                self.rows["key_ptrs"].append(
                    (content_id, ptr.slot, *map(s64, ptr.key), key_sort(*ptr.key),
                     s64(ptr.blockptr), s64(ptr.generation))
                )  # fmt: skip
            keys = [ptr.key for ptr in entries]
        self.rows["item_problems"].extend((content_id, None, detail) for detail in problems)
        first, last = (key_sort(*keys[0]), key_sort(*keys[-1])) if keys else (None, None)
        self.conn.execute(
            "UPDATE contents SET parsed = 1, first_key = ?, last_key = ? WHERE content_id = ?",
            (first, last, content_id),
        )
        self.pending += len(entries)
        if self.pending >= BATCH:
            self.flush()

    def _item(self, content_id: int, item: Item) -> None:
        key = item.key
        name = item_parsers.KEY_TYPE_NAMES.get(key.type, f"UNKNOWN.{key.type}")
        self.rows["items"].append(
            (content_id, item.slot, *map(s64, key), key_sort(*key), name, item.offset, item.size,
             item.data)
        )  # fmt: skip
        try:
            self._parsed_rows(content_id, item)
        except item_parsers.ItemError as exc:
            self.rows["item_problems"].append((content_id, item.slot, f"{name}: {exc}"))

    def _parsed_rows(self, content_id: int, item: Item) -> None:
        key, where = item.key, (content_id, item.slot)
        if key.type == K["INODE_ITEM"]:
            fields = item_parsers.inode_item(item.data)
            values = (s64(fields[column]) for column in _INODE_COLUMNS)
            self.rows["inodes"].append((*where, s64(key.objectid), *values))
        elif key.type == K["INODE_REF"]:
            for entry, ref in enumerate(item_parsers.inode_refs(item.data)):
                self.rows["inode_refs"].append(
                    (*where, entry, s64(key.objectid), s64(key.offset), s64(ref["index"]),
                     *_text(ref["name"]), 0)
                )  # fmt: skip
        elif key.type == K["INODE_EXTREF"]:
            for entry, ref in enumerate(item_parsers.inode_extrefs(item.data)):
                self.rows["inode_refs"].append(
                    (*where, entry, s64(key.objectid), s64(ref["parent"]), s64(ref["index"]),
                     *_text(ref["name"]), 1)
                )  # fmt: skip
        elif key.type in _DIR_KINDS:
            for entry, found in enumerate(item_parsers.dir_items(item.data)):
                location = found["location"]
                self.rows["dir_entries"].append(
                    (*where, entry, _DIR_KINDS[key.type], s64(key.objectid), s64(key.offset),
                     s64(location.objectid), location.type, s64(location.offset), found["type"],
                     s64(found["transid"]), found["data_len"], *_text(found["name"]))
                )  # fmt: skip
        elif key.type == K["EXTENT_DATA"]:
            fields = item_parsers.file_extent(item.data)
            kind = item_parsers.EXTENT_TYPE_NAMES.get(fields["type"], f"type {fields['type']}")
            self.rows["file_extents"].append(
                (*where, s64(key.objectid), s64(key.offset), s64(fields["generation"]),
                 s64(fields["ram_bytes"]), fields["compression"], fields["encryption"],
                 fields["other_encoding"], fields["type"], kind, s64(fields.get("disk_bytenr")),
                 s64(fields.get("disk_num_bytes")), s64(fields.get("offset")),
                 s64(fields.get("num_bytes")), fields.get("inline_size"))
            )  # fmt: skip
        elif key.type == K["ROOT_ITEM"]:
            fields = item_parsers.root_item(item.data)
            uuids = (fields.get(name) for name in ("uuid", "parent_uuid", "received_uuid"))
            self.rows["root_items"].append(
                (*where, s64(key.objectid), s64(key.offset), s64(fields["bytenr"]),
                 s64(fields["generation"]), fields["level"], s64(fields["root_dirid"]),
                 fields["refs"], s64(fields["flags"]), s64(fields["last_snapshot"]),
                 s64(fields["bytes_used"]), fields["drop_level"],
                 *(value.hex() if value and any(value) else None for value in uuids),
                 s64(fields.get("ctransid")), s64(fields.get("otransid")),
                 s64(fields.get("otime_sec")))
            )  # fmt: skip
        elif key.type in (K["EXTENT_ITEM"], K["METADATA_ITEM"]):
            extent = item_parsers.extent_item(key, item.data)
            self.rows["extents"].append(
                (*where, s64(extent["bytenr"]), s64(extent["num_bytes"]), s64(extent["refs"]),
                 s64(extent["generation"]), s64(extent["flags"]), int(extent["tree_block"]),
                 extent["level"])
            )  # fmt: skip
            for entry, ref in enumerate(extent["backrefs"]):
                self._backref(where, entry, extent["bytenr"], ref)
        elif key.type in _REF_KEYS:
            self._backref(where, 0, key.objectid, item_parsers.extent_ref(key, item.data))

    def _backref(self, where: tuple[int, int], entry: int, bytenr: int, ref: dict) -> None:
        self.rows["extent_backrefs"].append(
            (*where, entry, s64(bytenr), ref["type"], ref["type_name"], int(ref["inline"]),
             s64(ref["root"]), s64(ref["parent"]), s64(ref["objectid"]), s64(ref["offset"]),
             ref["count"])
        )  # fmt: skip

    def flush(self) -> None:
        for table, rows in self.rows.items():
            if rows:
                marks = ", ".join("?" * _INSERT[table])
                self.conn.executemany(f"INSERT INTO {table} VALUES ({marks})", rows)
                rows.clear()
        self.pending = 0
