"""Item payload parsers for the items the walker, inventories and `btrfska walk` read.

Each parser takes an item's data and returns plain values. It raises only `ItemError`, when the
payload is too short or a name runs past the item. Names are decoded as UTF-8 with
surrogateescape, so undecodable bytes survive: `name.encode("utf-8", "surrogateescape")`.
`summary()` never raises and returns JSON-ready values.
"""

import uuid

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import type_name
from btrfska.substrate.node import Key

K = ondisk.ITEM_KEYS
KEY_TYPE_NAMES = {value: name for name, value in K.items()}
EXTENT_TYPE_NAMES = {
    ondisk.FILE_EXTENT_INLINE: "inline",
    ondisk.FILE_EXTENT_REG: "regular",
    ondisk.FILE_EXTENT_PREALLOC: "prealloc",
}
# struct btrfs_root_item as written by kernels before generation_v2 (239 bytes).
_ROOT_ITEM_LEGACY = ondisk.Layout(
    "btrfs_root_item (legacy)",
    [
        ("inode", f"{ondisk.INODE_ITEM.size}s"),
        ("generation", "Q"),
        ("root_dirid", "Q"),
        ("bytenr", "Q"),
        ("byte_limit", "Q"),
        ("bytes_used", "Q"),
        ("last_snapshot", "Q"),
        ("flags", "Q"),
        ("refs", "I"),
        ("drop_progress_objectid", "Q"),
        ("drop_progress_type", "B"),
        ("drop_progress_offset", "Q"),
        ("drop_level", "B"),
        ("level", "B"),
    ],
)
_FILE_EXTENT_HEAD = ondisk.Layout(
    "btrfs_file_extent_item (head)",
    [
        ("generation", "Q"),
        ("ram_bytes", "Q"),
        ("compression", "B"),
        ("encryption", "B"),
        ("other_encoding", "H"),
        ("type", "B"),
    ],
)
ROOT_SUBVOL_RDONLY = 1 << 0  # btrfs_tree.h:922


class ItemError(ValueError):
    """An item payload does not fit its structure."""


def _unpack(layout: ondisk.Layout, data, offset: int = 0) -> dict:
    if len(data) < offset + layout.size:
        raise ItemError(
            f"{layout.name} needs {layout.size} bytes at offset {offset}; the item has {len(data)}"
        )
    return layout.unpack_from(data, offset)


def _name(data, start: int, length: int, what: str) -> str:
    if start + length > len(data):
        raise ItemError(
            f"{what} name of {length} bytes at {start} runs past the {len(data)}-byte item"
        )
    return bytes(data[start : start + length]).decode("utf-8", "surrogateescape")


def _uuid(raw: bytes) -> str | None:
    return str(uuid.UUID(bytes=raw)) if any(raw) else None


def inode_item(data) -> dict:
    return _unpack(ondisk.INODE_ITEM, data)


def inode_refs(data) -> list[dict]:
    """INODE_REF: one or more (index, name) entries packed together."""
    refs, pos = [], 0
    while pos < len(data) or not refs:
        fields = _unpack(ondisk.INODE_REF, data, pos)
        pos += ondisk.INODE_REF.size
        refs.append(
            {"index": fields["index"], "name": _name(data, pos, fields["name_len"], "INODE_REF")}
        )
        pos += fields["name_len"]
    return refs


def inode_extrefs(data) -> list[dict]:
    refs, pos = [], 0
    while pos < len(data) or not refs:
        fields = _unpack(ondisk.INODE_EXTREF, data, pos)
        pos += ondisk.INODE_EXTREF.size
        name = _name(data, pos, fields["name_len"], "INODE_EXTREF")
        refs.append({"parent": fields["parent_objectid"], "index": fields["index"], "name": name})
        pos += fields["name_len"]
    return refs


def dir_items(data) -> list[dict]:
    """DIR_ITEM, DIR_INDEX and XATTR_ITEM: one or more entries, each a name then data_len bytes."""
    entries, pos = [], 0
    while pos < len(data) or not entries:
        fields = _unpack(ondisk.DIR_ITEM, data, pos)
        pos += ondisk.DIR_ITEM.size
        name = _name(data, pos, fields["name_len"], "DIR_ITEM")
        pos += fields["name_len"]
        if pos + fields["data_len"] > len(data):
            raise ItemError(f"DIR_ITEM data of {fields['data_len']} bytes runs past the item")
        pos += fields["data_len"]
        location = Key(
            fields["location_objectid"], fields["location_type"], fields["location_offset"]
        )
        entries.append(
            {
                "name": name,
                "location": location,
                "type": fields["type"],
                "transid": fields["transid"],
                "data_len": fields["data_len"],
            }
        )
    return entries


def file_extent(data) -> dict:
    """EXTENT_DATA. Inline extents report `inline_size`; the data follows the 21-byte head."""
    head = _unpack(_FILE_EXTENT_HEAD, data)
    if head["type"] == ondisk.FILE_EXTENT_INLINE:
        return {**head, "inline_size": len(data) - ondisk.FILE_EXTENT_INLINE_DATA_START}
    return _unpack(ondisk.FILE_EXTENT_ITEM, data)


def root_item(data) -> dict:
    """ROOT_ITEM; legacy 239-byte items lack generation_v2, the uuids and the times."""
    layout = ondisk.ROOT_ITEM if len(data) >= ondisk.ROOT_ITEM.size else _ROOT_ITEM_LEGACY
    fields = _unpack(layout, data)
    del fields["inode"]
    return fields


def root_ref(data) -> dict:
    """ROOT_REF and ROOT_BACKREF."""
    fields = _unpack(ondisk.ROOT_REF, data)
    name = _name(data, ondisk.ROOT_REF.size, fields["name_len"], "ROOT_REF")
    return {"dirid": fields["dirid"], "sequence": fields["sequence"], "name": name}


# ---------------------------------------------------------------------------
# JSON summaries
# ---------------------------------------------------------------------------
def _key_dict(key: Key) -> dict:
    return {"objectid": key.objectid, "type": key.type, "offset": key.offset}


def _inode_summary(data) -> dict:
    inode = inode_item(data)
    names = ("generation", "transid", "size", "nbytes", "nlink", "uid", "gid", "mode", "flags")
    summary = {name: inode[name] for name in names}
    summary["mode"] = f"{inode['mode']:o}"
    return summary


def _dir_summary(data) -> dict:
    return {"entries": [{**e, "location": _key_dict(e["location"])} for e in dir_items(data)]}


def _extent_summary(data) -> dict:
    extent = file_extent(data)
    return {**extent, "type": EXTENT_TYPE_NAMES.get(extent["type"], extent["type"])}


def _root_summary(data) -> dict:
    fields = root_item(data)
    names = ("generation", "root_dirid", "bytenr", "level", "flags", "refs", "last_snapshot")
    summary = {name: fields[name] for name in names}
    if "uuid" in fields:
        summary |= {
            "generation_v2": fields["generation_v2"],
            "uuid": _uuid(fields["uuid"]),
            "parent_uuid": _uuid(fields["parent_uuid"]),
            "ctransid": fields["ctransid"],
            "otransid": fields["otransid"],
        }
    return summary


def _chunk_summary(data) -> dict:
    fields = _unpack(ondisk.CHUNK, data)
    stripes = []
    for index in range(fields["num_stripes"]):
        stripe = _unpack(ondisk.STRIPE, data, ondisk.CHUNK.size + index * ondisk.STRIPE.size)
        stripes.append({"devid": stripe["devid"], "offset": stripe["offset"]})
    return {
        "length": fields["length"],
        "type": type_name(fields["type"]),
        "num_stripes": fields["num_stripes"],
        "sub_stripes": fields["sub_stripes"],
        "stripes": stripes,
    }


def _dev_item_summary(data) -> dict:
    fields = _unpack(ondisk.DEV_ITEM, data)
    return {
        "devid": fields["devid"],
        "total_bytes": fields["total_bytes"],
        "bytes_used": fields["bytes_used"],
        "uuid": _uuid(fields["uuid"]),
        "fsid": _uuid(fields["fsid"]),
    }


def _plain(layout: ondisk.Layout, drop: tuple[str, ...] = ()):
    def summarize(data) -> dict:
        return {k: v for k, v in _unpack(layout, data).items() if k not in drop}

    return summarize


def _block_group_summary(data) -> dict:
    fields = _unpack(ondisk.BLOCK_GROUP_ITEM, data)
    return {**fields, "flags": type_name(fields["flags"])}


_SUMMARIES = {
    K["INODE_ITEM"]: _inode_summary,
    K["INODE_REF"]: lambda data: {"refs": inode_refs(data)},
    K["INODE_EXTREF"]: lambda data: {"refs": inode_extrefs(data)},
    K["DIR_ITEM"]: _dir_summary,
    K["DIR_INDEX"]: _dir_summary,
    K["XATTR_ITEM"]: _dir_summary,
    K["EXTENT_DATA"]: _extent_summary,
    K["ROOT_ITEM"]: _root_summary,
    K["ROOT_REF"]: root_ref,
    K["ROOT_BACKREF"]: root_ref,
    K["CHUNK_ITEM"]: _chunk_summary,
    K["DEV_ITEM"]: _dev_item_summary,
    K["DEV_EXTENT"]: _plain(ondisk.DEV_EXTENT, drop=("chunk_tree_uuid",)),
    K["EXTENT_ITEM"]: _plain(ondisk.EXTENT_ITEM),
    K["METADATA_ITEM"]: _plain(ondisk.EXTENT_ITEM),
    K["BLOCK_GROUP_ITEM"]: _block_group_summary,
}


def summary(key: Key, data) -> dict | None:
    """A JSON-ready summary of the item, {"error": ...} when malformed, None for other types."""
    summarize = _SUMMARIES.get(key.type)
    if summarize is None:
        return None
    try:
        return summarize(data)
    except ItemError as exc:
        return {"error": str(exc)}
