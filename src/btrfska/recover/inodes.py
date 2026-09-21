"""What a tree says about each inode: its item, names, attributes and extents, and their paths.

Input is the leaves of one tree from `recover/dbtree.py`. Every piece keeps the leaf and slot it
was read from; that is the provenance chain `recover/engine.py` stores. Item payloads go through
the `substrate/items.py` parsers; a payload that does not parse becomes a problem of its inode,
never an exception.

Names are bytes from an untrusted image. `safe_component` turns one into a file name that cannot
leave the output directory; `paths` resolves each inode to a path under the tree's root
directory, or under `UNATTACHED` when its parents do not lead there.
"""

import sqlite3
import stat
from dataclasses import dataclass, field

from btrfska.recover.dbtree import Leaf, leaf_items
from btrfska.substrate import items, ondisk
from btrfska.substrate.node import Item

K = ondisk.ITEM_KEYS
ROOT_DIR = ondisk.FIRST_FREE_OBJECTID  # the root directory of every fs and subvolume tree
UNATTACHED = b".btrfska-unattached"
ORPHAN_ITEMS = b".btrfska-orphan-items"  # inodes a tree lists under ORPHAN_ITEM
MAX_DEPTH = 4096  # PATH_MAX cannot hold a deeper path; a longer parent chain is a cycle


@dataclass(frozen=True)
class Origin:
    """An item an artifact was built from: where it is, and what it contributed."""

    role: str  # inode_item, inode_ref, inode_extref, xattr, extent_data
    leaf: Leaf
    slot: int


@dataclass(frozen=True)
class Name:
    parent: int
    name: bytes
    index: int
    extended: bool  # from INODE_EXTREF


@dataclass
class InodeRecord:
    objectid: int
    inode: dict | None = None  # the parsed INODE_ITEM
    names: list[Name] = field(default_factory=list)
    xattrs: list[tuple[bytes, bytes]] = field(default_factory=list)
    extents: list[tuple[Item, Leaf]] = field(default_factory=list)
    origins: list[Origin] = field(default_factory=list)
    encrypted_name: bool = False  # a directory entry marks it FT_ENCRYPTED
    orphan_item: bool = False  # the tree lists it under ORPHAN_ITEM: unlinked, not yet cleaned up
    problems: list[str] = field(default_factory=list)
    joins: list[dict] = field(default_factory=list)  # recover/graph.py: what was joined, and why
    log_only: bool = False  # from a log tree, without a base: what was not logged is not known
    exists_only: bool = False  # logged with generation 0: names, no content

    @property
    def kind(self) -> str:
        if self.inode is None:
            return "unknown"
        mode = self.inode["mode"]
        if stat.S_ISREG(mode):
            return "file"
        if stat.S_ISDIR(mode):
            return "dir"
        return "symlink" if stat.S_ISLNK(mode) else "other"


def _raw(name: str) -> bytes:
    return name.encode("utf-8", "surrogateescape")


def collect(conn: sqlite3.Connection, leaves: list[Leaf]) -> dict[int, InodeRecord]:
    """Every inode the leaves mention, keyed by objectid."""
    inodes: dict[int, InodeRecord] = {}
    encrypted: set[int] = set()
    orphaned: set[int] = set()
    for leaf in leaves:
        for item in leaf_items(conn, leaf):
            key = item.key
            try:
                if key.objectid == ondisk.ORPHAN_OBJECTID:
                    if key.type == K["ORPHAN_ITEM"]:
                        orphaned.add(key.offset)  # the key offset is the inode number
                elif key.type == K["INODE_ITEM"]:
                    record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                    record.inode = items.inode_item(item.data)
                    record.origins.append(Origin("inode_item", leaf, item.slot))
                elif key.type == K["INODE_REF"]:
                    record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                    for ref in items.inode_refs(item.data):
                        record.names.append(
                            Name(key.offset, _raw(ref["name"]), ref["index"], False)
                        )
                    record.origins.append(Origin("inode_ref", leaf, item.slot))
                elif key.type == K["INODE_EXTREF"]:
                    record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                    for ref in items.inode_extrefs(item.data):
                        name = Name(ref["parent"], _raw(ref["name"]), ref["index"], True)
                        record.names.append(name)
                    record.origins.append(Origin("inode_extref", leaf, item.slot))
                elif key.type == K["XATTR_ITEM"]:
                    record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                    for attr in items.xattr_items(item.data):
                        record.xattrs.append((_raw(attr["name"]), attr["value"]))
                    record.origins.append(Origin("xattr", leaf, item.slot))
                elif key.type == K["EXTENT_DATA"]:
                    record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                    record.extents.append((item, leaf))
                    record.origins.append(Origin("extent_data", leaf, item.slot))
                elif key.type == K["DIR_INDEX"]:
                    for entry in items.dir_items(item.data):
                        if entry["type"] & ondisk.FT_ENCRYPTED:
                            encrypted.add(entry["location"].objectid)
            except items.ItemError as exc:
                record = inodes.setdefault(key.objectid, InodeRecord(key.objectid))
                record.problems.append(f"item {key} in leaf {leaf.bytenr} slot {item.slot}: {exc}")
    for objectid in orphaned & inodes.keys():
        inodes[objectid].orphan_item = True
    for objectid in encrypted & inodes.keys():
        inodes[objectid].encrypted_name = True
        inodes[objectid].problems.append("its directory entry carries FT_ENCRYPTED (0x80)")
    return inodes


def safe_component(name: bytes, objectid: int) -> tuple[bytes, str | None]:
    """A usable file name for `name`, and what was changed, if anything."""
    cleaned = name.replace(b"/", b"_").replace(b"\0", b"_")
    if cleaned in (b"", b".", b".."):
        cleaned = b"_" + cleaned.replace(b".", b"dot") + b"_inode" + str(objectid).encode()
    if len(cleaned) > 200:  # room for the suffixes this tool may add, within NAME_MAX 255
        cleaned = cleaned[:200] + b"~inode" + str(objectid).encode()
    return cleaned, None if cleaned == name else f"name {name!r} written as {cleaned!r}"


def paths(
    inodes: dict[int, InodeRecord], ancestors: dict[int, Name] | None = None
) -> dict[int, tuple[tuple[bytes, ...], bool]]:
    """objectid -> (path components under the output root, attached to the root directory).

    An inode's path follows the first name of each ancestor. A chain that meets a missing inode,
    an inode without a name, or itself, ends under UNATTACHED/<objectid of where it broke>.
    `ancestors` names directories the leaves do not hold (recover/graph.py).
    """
    done: dict[int, tuple[tuple[bytes, ...], bool]] = {ROOT_DIR: ((), True)}
    known = dict(ancestors or {})
    known.update({number: record.names[0] for number, record in inodes.items() if record.names})

    def resolve(objectid: int) -> tuple[tuple[bytes, ...], bool]:
        chain, current = [], objectid
        while current not in done:
            if current not in known or current in chain or len(chain) >= MAX_DEPTH:
                done[current] = ((UNATTACHED, str(current).encode()), False)
                break
            chain.append(current)
            current = known[current].parent
        for member in reversed(chain):
            first = known[member]
            base, attached = done[first.parent]
            component, _ = safe_component(first.name, member)
            done[member] = ((*base, component), attached)
        return done[objectid]

    return {objectid: resolve(objectid) for objectid in inodes if objectid != ROOT_DIR}
