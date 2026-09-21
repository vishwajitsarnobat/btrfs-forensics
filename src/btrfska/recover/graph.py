"""The orphan graph: joins between blocks that no root tree leads to (plan.md M5c).

`recover --orphans` reads every such leaf on its own and joins nothing (M4). A wrong join makes
a file that never existed, so every join here rests on stated evidence, is written into the
artifact (`artifacts.joined`), and is refused when two candidates would give different results.

- `pointer` (dbtree.fragment_roots): a scanned internal node names its children by address and
  generation. A file-tree block that nothing names, walked like a tree, is a *fragment*: a tree
  version written within a transaction and replaced before its commit, or one whose root tree
  is lost. Its blocks were written at different moments of that transaction; it was never a
  committed state, and its artifacts say so.
- `sibling` (`continue_file`): the last file of a lone leaf continues in another leaf of the same
  tree, when that leaf's first key belongs to the same inode, head and tail cover the file
  exactly, and the file's newest extent item was written in the transaction of the INODE_ITEM's
  last change (`generation` equals `transid`). The same leaf boundary exists in many versions of
  a tree, so there are usually many candidate tails; an older one with the right size would
  otherwise pass for the file's content when the right one is lost.
- `parent_path` (`ancestors`): the name of a parent directory is taken from other leaves of the
  same tree when that inode number has exactly one name there.
"""

import sqlite3
from dataclasses import dataclass

from btrfska.catalog.schema import key_sort, s64, u64
from btrfska.recover.dbtree import Leaf, leaf_by_content
from btrfska.recover.inodes import MAX_DEPTH, ROOT_DIR, InodeRecord, Name, collect
from btrfska.substrate import items, ondisk

K = ondisk.ITEM_KEYS
MAX_CHAIN = 64  # leaves one file may be followed through
MAX_CANDIDATES = 256  # tails examined per step; more than that is reported, not searched
UNCOMMITTED = (
    "no ROOT_ITEM and no superblock slot names this tree version: it was written within a "
    "transaction and replaced before the commit, or its root tree is lost; its blocks were "
    "written at different moments of that transaction, and it was never a committed state"
)


def pointer_join(bytenr: int, generation: int, level: int, leaves: int, gaps: int) -> dict:
    """The join record every artifact of a fragment carries."""
    return {
        "kind": "pointer",
        "fragment_root": bytenr,
        "generation": generation,
        "level": level,
        "leaves": leaves,
        "gaps": gaps,
        "evidence": "each block is named by the key pointer of its parent: address, "
        "generation, level and first key. " + UNCOMMITTED,
    }


def _coverage(record: InodeRecord, sectorsize: int) -> tuple[int, str | None]:
    """(end of the contiguous cover from offset 0, why it is not exact or None)."""
    size, end = record.inode["size"], 0
    for item, _ in sorted(record.extents, key=lambda pair: pair[0].key.offset):
        try:
            extent = items.file_extent(item.data)
        except items.ItemError as exc:
            return end, f"an extent item does not parse: {exc}"
        inline = extent["type"] == ondisk.FILE_EXTENT_INLINE
        length = min(extent["ram_bytes"], sectorsize) if inline else extent["num_bytes"]
        if item.key.offset != end:
            kind = "overlap" if item.key.offset < end else "gap"
            return end, f"{kind} at file offset {min(end, item.key.offset)}"
        if extent["generation"] > record.inode["transid"]:
            return end, (
                f"the extent at file offset {item.key.offset} (generation {extent['generation']}) "
                f"is newer than the INODE_ITEM (transid {record.inode['transid']})"
            )
        end += length
    if end < size:
        return end, f"the extents end at {end}, the file has {size} bytes"
    if end >= size + sectorsize or (end > size and end % sectorsize):
        return end, f"the extents end at {end}, past the file's {size} bytes"
    return end, None


def _newest_extent(record: InodeRecord) -> int:
    return max(
        (items.file_extent(item.data)["generation"] for item, _ in record.extents), default=0
    )


@dataclass
class _Step:
    leaves: tuple[Leaf, ...]
    record: InodeRecord
    last: bytes  # key_sort of the last key of the chain so far


def _merge(record: InodeRecord, more: InodeRecord) -> InodeRecord:
    return InodeRecord(
        record.objectid, record.inode, record.names + more.names, record.xattrs + more.xattrs,
        record.extents + more.extents, record.origins + more.origins, record.encrypted_name,
        record.orphan_item, record.problems + more.problems,
    )  # fmt: skip


def _tails(conn: sqlite3.Connection, tree_id: int, objectid: int, after: bytes) -> list[int]:
    """Contents of leaves of `tree_id` whose first key is a later key of `objectid`."""
    rows = conn.execute(
        "SELECT DISTINCT c.content_id FROM contents c JOIN content_blocks b USING (content_id)"
        " WHERE c.level = 0 AND c.parsed AND b.owner = ? AND c.first_key > ? AND c.first_key < ?"
        " ORDER BY c.content_id LIMIT ?",
        (s64(tree_id), after, key_sort(objectid + 1, 0, 0), MAX_CANDIDATES + 1),
    ).fetchall()
    return [row[0] for row in rows]


def continue_file(
    conn: sqlite3.Connection, tree_id: int, head: Leaf, record: InodeRecord, sectorsize: int
) -> tuple[InodeRecord | None, dict | str | None]:
    """Follow a file that ends with its leaf into the leaves that continue it.

    Returns (the record with the tail's items, the join) when exactly one continuation covers
    the file; (None, the reason) when a join was looked for and refused; (None, None) when the
    file does not continue (its leaf does not end with it, or it is complete as it is).
    """
    last = conn.execute(
        "SELECT last_key FROM contents WHERE content_id = ?", (head.content_id,)
    ).fetchone()[0]
    if record.kind != "file" or last is None or last[:8] != key_sort(record.objectid, 0, 0)[:8]:
        return None, None
    if _coverage(record, sectorsize)[1] is None and record.names:
        return None, None
    found: dict[tuple, _Step] = {}
    reasons: list[str] = []
    frontier, searched = [_Step((head,), record, bytes(last))], 0
    while frontier:
        step = frontier.pop()
        candidates = _tails(conn, tree_id, record.objectid, step.last)
        if len(candidates) > MAX_CANDIDATES or len(step.leaves) > MAX_CHAIN:
            return None, "more continuation candidates than are searched; not joined"
        for content_id in candidates:
            searched += 1
            leaf = leaf_by_content(conn, content_id)
            if leaf is None or any(leaf.content_id == seen.content_id for seen in step.leaves):
                continue
            more = collect(conn, [leaf]).get(record.objectid)
            if more is None or more.inode is not None or more.problems:
                reasons.append(f"leaf {leaf.bytenr}: holds another INODE_ITEM or unparsable items")
                continue
            joined = _merge(step.record, more)
            tail_last = conn.execute(
                "SELECT last_key FROM contents WHERE content_id = ?", (content_id,)
            ).fetchone()[0]
            _, problem = _coverage(joined, sectorsize)
            if (
                problem is None
                and more.extents
                and (_newest_extent(joined) != record.inode["transid"])
            ):
                problem = (
                    f"its newest extent (generation {_newest_extent(joined)}) is older than the "
                    f"INODE_ITEM's last change (transid {record.inode['transid']}): a later "
                    "rewrite whose leaf is lost cannot be excluded"
                )
            if problem is None:
                signature = tuple(
                    (item.key.type, item.key.offset, bytes(item.data))
                    for item, _ in sorted(joined.extents, key=lambda p: p[0].key.offset)
                ) + tuple((n.parent, n.name, n.index) for n in joined.names)
                best = found.get(signature)
                if best is None or _closer(leaf, best.leaves[-1], head):
                    found[signature] = _Step((*step.leaves, leaf), joined, bytes(tail_last))
            elif (
                problem.startswith("the extents end at")
                and "the file has" in problem
                and (bytes(tail_last)[:8] == key_sort(record.objectid, 0, 0)[:8])
            ):
                frontier.append(_Step((*step.leaves, leaf), joined, bytes(tail_last)))
            else:
                reasons.append(f"leaf {leaf.bytenr} generation {leaf.generation}: {problem}")
    if len(found) > 1:
        options = "; ".join(
            " + ".join(f"{leaf.bytenr}@{leaf.generation}" for leaf in step.leaves[1:])
            for step in found.values()
        )
        return None, f"ambiguous continuation, {len(found)} different candidates ({options})"
    if not found:
        if not searched:
            return None, "no scanned leaf of this tree continues the file"
        return None, "no leaf continues the file exactly: " + "; ".join(reasons[:4])
    (step,) = found.values()
    join = {
        "kind": "sibling",
        "objectid": record.objectid,
        "leaves": [{"bytenr": leaf.bytenr, "generation": leaf.generation} for leaf in step.leaves],
        "evidence": "same tree; the next leaf's first key continues this inode; together the "
        "extents cover the file exactly, without gap or overlap; the newest extent was written "
        "in the transaction of the INODE_ITEM's last change; no other scanned leaf continues "
        "the file differently under these rules",
    }
    return step.record, join


def _closer(leaf: Leaf, other: Leaf, head: Leaf) -> bool:
    """Of two tails with identical items: the one nearest in time to the head, older first."""

    def rank(candidate: Leaf) -> tuple[bool, int]:
        return candidate.generation > head.generation, abs(candidate.generation - head.generation)

    return rank(leaf) < rank(other)


def ancestors(
    conn: sqlite3.Connection, tree_id: int, inodes: dict[int, InodeRecord]
) -> tuple[dict[int, Name], dict[int, list[dict]], dict[int, str]]:
    """Names of directories the leaves do not hold, from other leaves of the same tree.

    Returns (names by directory inode, the joins that gave them, by the directory they start
    from, and refusals by directory). A number with two different names, or two creation
    generations, in the scanned leaves of the tree is not resolved.
    """
    names: dict[int, Name] = {}
    joins: dict[int, list[dict]] = {}
    refused: dict[int, str] = {}

    def lookup(objectid: int) -> Name | str:
        rows = conn.execute(
            "SELECT DISTINCT r.parent_objectid, r.name_raw, r.dir_index, r.extended, i.generation,"
            " b.bytenr, b.generation FROM inode_refs r"
            " JOIN content_blocks b ON b.content_id = r.content_id"
            " LEFT JOIN inodes i ON i.content_id = r.content_id AND i.objectid = r.objectid"
            " WHERE r.objectid = ? AND b.owner = ?",
            (s64(objectid), s64(tree_id)),
        ).fetchall()
        if not rows:
            return "no scanned leaf of this tree holds a name for it"
        distinct = {(u64(row[0]), bytes(row[1])) for row in rows}
        created = {u64(row[4]) for row in rows if row[4] is not None}
        if len(distinct) > 1 or len(created) > 1:
            shown = ", ".join(sorted(f"{name!r} in {parent}" for parent, name in distinct)[:4])
            return (
                f"inode {objectid} has {len(distinct)} names and {len(created)} creation "
                f"generations in the scanned leaves of this tree ({shown}): ambiguous"
            )
        parent, name = next(iter(distinct))
        leaves = sorted({(u64(row[5]), u64(row[6])) for row in rows})
        joins.setdefault(objectid, []).append(
            {
                "kind": "parent_path",
                "objectid": objectid,
                "name_hex": name.hex(),
                "parent": parent,
                "leaves": [{"bytenr": b, "generation": g} for b, g in leaves[:8]],
                "evidence": f"the only name inode {objectid} has in the {len(leaves)} scanned "
                "leaves of this tree that hold one",
            }
        )
        return Name(parent, name, u64(rows[0][2]), bool(rows[0][3]))

    wanted = {name.parent for record in inodes.values() for name in record.names[:1]}
    for start in sorted(wanted - inodes.keys() - {ROOT_DIR}):
        current, depth = start, 0
        while current != ROOT_DIR and current not in inodes and current not in names:
            if current in refused or depth >= MAX_DEPTH:
                break
            found = lookup(current)
            if isinstance(found, str):
                refused[current] = found
                break
            names[current] = found
            current, depth = found.parent, depth + 1
    return names, joins, refused


def confirmed_by_dir_index(
    conn: sqlite3.Connection, tree_id: int, parent: int, objectid: int, name: bytes
) -> bool:
    """Whether a DIR_INDEX of `parent` in a leaf of the tree names `objectid` as `name`."""
    row = conn.execute(
        "SELECT 1 FROM dir_entries d JOIN content_blocks b USING (content_id)"
        " WHERE d.kind = 'DIR_INDEX' AND d.dir_objectid = ? AND d.child_objectid = ?"
        " AND d.name_raw = ? AND b.owner = ? LIMIT 1",
        (s64(parent), s64(objectid), name, s64(tree_id)),
    ).fetchone()
    return row is not None
