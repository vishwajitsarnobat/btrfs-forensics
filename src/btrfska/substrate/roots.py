"""Root sets (the current superblock state and each backup root), tree resolution, subvolumes.

A `RootSet` is one committed state: the superblock's own roots ("current") or one backup root
slot ("backup:GEN"). Backup sets are ordered by generation, never by slot, because the slots form a
ring (disk-io.c:1596-1607). Trees resolve as follows:
- "root" and "chunk": the superblock fields (current) or the slot fields (backup);
- "extent", "fs", "dev" and "csum" in a backup set: the slot fields, which the superblock
  checksum covers;
- a numeric tree id, or those names in the current set: the ROOT_ITEM with that objectid and the
  highest key offset in the set's root tree. For a backup set, resolving a slot tree by id
  anchors it a second time.

Subvolumes (ids for which node.is_subvolume_tree holds) come from a set's root tree. ROOT_ITEM
gives the tree. ROOT_BACKREF (child 144 parent) and ROOT_REF (parent 156 child) give name, parent
and directory, and each must have its counterpart.
"""

import re
import uuid
from dataclasses import dataclass

from btrfska.substrate import items, ondisk, superblock
from btrfska.substrate.node import Expect, NodeReader, is_subvolume_tree
from btrfska.substrate.tree import walk

K = ondisk.ITEM_KEYS
TREE_IDS = {
    "root": ondisk.ROOT_TREE_OBJECTID,
    "extent": ondisk.EXTENT_TREE_OBJECTID,
    "chunk": ondisk.CHUNK_TREE_OBJECTID,
    "dev": ondisk.DEV_TREE_OBJECTID,
    "fs": ondisk.FS_TREE_OBJECTID,
    "csum": ondisk.CSUM_TREE_OBJECTID,
}
_SLOT_FIELDS = {name: f"{'tree' if name == 'root' else name}_root" for name in TREE_IDS}
_SPEC = re.compile(r"current|(backup|bytenr):(\d+)")


class RootNotFound(LookupError):
    """The requested root set or tree does not exist in this image."""


@dataclass(frozen=True)
class TreeRoot:
    tree_id: int
    bytenr: int
    level: int | None
    generation: int | None
    via: str  # the anchor: "superblock", "backup slot N" or the ROOT_ITEM it came from

    def expect(self) -> Expect:
        return Expect(level=self.level, owner=self.tree_id, generation=self.generation)


@dataclass(frozen=True)
class RootSet:
    source: str  # "current" or "backup:GEN"
    generation: int
    slot: int | None
    trees: dict[str, TreeRoot]


@dataclass(frozen=True)
class Subvolume:
    id: int
    root: TreeRoot | None  # None when refs exist without a ROOT_ITEM
    name: str | None
    parent: int | None
    dirid: int | None
    readonly: bool
    uuid: str | None
    parent_uuid: str | None
    otransid: int | None
    ctransid: int | None
    problems: tuple[str, ...] = ()


def parse_root_spec(spec: str) -> tuple[str, int | None]:
    """'current' -> ('current', None); 'backup:GEN' and 'bytenr:N' -> (kind, number)."""
    match = _SPEC.fullmatch(spec)
    if match is None:
        raise ValueError(f"invalid root {spec!r}: expected current, backup:GEN or bytenr:N")
    if spec == "current":
        return "current", None
    return match[1], int(match[2])


def root_sets(fields: dict) -> list[RootSet]:
    """Backup sets by generation (empty slots skipped), then the current set."""
    sets = []
    for backup in superblock.backup_roots(fields):
        if not backup["tree_root"]:
            continue
        via = f"backup slot {backup['slot']}"
        trees = {
            name: TreeRoot(
                TREE_IDS[name], backup[slot_field], backup[f"{slot_field}_level"],
                backup[f"{slot_field}_gen"], via,
            )
            for name, slot_field in _SLOT_FIELDS.items()
        }  # fmt: skip
        generation = backup["tree_root_gen"]
        sets.append(RootSet(f"backup:{generation}", generation, backup["slot"], trees))
    current = {
        "root": TreeRoot(
            ondisk.ROOT_TREE_OBJECTID, fields["root"], fields["root_level"], fields["generation"],
            "superblock",
        ),
        "chunk": TreeRoot(
            ondisk.CHUNK_TREE_OBJECTID, fields["chunk_root"], fields["chunk_root_level"],
            fields["chunk_root_generation"], "superblock",
        ),
    }  # fmt: skip
    sets.append(RootSet("current", fields["generation"], None, current))
    return sets


def find_root_set(fields: dict, spec: str) -> RootSet:
    kind, generation = parse_root_spec(spec)
    if kind == "bytenr":
        raise ValueError("a bytenr root is a single block, not a root set")
    sets = root_sets(fields)
    if kind == "current":
        return sets[-1]
    for root_set in sets[:-1]:
        if root_set.generation == generation:
            return root_set
    have = ", ".join(str(s.generation) for s in sets[:-1])
    raise RootNotFound(f"no backup root with generation {generation} (have {have})")


def _root_items(reader: NodeReader, root: TreeRoot):
    """(item, leaf bytenr) for every ROOT_ITEM, ROOT_REF and ROOT_BACKREF, plus walk problems."""
    found, problems = [], []
    wanted = (K["ROOT_ITEM"], K["ROOT_REF"], K["ROOT_BACKREF"])
    for visit in walk(reader, root.bytenr, root.expect()):
        node = visit.node
        if not node.valid:
            problems.append(f"root tree node {node.logical} is invalid: {'; '.join(node.problems)}")
            continue
        problems += [f"root tree node {node.logical}: {p}" for p in visit.problems]
        if node.level == 0:
            found += [(item, node.logical) for item in node.items if item.key.type in wanted]
    return found, problems


def _tree_root_from_item(item, leaf: int, root: TreeRoot) -> TreeRoot:
    parsed = items.root_item(item.data)
    via = f"ROOT_ITEM {item.key} in root tree {root.bytenr} leaf {leaf} slot {item.slot}"
    return TreeRoot(item.key.objectid, parsed["bytenr"], parsed["level"], parsed["generation"], via)


def resolve_tree(reader: NodeReader, root_set: RootSet, tree: str | int) -> TreeRoot:
    """The root of `tree` (a name or a numeric tree id) in `root_set`; see the module docstring."""
    if isinstance(tree, str):
        if tree in root_set.trees:
            return root_set.trees[tree]
        if tree not in TREE_IDS:
            raise ValueError(f"unknown tree {tree!r}: expected {', '.join(TREE_IDS)} or a tree id")
        tree = TREE_IDS[tree]
    if tree == ondisk.ROOT_TREE_OBJECTID:
        return root_set.trees["root"]
    if tree == ondisk.CHUNK_TREE_OBJECTID:
        return root_set.trees["chunk"]
    root = root_set.trees["root"]
    found, problems = _root_items(reader, root)
    candidates = [
        (item, leaf)
        for item, leaf in found
        if item.key.objectid == tree and item.key.type == K["ROOT_ITEM"]
    ]
    if not candidates:
        detail = f"; {'; '.join(problems)}" if problems else ""
        raise RootNotFound(
            f"no ROOT_ITEM for tree {tree} in root tree {root.bytenr} ({root_set.source}){detail}"
        )
    item, leaf = max(candidates, key=lambda pair: pair[0].key.offset)
    try:
        return _tree_root_from_item(item, leaf, root)
    except items.ItemError as exc:
        raise RootNotFound(f"ROOT_ITEM {item.key} in leaf {leaf} is malformed: {exc}") from None


def _optional_uuid(fields: dict | None, name: str) -> str | None:
    raw = (fields or {}).get(name)
    return str(uuid.UUID(bytes=raw)) if raw and any(raw) else None


def subvolumes(reader: NodeReader, root_set: RootSet) -> tuple[list[Subvolume], tuple[str, ...]]:
    """Subvolumes of `root_set`, by id, and the problems met while walking its root tree."""
    root = root_set.trees["root"]
    found, problems = _root_items(reader, root)
    root_items, refs, backrefs = {}, {}, {}
    for item, leaf in found:
        key = item.key
        try:
            if key.type == K["ROOT_ITEM"] and is_subvolume_tree(key.objectid):
                previous = root_items.get(key.objectid)
                if previous is None or key.offset > previous[0].key.offset:
                    root_items[key.objectid] = (item, leaf, items.root_item(item.data))
            elif key.type == K["ROOT_REF"]:
                refs[(key.objectid, key.offset)] = items.root_ref(item.data)
            elif key.type == K["ROOT_BACKREF"]:
                backrefs[(key.objectid, key.offset)] = items.root_ref(item.data)
        except items.ItemError as exc:
            problems.append(f"{key} in leaf {leaf}: {exc}")

    ids = set(root_items) | {child for child, _ in backrefs} | {child for _, child in refs}
    result = []
    for subvol in sorted(ids):
        own = []
        tree_root = fields = None
        if subvol in root_items:
            item, leaf, fields = root_items[subvol]
            tree_root = _tree_root_from_item(item, leaf, root)
        else:
            own.append("ROOT_REF or ROOT_BACKREF without a ROOT_ITEM")
        parents = sorted(parent for child, parent in backrefs if child == subvol)
        name = parent = dirid = None
        if parents:
            parent = parents[0]
            ref = backrefs[(subvol, parent)]
            name, dirid = ref["name"], ref["dirid"]
            if len(parents) > 1:
                own.append(f"{len(parents)} ROOT_BACKREFs (parents {parents})")
            for other in parents:
                if refs.get((other, subvol)) != backrefs[(subvol, other)]:
                    own.append(f"ROOT_BACKREF ({subvol} 144 {other}) has no matching ROOT_REF")
        elif subvol != ondisk.FS_TREE_OBJECTID:
            own.append("no ROOT_BACKREF")
        for other, child in refs:
            if child == subvol and (subvol, other) not in backrefs:
                own.append(f"ROOT_REF ({other} 156 {subvol}) has no matching ROOT_BACKREF")
        has_uuids = fields is not None and "uuid" in fields
        result.append(
            Subvolume(
                id=subvol,
                root=tree_root,
                name=name,
                parent=parent,
                dirid=dirid,
                readonly=bool(fields and fields["flags"] & items.ROOT_SUBVOL_RDONLY),
                uuid=_optional_uuid(fields, "uuid"),
                parent_uuid=_optional_uuid(fields, "parent_uuid"),
                otransid=fields["otransid"] if has_uuids else None,
                ctransid=fields["ctransid"] if has_uuids else None,
                problems=tuple(own),
            )
        )
    return result, tuple(problems)
