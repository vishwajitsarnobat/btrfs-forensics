"""Confidence tiers of recovered artifacts, from named evidence rules (plan.md M6c).

A tier answers two questions about an artifact, each from evidence the recovery already holds.
*Is it tied to a committed state?* Yes when a walk down from a committed root tree reached it
(every block through its parent's checked key pointer), or, for a lone leaf, a fragment or a log
tree, when every data extent it read from disk matched the csum tree of a cataloged state whose
extent tree gives that extent to this inode (`backref_attributed`). *Is its content proven?* Yes
when its data checksum matched in its own state's csum tree (a log tree's own items) or in one
whose extent tree gives the extent to this inode, or when it has no data on disk, so that its
content lies in leaves whose checksum verified. Decoding never counts: a compressed extent's
checksum covers its bytes on disk, an inline extent's the leaf.

Any contradiction (a failed check) gives `unattached`; tied and proven `confirmed`; one of the
two `probable`; neither `unattached`. `decide` is a pure function of an `Evidence`, so every
rule can be tested on a forged record; `Backrefs` answers the back-reference question from the
evidence database. README.md and docs/evidence-db.md give the rule table with the reason for
each rule.
"""

import sqlite3
from dataclasses import dataclass, field

from btrfska.catalog.schema import s64, u64
from btrfska.recover.dbtree import Root, tree_leaves
from btrfska.substrate import ondisk

TIERS = ("confirmed", "probable", "unattached")
# Every rule, in the order of the table in README.md and docs/evidence-db.md.
RULES = (
    "blocks_validated", "block_not_validated", "anchored", "backref_attributed", "not_committed",
    "csum_match", "content_in_leaf", "csum_match_unattributed", "csum_partial_match",
    "csum_unavailable", "csum_no_csum", "csum_not_checked", "not_complete", "no_inode_item",
    "backref_agrees", "backref_unknown", "backref_disagrees", "generation_owner_consistent",
    "generation_inconsistent", "owner_inconsistent", "inode_item_older_than_extent",
    "csum_mismatch", "duplicate",
)  # fmt: skip
CONTRADICTIONS = frozenset({
    "block_not_validated", "backref_disagrees", "generation_inconsistent", "owner_inconsistent",
    "inode_item_older_than_extent", "csum_mismatch",
})  # fmt: skip
UNPROVEN = {
    "partial_match": "csum_partial_match", "unavailable": "csum_unavailable",
    "no_csum": "csum_no_csum", None: "csum_not_checked",
}  # fmt: skip
EXTENT_TREE = ondisk.EXTENT_TREE_OBJECTID
K = ondisk.ITEM_KEYS


@dataclass(frozen=True)
class ExtentEvidence:
    """One data extent the artifact read from disk: its data-checksum verdict, the csum trees
    that decided it, and per state asked (by its name) whether that state's extent tree gives
    the extent to this inode: `agrees`, `disagrees` or `unknown`."""

    verdict: str | None
    sources: tuple[str, ...] = ()
    backrefs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """What the rules read about one artifact.

    `anchored`: reached from a committed root tree. `own`: the name of the csum tree that is the
    artifact's own (its state's, or its log tree's), None for a lone leaf or a fragment;
    `own_state`: its state's name, whose extent tree is asked for `backref_*`. `content_read`:
    every byte of its content was read. `extents`: its data extents read from disk.
    `generation_problems`, `owner_problems`: what the consistency checks found."""

    anchored: bool
    validated: bool = True
    own: str | None = None
    own_state: str | None = None
    has_inode: bool = True
    content_read: bool = True
    csum_verdict: str | None = None
    extents: tuple[ExtentEvidence, ...] = ()
    generation_problems: tuple[str, ...] = ()
    owner_problems: tuple[str, ...] = ()
    inode_older: bool = False


def _vouched(extent: ExtentEvidence, own: str | None) -> bool:
    """Every tree that decided the extent is the artifact's own, or a state whose extent tree
    gives the extent to this inode."""
    return bool(extent.sources) and all(
        source == own or extent.backrefs.get(source) == "agrees" for source in extent.sources
    )


def decide(evidence: Evidence) -> tuple[str, list[str]]:
    """(tier, the rules that fired, in table order) for one artifact (plan.md M6c)."""
    fired = []
    fired.append("blocks_validated" if evidence.validated else "block_not_validated")
    extents = evidence.extents
    if evidence.anchored:
        tied = True
        fired.append("anchored")
    elif extents and all(
        e.verdict == "match" and _vouched(e, None) for e in extents
    ):  # a lone leaf, fragment or log tree whose every data extent a committed state vouches for
        tied = True
        fired.append("backref_attributed")
    else:
        tied = False
        fired.append("not_committed")

    proof = None
    if evidence.csum_verdict == "mismatch":
        fired.append("csum_mismatch")
    elif not extents:
        proof = "content_in_leaf"
    elif evidence.csum_verdict == "match":
        own = evidence.own
        proof = "csum_match" if all(_vouched(e, own) for e in extents) else None
        if proof is None:
            fired.append("csum_match_unattributed")
    else:
        fired.append(UNPROVEN.get(evidence.csum_verdict, "csum_not_checked"))
    if not evidence.content_read:
        fired.append("not_complete")
        proof = None
    if not evidence.has_inode:
        fired.append("no_inode_item")
        proof = None
    if proof is not None:
        fired.append(proof)

    if evidence.anchored and extents:
        own_refs = [e.backrefs.get(evidence.own_state, "unknown") for e in extents]
        if "disagrees" in own_refs:
            fired.append("backref_disagrees")
        elif all(v == "agrees" for v in own_refs):
            fired.append("backref_agrees")
        else:
            fired.append("backref_unknown")
    if evidence.generation_problems:
        fired.append("generation_inconsistent")
    if evidence.owner_problems:
        fired.append("owner_inconsistent")
    if not evidence.generation_problems and not evidence.owner_problems:
        fired.append("generation_owner_consistent")
    if evidence.inode_older:
        fired.append("inode_item_older_than_extent")

    fired.sort(key=RULES.index)
    if CONTRADICTIONS.intersection(fired):
        return "unattached", fired
    proven = proof is not None
    if tied and proven:
        return "confirmed", fired
    return ("probable" if tied or proven else "unattached"), fired


class Backrefs:
    """Whether the extent tree of a cataloged state gives a data extent to an inode, each state's
    extent tree walked once in the database (`dbtree`)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.trees: dict[int, tuple[frozenset[int], bool] | None] = {}  # leaves, walked whole
        self._cache: dict[tuple[int, int, int, int], str] = {}

    def tree(self, state_id: int) -> tuple[frozenset[int], bool] | None:
        """(content ids of the leaves, walked without a gap) of the state's extent tree; None
        when the state names none."""
        if state_id not in self.trees:
            row = self.conn.execute(
                "SELECT bytenr, generation, level FROM state_trees WHERE state_id = ?"
                " AND tree_id = ? ORDER BY key_offset DESC LIMIT 1",
                (state_id, EXTENT_TREE),
            ).fetchone()
            if row is None:
                self.trees[state_id] = None
            else:
                root = Root(f"state:{state_id}", state_id, EXTENT_TREE, u64(row[0]), u64(row[1]),
                            row[2])  # fmt: skip
                leaves, gaps = tree_leaves(self.conn, root)
                self.trees[state_id] = (frozenset(leaf.content_id for leaf in leaves), not gaps)
        return self.trees[state_id]

    def _parent_holds(self, parent: int, objectid: int, bytenr: int) -> bool:
        """Whether a valid leaf at `parent` has an EXTENT_DATA of inode `objectid` pointing at
        `bytenr` (the leaf a SHARED_DATA_REF names, extent-tree.c:2575-2578)."""
        return (
            self.conn.execute(
                "SELECT 1 FROM file_extents f JOIN content_blocks b USING (content_id)"
                " WHERE b.bytenr = ? AND f.objectid = ? AND f.disk_bytenr = ? LIMIT 1",
                (parent, s64(objectid), s64(bytenr)),
            ).fetchone()
            is not None
        )

    def check(self, state_id: int, bytenr: int, length: int, objectid: int) -> str:
        """`agrees` when the state's extent tree has a data extent at `bytenr` of `length` that
        an EXTENT_DATA_REF gives to inode `objectid` (of any tree: a snapshot's copy of a file
        shares its extents), or a SHARED_DATA_REF through a leaf holding the file extent;
        `disagrees` when it has not and the tree was walked without a gap; else `unknown`."""
        key = (state_id, bytenr, length, objectid)
        if key in self._cache:
            return self._cache[key]
        tree = self.tree(state_id)
        verdict = "unknown"
        if tree is not None:
            held, complete = tree
            extent = any(
                content_id in held and num_bytes is not None and u64(num_bytes) == length
                and not tree_block
                for content_id, num_bytes, tree_block in self.conn.execute(
                    "SELECT content_id, num_bytes, tree_block FROM extents WHERE bytenr = ?",
                    (s64(bytenr),),
                )
            )  # fmt: skip
            agrees = extent and any(
                content_id in held
                and (
                    (ref_type == K["EXTENT_DATA_REF"] and u64(ref_objectid) == objectid)
                    or (ref_type == K["SHARED_DATA_REF"] and parent is not None
                        and self._parent_holds(parent, objectid, bytenr))
                )
                for content_id, ref_type, ref_objectid, parent in self.conn.execute(
                    "SELECT content_id, ref_type, objectid, parent FROM extent_backrefs"
                    " WHERE extent_bytenr = ?",
                    (s64(bytenr),),
                )
            )  # fmt: skip
            verdict = "agrees" if agrees else ("disagrees" if complete else "unknown")
        self._cache[key] = verdict
        return verdict
