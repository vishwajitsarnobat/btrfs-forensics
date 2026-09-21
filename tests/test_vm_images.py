"""M1 corpus images (corpus/manifest.tsv). Skipped when an image has not been generated locally."""

import csv
import json
import re
import shutil
import subprocess
import uuid

import pytest

from btrfska.cli import main
from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.chunks import STRIPE_LEN, type_name
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.roots import find_root_set, resolve_tree, root_sets, subvolumes
from btrfska.substrate.tree import IncompleteTree, fs_tree_inventory, leaf_items, walk
from tests.helpers import REPO_ROOT, SCENARIOS, scratch_dir

pytestmark = pytest.mark.vm

MANIFEST = REPO_ROOT / "corpus" / "manifest.tsv"
# name -> (csum type, block-group tree expected)
HEALTHY = {
    "m1_xxhash": (csum.XXHASH, False),
    "m1_sha256_bgt": (csum.SHA256, True),
    "m1_blake2b": (csum.BLAKE2, False),
    "m1_lzo": (csum.XXHASH, False),
    "m1_zlib": (csum.XXHASH, False),
}


def image(name: str):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: regenerate it with the corpus/manifest.tsv command")
    return path


def read(name: str) -> sb.Selection:
    with open_image(image(name)) as img:
        return sb.read_superblock(img)


def manifest_rows() -> dict[str, dict]:
    with MANIFEST.open(newline="") as f:
        return {row["name"]: row for row in csv.DictReader(f, delimiter="\t")}


def build_record() -> dict[str, str]:
    """images/scenarios/SHA256SUMS, written by corpus/build.py: file name -> sha256 as built."""
    path = SCENARIOS / "SHA256SUMS"
    if not path.exists():
        return {}
    lines = (line.split(maxsplit=1) for line in path.read_text().splitlines() if line.strip())
    return {name.strip().removeprefix("*"): digest for digest, name in lines}


def assert_unchanged_since_built(path) -> None:
    """The image still has the hash recorded when it was built; skip when it has no record."""
    recorded = build_record().get(path.name)
    if recorded is None:
        pytest.skip(f"{path.name} has no build record: build it with corpus/build.py")
    with open_image(path) as img:
        assert img.sha256() == recorded, f"{path.name} was modified after it was built"


DERIVED = [
    "m1_unknown_incompat",
    "m1_mirror_damage",
    "m1_foreign_mirror",
    "m1_badnode",
    "m1_badnode_both",
]


M2 = ["m2_logtree"]
M3 = ["m3_wide"]
M4 = ["m4_planted_slack", "m4_deep", "m4_deep_lost_parent"]


def test_manifest_lists_every_m1_and_m2_image():
    rows = manifest_rows()
    for name in [*HEALTHY, *DERIVED, *M2, *M3, *M4]:
        assert name in rows
        assert rows[name]["command"]
        # The manifest is a recipe: an image's bytes differ on every build (new filesystem UUID),
        # so it records no hash. corpus/build.py records the hashes of what was built locally.
        assert "sha256" not in rows[name]


@pytest.mark.parametrize("name", [*HEALTHY, *DERIVED, *M2, *M3, *M4])
def test_local_image_is_unchanged_since_it_was_built(name):
    assert_unchanged_since_built(image(name))


@pytest.mark.parametrize("name", HEALTHY)
def test_superblock_csum_validates_on_every_copy(name):
    csum_type, bgt = HEALTHY[name]
    selection = read(name)
    assert [(c.present, c.valid) for c in selection.copies] == [
        (True, True),
        (True, True),
        (False, False),
    ]
    assert selection.selected.mirror == 0
    assert selection.disagreements == []
    fields = selection.selected.fields
    assert fields["csum_type"] == csum_type
    verdict = sb.gate(fields)
    assert verdict.status == "OK"
    assert verdict.block_group_tree is bgt
    assert len({r["tree_root_gen"] for r in sb.backup_roots(fields)}) == 4


@pytest.mark.parametrize("name", ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_foreign_mirror"])
def test_superblock_csums_agree_with_dump_super(name):
    """Independent oracle: btrfs-progs computes and prints the same csum with [match]."""
    if shutil.which("btrfs") is None:
        pytest.skip("btrfs-progs not installed")
    out = subprocess.run(
        ["btrfs", "inspect-internal", "dump-super", "-a", str(image(name))],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    printed = re.findall(r"^csum\s+0x([0-9a-f]+) \[match\]$", out, re.MULTILINE)
    ours = []
    for copy in read(name).copies:
        if copy.present:
            size = csum.csum_size(copy.fields["csum_type"])
            ours.append(copy.fields["csum"][:size].hex())
    assert printed == ours


def test_unknown_incompat_image_is_refused(capsys):
    path = image("m1_unknown_incompat")
    selection = read("m1_unknown_incompat")
    assert all(c.valid for c in selection.copies if c.present)
    assert selection.selected.fields["incompat_flags"] & (1 << 40)
    assert main(["info", str(path)]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert "gate: REFUSED" in lines
    assert "UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40" in lines
    assert main(["info", "--allow-unsupported", str(path)]) == 0


def test_mirror_damage_image_selects_mirror_1_and_reports_it(capsys):
    path = image("m1_mirror_damage")
    selection = read("m1_mirror_damage")
    assert selection.selected.mirror == 1
    assert selection.disagreements == ["mirror 0 invalid: magic mismatch, csum mismatch"]
    assert main(["info", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    generation = selection.selected.fields["generation"]
    assert f"selected: mirror 1 (generation {generation})" in lines
    assert "  mirror 0 invalid: magic mismatch, csum mismatch" in lines
    assert "kernel would mount: mirror 0 (invalid: magic mismatch, csum mismatch)" in lines


def test_foreign_mirror_image_keeps_the_primary_and_reports_the_residue(capsys):
    """Mirror 1 holds m1_sha256_bgt's copy at generation 1000 (sha256 csum, other fsid)."""
    path = image("m1_foreign_mirror")
    selection = read("m1_foreign_mirror")
    primary, mirror1 = selection.copies[0], selection.copies[1]
    assert primary.valid and mirror1.valid
    assert mirror1.fields["generation"] == 1000 > primary.fields["generation"]
    assert mirror1.fields["csum_type"] == csum.SHA256
    assert mirror1.fields["fsid"] != primary.fields["fsid"]
    assert selection.selected is primary
    assert selection.foreign == [mirror1]
    assert main(["info", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    foreign_fsid = str(uuid.UUID(bytes=mirror1.fields["fsid"]))
    assert f"selected: mirror 0 (generation {primary.fields['generation']})" in lines
    assert (
        f"  mirror 1 foreign superblock at 67108864 (fsid {foreign_fsid}, generation 1000)" in lines
    )
    assert f"fsid: {uuid.UUID(bytes=primary.fields['fsid'])}" in lines
    assert not any(line.startswith("kernel would mount") for line in lines)


# ---------------------------------------------------------------------------
# M1b: chunk maps, anchored walks, subvolume history, corrupt tree-block copies
# ---------------------------------------------------------------------------
CSUM_IMAGES = ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b"]
# m1_xxhash: subvolume 256's only leaf (ROOT_ITEM gen 34 in every root set) and its two DUP
# copies (METADATA|DUP chunk 63963136, stripes at 105906176 and 173015040).
SV1_LEAF = 65159168
SV1_COPIES = (107102208, 174211072)
SV1_ITEMS = 37
BALANCE_OBJECTID = (1 << 64) - 4  # btrfs_tree.h BTRFS_BALANCE_OBJECTID
NODE_LINE = re.compile(
    r"^(?:leaf|node) (\d+) (?:level \d+ )?items (\d+) free space \d+ generation (\d+) owner",
    re.MULTILINE,
)


def source(name: str):
    return REPO_ROOT / "sandbox.img" if name == "sandbox" else image(name)


def need_btrfs():
    if shutil.which("btrfs") is None:
        pytest.skip("btrfs-progs not installed")


@pytest.fixture(scope="module")
def readonly_copy():
    """btrfs-progs only ever reads 0444 copies under images/scratch/, never the images."""
    made = {}
    with scratch_dir("test_vm_ro_") as d:

        def copy(name: str):
            if name not in made:
                path = source(name)
                if not path.exists():
                    pytest.skip(f"{path.name} absent")
                target = d / f"{name}.img"
                subprocess.run(["cp", "--sparse=always", str(path), str(target)], check=True)
                target.chmod(0o444)
                made[name] = target
            return made[name]

        yield copy


def dump_tree(path, *args) -> subprocess.CompletedProcess:
    command = ["btrfs", "inspect-internal", "dump-tree", *args, str(path)]
    return subprocess.run(command, capture_output=True, text=True, check=False)


def dump_tree_chunks(text: str) -> list[dict]:
    chunks, current = [], None
    for line in text.splitlines():
        if match := re.search(r"CHUNK_ITEM (\d+)\)", line):
            current = {"logical": int(match[1]), "stripes": []}
            chunks.append(current)
        elif current is None:
            continue
        elif match := re.match(r"\s+length (\d+) owner \d+ stripe_len (\d+) type (\S+)", line):
            current |= {"length": int(match[1]), "stripe_len": int(match[2]), "type": match[3]}
        elif match := re.match(r"\s+num_stripes (\d+) sub_stripes (\d+)", line):
            current |= {"num_stripes": int(match[1]), "sub_stripes": int(match[2])}
        elif match := re.match(r"\s+stripe \d+ devid (\d+) offset (\d+)", line):
            current["stripes"].append([int(match[1]), int(match[2])])
    return chunks


@pytest.mark.parametrize("name", ["sandbox", *CSUM_IMAGES])
def test_chunk_map_matches_dump_tree(name, readonly_copy):
    need_btrfs()
    expected = dump_tree_chunks(dump_tree(readonly_copy(name), "-t", "chunk").stdout)
    with open_image(source(name)) as img:
        chunk_map = open_filesystem(img).chunk_map
    assert chunk_map.source == "current" and chunk_map.problems == ()
    ours = [
        {
            "logical": c.logical,
            "stripes": [[s.devid, s.offset] for s in c.stripes],
            "length": c.length,
            "stripe_len": STRIPE_LEN,
            "type": type_name(c.type),
            "num_stripes": c.num_stripes,
            "sub_stripes": c.sub_stripes,
        }
        for c in chunk_map.chunks
    ]
    assert ours == expected and len(ours) == 3
    for chunk in chunk_map.chunks:  # translation of an address inside each chunk, every stripe
        copies = chunk_map.copies(chunk.logical + 12345, 1)
        assert [c.physical for c in copies] == [s.offset + 12345 for s in chunk.stripes]


def tree_roots(fs, root_set) -> dict:
    """A root set's own tree roots plus one per ROOT_ITEM in its root tree."""
    roots = dict(root_set.trees)
    root = root_set.trees["root"]
    for _, item in leaf_items(walk(fs.reader, root.bytenr, root.expect())):
        if item.key.type == ondisk.ITEM_KEYS["ROOT_ITEM"]:
            roots[item.key.objectid] = resolve_tree(fs.reader, root_set, item.key.objectid)
    return roots


@pytest.mark.parametrize("name", CSUM_IMAGES)
def test_every_node_of_every_root_set_is_csum_valid_on_both_copies(name):
    with open_image(image(name)) as img:
        fs = open_filesystem(img)
        sets = root_sets(fs.fields)
        assert [s.source for s in sets] == [f"backup:{g}" for g in (35, 36, 37, 38)] + ["current"]
        for root_set in sets:
            roots = tree_roots(fs, root_set)
            assert len(roots) >= 11
            for tree_root in roots.values():
                for visit in walk(fs.reader, tree_root.bytenr, tree_root.expect()):
                    node = visit.node
                    where = (root_set.source, tree_root, node.problems, visit.problems)
                    assert node.valid and node.problems == () and visit.problems == (), where
                    csums = [{c.name: c.ok for c in copy.checks}["csum"] for copy in node.copies]
                    assert csums == [True, True], where


@pytest.mark.parametrize("name", CSUM_IMAGES)
def test_walks_match_dump_tree_block_by_block(name, readonly_copy):
    need_btrfs()
    copy = readonly_copy(name)
    compared = set()
    with open_image(image(name)) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            for tree_root in tree_roots(fs, root_set).values():
                if tree_root.bytenr in compared:
                    continue
                compared.add(tree_root.bytenr)
                ours = [
                    (
                        v.node.logical,
                        len(v.node.items) if v.node.level == 0 else len(v.node.key_ptrs),
                        v.node.generation,
                    )
                    for v in walk(fs.reader, tree_root.bytenr, tree_root.expect())
                ]
                out = dump_tree(copy, "-b", str(tree_root.bytenr), "--follow").stdout
                theirs = [tuple(map(int, groups)) for groups in NODE_LINE.findall(out)]
                assert ours == theirs, (root_set.source, tree_root)
    assert len(compared) >= 20


def scenario_sizes() -> dict[str, int]:
    """File sizes written by corpus/vm/scenarios/s01.guest.sh."""

    def seq(n: int) -> int:
        return sum(len(f"{i}\n") for i in range(1, n + 1))

    sizes = {
        "keep.txt": seq(20000),
        "deleted_big.txt": seq(50000),
        "deleted_inline.txt": len("small secret\n"),
    }
    return sizes | {f"churn_{i}": len(f"gen{i}\n") for i in range(1, 7)}


def files(inventory: dict) -> dict[str, int]:
    return {e["name"]: e["size"] for e in inventory.values() if e["kind"] == "file"}


def test_m1_xxhash_subvolume_history_per_generation():
    """sv1 and its snapshot, walked from each backup root's own root tree."""
    sizes = scenario_sizes()
    churn = [f"churn_{i}" for i in range(1, 7)]
    with open_image(image("m1_xxhash")) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):
            found, problems = subvolumes(fs.reader, root_set)
            assert problems == ()
            assert [(s.id, s.name, s.parent, s.readonly, s.problems) for s in found] == [
                (5, None, None, False, ()),
                (256, "sv1", 5, False, ()),
                (257, "snap_before_delete", 5, True, ()),
            ]
            roots = {s.id: s.root for s in found}
            # Identical ROOT_ITEMs in every generation (dump-tree -b <tree_root>).
            assert [(roots[i].bytenr, roots[i].generation) for i in (5, 256, 257)] == [
                (64208896, 19),
                (SV1_LEAF, 34),
                (65126400, 34),
            ]
            assert [s.otransid for s in found[1:]] == [7, 8]
            inventories = {
                i: fs_tree_inventory(fs.reader, roots[i].bytenr, roots[i].expect()) for i in roots
            }
            assert inventories[5][256]["entries"] == {"sv1": 256, "snap_before_delete": 257}
            assert files(inventories[256]) == {n: sizes[n] for n in ["keep.txt", *churn]}
            assert files(inventories[257]) == {
                n: sizes[n] for n in ["keep.txt", "deleted_big.txt", "deleted_inline.txt"]
            }
            # Gens 35-37 still record the running balance; it finished in transaction 38.
            root = root_set.trees["root"]
            keys = {
                (i.key.objectid, i.key.type) for _, i in leaf_items(walk(fs.reader, root.bytenr))
            }
            balance = (BALANCE_OBJECTID, ondisk.ITEM_KEYS["TEMPORARY_ITEM"]) in keys
            assert balance is (root_set.generation < 38), root_set.source


def failed_checks(copy) -> list[str]:
    return [check.name for check in copy.checks if check.ok is False]


def test_badnode_reads_the_good_copy_and_reports_the_corrupt_one(capsys):
    path = image("m1_badnode")
    with open_image(path) as img:
        fs = open_filesystem(img)
        for root_set in root_sets(fs.fields):  # every generation shares the leaf
            root = resolve_tree(fs.reader, root_set, 256)
            node = fs.reader.read(root.bytenr, root.expect())
            assert root.bytenr == SV1_LEAF and node.valid and node.chosen == 1
            assert [(c.mirror, c.physical, c.ok) for c in node.copies] == [
                (1, SV1_COPIES[0], False),
                (2, SV1_COPIES[1], True),
            ]
            assert failed_checks(node.copies[0]) == ["csum"]
            assert len(node.items) == SV1_ITEMS
    assert main(["walk", str(path), "--tree", "256"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["record"] for r in records] == ["item"] * SV1_ITEMS
    copies = records[0]["node"]["copies"]
    assert [
        (c["mirror"], c["physical"], c["used"], c["valid"], c["checks"]["csum"]) for c in copies
    ] == [
        (1, SV1_COPIES[0], False, False, False),
        (2, SV1_COPIES[1], True, True, True),
    ]
    assert records[0]["node"]["problems"][0].startswith("mirror 1: csum: stored ")


def test_badnode_both_reports_a_csum_failure_instead_of_items(capsys):
    path = image("m1_badnode_both")
    with open_image(path) as img:
        fs = open_filesystem(img)
        root = resolve_tree(fs.reader, find_root_set(fs.fields, "backup:35"), 256)
        node = fs.reader.read(root.bytenr, root.expect())
        assert not node.valid and [failed_checks(c) for c in node.copies] == [["csum"], ["csum"]]
        with pytest.raises(IncompleteTree, match=f"node {SV1_LEAF}: mirror 1: csum"):
            fs_tree_inventory(fs.reader, root.bytenr, root.expect())
        snapshot = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), 257)
        assert fs.reader.read(snapshot.bytenr, snapshot.expect()).valid
    assert main(["walk", str(path), "--root", "backup:35", "--tree", "256"]) == 0
    captured = capsys.readouterr()
    (record,) = [json.loads(line) for line in captured.out.splitlines()]
    assert record["record"] == "invalid_node" and "key" not in record
    node_record = record["node"]
    assert (node_record["owner"], node_record["generation"]) == (256, 34)  # header, report only
    assert [(c["used"], c["valid"], c["checks"]["csum"]) for c in node_record["copies"]] == [
        (False, False, False),
        (False, False, False),
    ]
    assert "btrfska walk: 1 nodes (1 invalid), 0 items" in captured.err


@pytest.mark.parametrize(("name", "failures"), [("m1_badnode", 1), ("m1_badnode_both", 2)])
def test_badnode_csum_values_agree_with_dump_tree(name, failures, readonly_copy):
    """btrfs-progs prints 'wanted' (stored) and 'found' (computed) for each bad copy it reads."""
    need_btrfs()
    result = dump_tree(readonly_copy(name), "-b", str(SV1_LEAF))
    printed = re.findall(
        rf"checksum verify failed on {SV1_LEAF} wanted 0x([0-9a-f]+) found 0x([0-9a-f]+)",
        result.stderr,
    )
    with open_image(image(name)) as img:
        node = open_filesystem(img).reader.read(SV1_LEAF)
    ours = [
        tuple(check.detail.split()[1::2])
        for copy in node.copies
        for check in copy.checks
        if check.name == "csum" and check.ok is False
    ]
    assert len(ours) == failures and printed == ours
    if failures == 1:
        assert f"leaf {SV1_LEAF} items {SV1_ITEMS}" in result.stdout  # progs used mirror 2
    else:
        assert f"ERROR: failed to read tree block {SV1_LEAF}" in result.stderr
