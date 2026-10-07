"""M7a corpus matrix images (corpus/matrix.tsv, plan.md M7a): each image has the configuration
its row claims, and its log is a consistent ground truth that agrees with the image.

The matrix tier is built on request (`uv run python corpus/build.py --tier matrix`), not by
./setup.sh or CI, so these tests skip when it is absent. Every claim is read from the image or its
own log; none is a number from one guest run.
"""

import hashlib
import importlib.util

import pytest

from btrfska.substrate import csum, items, ondisk
from btrfska.substrate.chunks import type_name
from btrfska.substrate.extents import read_file
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.roots import find_root_set, resolve_tree, subvolumes
from btrfska.substrate.tree import fs_tree_inventory, leaf_items, walk
from tests.helpers import REPO_ROOT, SCENARIOS
from tests.test_vm_images import assert_unchanged_since_built

pytestmark = pytest.mark.matrix


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"corpus_{name}", REPO_ROOT / "corpus" / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build, matrix, groundtruth = _load("build"), _load("matrix"), _load("groundtruth")
ROWS = {row["name"]: row for row in build.manifest_rows("matrix")}
NOT_BUILT = "matrix tier not built here: uv run python corpus/build.py --tier matrix"
CSUM_TYPES = {"crc32c": csum.CRC32C, "xxhash": csum.XXHASH, "sha256": csum.SHA256,
              "blake2b": csum.BLAKE2}  # fmt: skip
COMPRESSION = {"zlib": 1, "lzo": 2, "zstd": 3}  # BTRFS_COMPRESS_*, compression.h
SIZES = {"256M": 256 << 20, "512M": 512 << 20, "8G": 8 << 30, "100G": 100 << 30}
DATA_TREE = 256  # subvolume `data`, the first subvolume the scenario creates


def image(name: str):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(NOT_BUILT)
    return path


def truth(name: str):
    path = SCENARIOS / f"{name}.log"
    if not path.exists():
        pytest.skip(NOT_BUILT)
    return groundtruth.parse(path.read_text(errors="replace"))


def config(name: str) -> dict[str, str]:
    return matrix.configuration(ROWS[name])


@pytest.mark.parametrize("name", ROWS)
def test_local_image_is_unchanged_since_it_was_built(name):
    path = image(name)
    assert_unchanged_since_built(path)
    if config(name)["LAYOUT"] == "raid1":
        assert_unchanged_since_built(SCENARIOS / f"{name}.dev2.img")


@pytest.mark.parametrize("name", ROWS)
def test_image_has_the_configuration_its_row_claims(name):
    axes = config(name)
    with open_image(image(name)) as img:
        fs = open_filesystem(img)
        fields = fs.fields
        incompat = ondisk.flag_names(fields["incompat_flags"], ondisk.INCOMPAT)
        assert fields["csum_type"] == CSUM_TYPES[axes["CSUM"]]
        assert fs.verdict.block_group_tree is (axes["BGT"] == "on")
        assert ("MIXED_GROUPS" in incompat) is (axes["LAYOUT"] == "mixed")
        devices = 2 if axes["LAYOUT"] == "raid1" else 1
        assert fields["num_devices"] == devices
        assert fields["total_bytes"] == SIZES[axes["SIZE"]] * devices
        if axes["COMPRESS"] in ("lzo", "zstd"):  # the kernel sets the bit on first use
            assert f"COMPRESS_{axes['COMPRESS'].upper()}" in incompat

        profiles = {type_name(chunk.type) for chunk in fs.chunk_map.chunks}
        if axes["LAYOUT"] == "raid1":
            assert profiles == {"DATA|RAID1", "METADATA|RAID1", "SYSTEM|RAID1"}
            # only the second device is missing: this test reads the first
            assert fs.chunk_map.problems
            assert all("devid 2" in problem for problem in fs.chunk_map.problems)
        elif axes["LAYOUT"] == "mixed":
            assert "DATA|METADATA|single" in profiles and not {"DATA|single"} & profiles
            assert fs.chunk_map.problems == ()
        else:
            assert profiles == {"DATA|single", "METADATA|DUP", "SYSTEM|DUP"}
            assert fs.chunk_map.problems == ()

        root_set = find_root_set(fields, "current")
        tree = resolve_tree(fs.reader, root_set, DATA_TREE)
        inventory = fs_tree_inventory(fs.reader, tree.bytenr, tree.expect())
    codes = {e["compression"] for inode in inventory.values() for e in inode.get("extents", ())}
    if axes["COMPRESS"] == "none":
        assert codes == {0}
    else:  # random bytes do not compress and stay plain; everything else is compressed
        assert codes == {0, COMPRESSION[axes["COMPRESS"]]}


@pytest.mark.parametrize("name", ROWS)
def test_log_records_the_configuration_and_the_mount_options_in_effect(name):
    axes, log = config(name), truth(name)
    assert log.done
    assert log.guest_kernel == ROWS[name]["guest_kernel"]
    assert "btrfs-progs v6.6.3" in log.host["mkfs"]
    assert log.host["size"] == axes["SIZE"]
    assert log.host["devices"] == ("2" if axes["LAYOUT"] == "raid1" else "1")
    assert log.host["discard"] == ("none" if axes["DISCARD_MODE"] == "none" else "unmap")
    assert f"--csum {axes['CSUM'].replace('blake2b', 'blake2')}" in log.host["mkfs_args"]
    reclaim = "50" if axes["RECLAIM"] == "on" else "0"
    expected = {"op": axes["OP"], "size": axes["SIZE"], "compress": axes["COMPRESS"],
                "csum": axes["CSUM"], "bgt": axes["BGT"], "discard": axes["DISCARD_MODE"],
                "reclaim": reclaim, "idle": "130" if axes["DISCARD_MODE"] == "idle" else "0",
                "layout": axes["LAYOUT"]}  # fmt: skip
    assert log.matrix == expected

    # the discard option /proc/mounts shows: the kernel would otherwise pick discard=async itself
    discard = {o for o in log.mount_options if o == "discard" or o.startswith("discard=")}
    assert discard == {
        "none": set(), "nodiscard": set(), "async": {"discard=async"}, "idle": {"discard=async"},
        "sync": {"discard"},
    }[axes["DISCARD_MODE"]]  # fmt: skip
    compress = {o for o in log.mount_options if o.startswith("compress")}
    if axes["COMPRESS"] == "none":
        assert compress == set()
    else:
        assert len(compress) == 1 and compress.pop().startswith(
            f"compress-force={axes['COMPRESS']}"
        )

    assert len(log.reclaim) == 2  # before the operation and at the end
    space = "mixed" if axes["LAYOUT"] == "mixed" else "data"
    for counters in log.reclaim:
        assert counters["space"] == space and counters["bg_reclaim_threshold"] == reclaim
        assert counters["dynamic_reclaim"] == counters["periodic_reclaim"] == "0"
    if axes["RECLAIM"] == "off":  # threshold 0: the worker never relocates
        assert log.reclaim[-1]["reclaim_count"] == "0"


def _inode_items(fs, tree) -> dict[int, dict]:
    return {
        item.key.objectid: items.inode_item(item.data)
        for _, item in leaf_items(walk(fs.reader, tree.bytenr, tree.expect()))
        if item.key.type == ondisk.ITEM_KEYS["INODE_ITEM"]
    }


def _lookup(inventory: dict[int, dict], path: str) -> int | None:
    """The inode of `path` (relative to the mount point, under data/) in a tree's inventory."""
    first, *names = path.split("/")
    assert first == "data", path
    inode = DATA_TREE
    for name in names:
        inode = inventory.get(inode, {}).get("entries", {}).get(name)
        if inode is None:
            return None
    return inode


@pytest.mark.parametrize("name", ROWS)
def test_history_is_consistent_and_its_last_states_are_the_image(name):
    log = truth(name)
    assert log.events and groundtruth.check(log) == []
    op = config(name)["OP"]
    assert {"create", "delete" if op != "overwrite" else "overwrite"} <= {
        e.kind for e in log.events
    }
    if op == "overwrite":
        assert {"modify", "overwrite"} <= {e.kind for e in log.events}
    if op == "stress":
        assert "rename" in {e.kind for e in log.events}
    created = {}
    for event in log.events:
        if event.kind == "create":
            created[event.path] = event

    with open_image(image(name)) as img:
        fs = open_filesystem(img)
        root_set = find_root_set(fs.fields, "current")
        tree = resolve_tree(fs.reader, root_set, DATA_TREE)
        inventory = fs_tree_inventory(fs.reader, tree.bytenr, tree.expect())
        inode_items = _inode_items(fs, tree)
        no_holes = "NO_HOLES" in ondisk.flag_names(fs.fields["incompat_flags"], ondisk.INCOMPAT)
        states = {p: e for p, e in groundtruth.final_states(log).items() if e.sha256}
        assert states
        for path, state in states.items():
            inode = _lookup(inventory, path)
            assert inode == state.inode, path
            # the creation generation the kernel stored lies in the window the log claims, and is
            # the logged generation itself where the log says it is exact
            origin = created[path] if path in created else None
            if origin is not None:
                assert origin.after is not None, path
                assert origin.after < inode_items[inode]["generation"] <= origin.generation, path
                if origin.exact:
                    assert inode_items[inode]["generation"] == origin.generation, path
            # the last change to the inode is no older than the window of its last logged state
            assert state.after is not None and inode_items[inode]["transid"] > state.after, path
            if state.exact:
                assert inode_items[inode]["transid"] >= state.generation, path
            content = read_file(fs.reader, tree, inode, no_holes=no_holes)
            assert content.complete, (path, content.failures)
            assert hashlib.sha256(b"".join(content.chunks())).hexdigest() == state.sha256, path
        # nothing the log deleted is still there
        for event in log.events:
            if event.kind == "delete" and event.path.startswith("data/"):
                if event.path not in states:
                    assert _lookup(inventory, event.path) is None, event.path
        if op == "snapshot":  # the snapshot was deleted and the cleaner dropped it
            found, _ = subvolumes(fs.reader, root_set)
            assert [s.name for s in found if s.id >= DATA_TREE and s.root is not None] == ["data"]
