"""Item payload parsers: exact values on sandbox.img; hostile payloads raise only ItemError."""

import random
import struct

import pytest

from btrfska.substrate import items, ondisk
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.items import ItemError
from btrfska.substrate.node import Expect, Key

K = ondisk.ITEM_KEYS


def test_inode_ref_with_several_names():
    data = b"".join(
        struct.pack(ondisk.INODE_REF.format, index, len(name)) + name
        for index, name in ((2, b"a"), (7, b"bc"))
    )
    assert items.inode_refs(data) == [{"index": 2, "name": "a"}, {"index": 7, "name": "bc"}]


@pytest.mark.parametrize(
    ("parser", "data"),
    [
        (items.inode_item, bytes(159)),
        (items.inode_refs, struct.pack(ondisk.INODE_REF.format, 1, 5) + b"abc"),
        (items.inode_refs, b"\x01"),
        (items.dir_items, bytes(29)),
        (items.dir_items, struct.pack(ondisk.DIR_ITEM.format, 1, 1, 0, 0, 0, 10, 1) + b"short"),
        (items.file_extent, bytes(20)),
        (items.file_extent, struct.pack("<QQBBHB", 1, 1, 0, 0, 0, ondisk.FILE_EXTENT_REG)),
        (items.root_item, bytes(238)),
        (items.root_ref, struct.pack(ondisk.ROOT_REF.format, 256, 2, 9) + b"sv"),
    ],
)
def test_malformed_payloads_raise_item_error(parser, data):
    with pytest.raises(ItemError):
        parser(data)


def test_names_keep_undecodable_bytes():
    data = struct.pack(ondisk.INODE_REF.format, 1, 2) + b"\xff\xfe"
    name = items.inode_refs(data)[0]["name"]
    assert name.encode("utf-8", "surrogateescape") == b"\xff\xfe"


def test_legacy_root_item_has_no_uuids():
    data = bytearray(ondisk.ROOT_ITEM_LEGACY_SIZE)
    struct.pack_into("<Q", data, ondisk.ROOT_ITEM.offset("bytenr"), 4096)
    parsed = items.root_item(bytes(data))
    assert parsed["bytenr"] == 4096 and "uuid" not in parsed


# ---------------------------------------------------------------------------
# EXTENT_ITEM, METADATA_ITEM and the back-reference items
# ---------------------------------------------------------------------------
def _head(refs: int, generation: int, flags: int) -> bytes:
    return struct.pack("<QQQ", refs, generation, flags)


def _inline(kind: str, value: int) -> bytes:
    return struct.pack("<BQ", K[kind], value)


def test_skinny_metadata_item_takes_address_and_level_from_the_key():
    data = _head(1, 9, ondisk.EXTENT_FLAG_TREE_BLOCK) + _inline("TREE_BLOCK_REF", 5)
    extent = items.extent_item(Key(30720000, K["METADATA_ITEM"], 1), data)
    assert (extent["bytenr"], extent["num_bytes"], extent["level"]) == (30720000, None, 1)
    assert (extent["refs"], extent["generation"], extent["tree_block"]) == (1, 9, True)
    assert extent["first_key"] is None
    [ref] = extent["backrefs"]
    assert (ref["type_name"], ref["inline"], ref["root"], ref["parent"]) == (
        "TREE_BLOCK_REF", True, 5, None,
    )  # fmt: skip


def test_tree_block_extent_item_carries_tree_block_info_before_its_refs():
    """Without skinny metadata the key offset is the length and the level follows the head."""
    info = struct.pack("<QBQB", 256, K["INODE_ITEM"], 0, 2)
    data = _head(2, 7, ondisk.EXTENT_FLAG_TREE_BLOCK) + info
    data += _inline("SHARED_BLOCK_REF", 30408704) + _inline("TREE_BLOCK_REF", 257)
    extent = items.extent_item(Key(30720000, K["EXTENT_ITEM"], 16384), data)
    assert (extent["bytenr"], extent["num_bytes"], extent["level"]) == (30720000, 16384, 2)
    assert extent["first_key"] == Key(256, K["INODE_ITEM"], 0)
    assert [(r["type_name"], r["root"], r["parent"]) for r in extent["backrefs"]] == [
        ("SHARED_BLOCK_REF", None, 30408704),
        ("TREE_BLOCK_REF", 257, None),
    ]


def test_data_extent_with_owner_data_and_shared_data_refs():
    """EXTENT_DATA_REF starts right after the type byte; the other kinds after an 8-byte value."""
    data = _head(3, 11, ondisk.EXTENT_FLAG_DATA)
    data += _inline("EXTENT_OWNER_REF", 256)
    data += struct.pack("<B", K["EXTENT_DATA_REF"]) + struct.pack("<QQQI", 5, 1758, 4096, 2)
    data += _inline("SHARED_DATA_REF", 30408704) + struct.pack("<I", 1)
    extent = items.extent_item(Key(13631488, K["EXTENT_ITEM"], 8192), data)
    assert (extent["tree_block"], extent["level"], extent["num_bytes"]) == (False, None, 8192)
    owner, data_ref, shared = extent["backrefs"]
    assert (owner["type_name"], owner["root"]) == ("EXTENT_OWNER_REF", 256)
    assert (data_ref["root"], data_ref["objectid"], data_ref["offset"], data_ref["count"]) == (
        5, 1758, 4096, 2,
    )  # fmt: skip
    assert (shared["type_name"], shared["parent"], shared["count"]) == (
        "SHARED_DATA_REF", 30408704, 1,
    )  # fmt: skip


def test_standalone_back_reference_items():
    assert items.extent_ref(Key(1, K["TREE_BLOCK_REF"], 7), b"")["root"] == 7
    assert items.extent_ref(Key(1, K["SHARED_BLOCK_REF"], 4096), b"")["parent"] == 4096
    ref = items.extent_ref(Key(1, K["EXTENT_DATA_REF"], 99), struct.pack("<QQQI", 5, 257, 0, 1))
    assert (ref["root"], ref["objectid"], ref["offset"], ref["count"], ref["inline"]) == (
        5, 257, 0, 1, False,
    )  # fmt: skip
    ref = items.extent_ref(Key(1, K["SHARED_DATA_REF"], 8192), struct.pack("<I", 3))
    assert (ref["parent"], ref["count"]) == (8192, 3)
    assert items.extent_ref(Key(1, K["EXTENT_OWNER_REF"], 0), struct.pack("<Q", 256))["root"] == 256
    with pytest.raises(ItemError, match="not a back-reference"):
        items.extent_ref(Key(1, K["INODE_ITEM"], 0), b"")


@pytest.mark.parametrize(
    ("key_type", "data", "message"),
    [
        ("EXTENT_ITEM", b"\0" * 23, "btrfs_extent_item needs 24 bytes"),
        ("EXTENT_ITEM", _head(1, 1, 2) + b"\0" * 5, "btrfs_tree_block_info needs 18 bytes"),
        ("METADATA_ITEM", _head(1, 1, 2) + b"\xb0\x01", "btrfs_extent_inline_ref needs 9 bytes"),
        ("METADATA_ITEM", _head(1, 1, 2) + b"\xb2" * 3, "btrfs_extent_data_ref needs 28 bytes"),
        ("EXTENT_ITEM", _head(1, 1, 1) + _inline("SHARED_DATA_REF", 1), "needs 4 bytes"),
        ("METADATA_ITEM", _head(1, 1, 2) + struct.pack("<BQ", 1, 0), "unknown inline reference"),
    ],
)
def test_malformed_extent_items_raise_item_error(key_type, data, message):
    with pytest.raises(ItemError, match=message):
        items.extent_item(Key(4096, K[key_type], 0), data)


def test_extent_parsers_raise_only_item_error_on_random_payloads():
    rng = random.Random(172)
    kinds = [K[name] for name in ("EXTENT_ITEM", "METADATA_ITEM")]
    ref_kinds = [K[n] for n in ("TREE_BLOCK_REF", "SHARED_BLOCK_REF", "EXTENT_DATA_REF",
                                "SHARED_DATA_REF", "EXTENT_OWNER_REF")]  # fmt: skip
    parsed = 0
    for _ in range(4000):
        data = rng.randbytes(rng.choice([0, 8, 24, 33, 42, 53, 70, rng.randrange(200)]))
        if rng.random() < 0.5 and len(data) >= 25:  # a plausible head, so inline refs are reached
            flags = rng.choice([1, 2])
            data = _head(1, 1, flags) + bytes([rng.choice(ref_kinds)]) + data[25:]
        for parser, types in ((items.extent_item, kinds), (items.extent_ref, ref_kinds)):
            try:
                parser(Key(rng.randrange(1 << 64), rng.choice(types), rng.randrange(1 << 64)), data)
                parsed += 1
            except ItemError:
                pass
    assert parsed > 100  # the loop really reached the parsers' success paths


def test_summaries_never_raise_on_random_payloads():
    rng = random.Random(99)
    for _ in range(3000):
        key = Key(
            rng.randrange(1 << 64),
            rng.choice(list(K.values()) + [0, 7, 255]),
            rng.randrange(1 << 64),
        )
        data = rng.randbytes(rng.choice([0, 1, 12, 30, 53, 160, 439, rng.randrange(600)]))
        summary = items.summary(key, data)
        assert summary is None or isinstance(summary, dict)


@pytest.mark.sandbox
def test_sandbox_gen_11_leaf_parses_exactly(sandbox_img):
    with open_image(sandbox_img) as img:
        leaf = open_filesystem(img).reader.read(30785536, Expect(level=0, owner=5, generation=11))
    by_key = {(i.key.objectid, i.key.type): i.data for i in leaf.items}
    inode = items.inode_item(by_key[(257, K["INODE_ITEM"])])
    assert (inode["size"], inode["nbytes"], inode["mode"] & 0o170000) == (31, 31, 0o100000)
    assert items.inode_refs(by_key[(257, K["INODE_REF"])]) == [
        {"index": 2, "name": "target_file.txt"}
    ]
    (entry,) = items.dir_items(by_key[(256, K["DIR_INDEX"])])
    assert (entry["name"], entry["location"], entry["type"]) == (
        "target_file.txt",
        Key(257, K["INODE_ITEM"], 0),
        ondisk.FT_REG_FILE,
    )
    extent = items.file_extent(by_key[(257, K["EXTENT_DATA"])])
    assert extent == {
        "generation": extent["generation"],
        "ram_bytes": 31,
        "compression": 0,
        "encryption": 0,
        "other_encoding": 0,
        "type": ondisk.FILE_EXTENT_INLINE,
        "inline_size": 31,
    }
    summary = items.summary(Key(257, K["EXTENT_DATA"], 0), by_key[(257, K["EXTENT_DATA"])])
    assert summary["type"] == "inline" and summary["inline_size"] == 31
