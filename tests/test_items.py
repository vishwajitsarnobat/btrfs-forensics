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
