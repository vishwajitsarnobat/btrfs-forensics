"""On-disk tables checked against Linux v7.0 headers.

Every expected value below was read from the kernel source at tag v7.0
(https://github.com/torvalds/linux/tree/v7.0, tag object 3131ff5a1174); the
file:line of each definition is given next to it. Sizes are the packed C
sizeof(), computed by hand from the struct bodies.
"""

import pytest

from btrfska.substrate import ondisk as od

# (layout, sizeof, kernel source)
SIZES = [
    (od.DISK_KEY, 17, "btrfs_tree.h:473-477 struct btrfs_disk_key"),
    (od.HEADER, 101, "btrfs_tree.h:488-503 struct btrfs_header"),
    (od.ROOT_BACKUP, 168, "btrfs_tree.h:516-549 struct btrfs_root_backup"),
    (od.ITEM, 25, "btrfs_tree.h:555-559 struct btrfs_item"),
    (od.KEY_PTR, 33, "btrfs_tree.h:577-581 struct btrfs_key_ptr"),
    (od.DEV_ITEM, 98, "btrfs_tree.h:588-633 struct btrfs_dev_item"),
    (od.STRIPE, 32, "btrfs_tree.h:635-639 struct btrfs_stripe"),
    (od.CHUNK, 48, "btrfs_tree.h:641-669 struct btrfs_chunk without its first stripe"),
    (od.SUPERBLOCK, 4096, "btrfs_tree.h:674-735 struct btrfs_super_block; fs.h:82 static_assert"),
    (od.EXTENT_ITEM, 24, "btrfs_tree.h:792-796 struct btrfs_extent_item"),
    (od.TREE_BLOCK_INFO, 18, "btrfs_tree.h:825-828 struct btrfs_tree_block_info"),
    (od.EXTENT_DATA_REF, 28, "btrfs_tree.h:830-835 struct btrfs_extent_data_ref"),
    (od.SHARED_DATA_REF, 4, "btrfs_tree.h:837-839 struct btrfs_shared_data_ref"),
    (od.EXTENT_OWNER_REF, 8, "btrfs_tree.h:841-843 struct btrfs_extent_owner_ref"),
    (od.EXTENT_INLINE_REF, 9, "btrfs_tree.h:845-848 struct btrfs_extent_inline_ref"),
    (od.DEV_EXTENT, 48, "btrfs_tree.h:854-860 struct btrfs_dev_extent"),
    (od.INODE_REF, 10, "btrfs_tree.h:862-866 struct btrfs_inode_ref"),
    (od.INODE_EXTREF, 18, "btrfs_tree.h:868-874 struct btrfs_inode_extref"),
    (od.TIMESPEC, 12, "btrfs_tree.h:876-879 struct btrfs_timespec"),
    (od.INODE_ITEM, 160, "btrfs_tree.h:881-908 struct btrfs_inode_item"),
    (od.DIR_ITEM, 30, "btrfs_tree.h:914-920 struct btrfs_dir_item"),
    (od.ROOT_ITEM, 439, "btrfs_tree.h:930-973 struct btrfs_root_item"),
    (od.ROOT_REF, 18, "btrfs_tree.h:987-991 struct btrfs_root_ref"),
    (od.FILE_EXTENT_ITEM, 53, "btrfs_tree.h:1078-1128 struct btrfs_file_extent_item"),
    (od.BLOCK_GROUP_ITEM, 24, "btrfs_tree.h:1229-1233 struct btrfs_block_group_item"),
    (od.BLOCK_GROUP_ITEM_V2, 36, "btrfs_tree.h:1235-1241 struct btrfs_block_group_item_v2"),
    (od.FREE_SPACE_INFO, 8, "btrfs_tree.h:1243-1246 struct btrfs_free_space_info"),
    (od.REMAP_ITEM, 8, "btrfs_tree.h:1352-1354 struct btrfs_remap_item"),
]


@pytest.mark.parametrize(("layout", "size", "source"), SIZES, ids=[s[2].split()[-1] for s in SIZES])
def test_layout_size_matches_kernel(layout, size, source):
    assert layout.size == size, source


def test_layouts_are_little_endian_and_named():
    for layout, _, _ in SIZES:
        assert layout.format.startswith("<")
        assert len(layout.fields) == len(layout.unpack_from(bytes(layout.size)))


def test_derived_sizes():
    # btrfs_chunk_item_size(n) = sizeof(struct btrfs_chunk) + (n - 1) * sizeof(struct btrfs_stripe)
    assert od.CHUNK.size + od.STRIPE.size == 80
    # btrfs_tree.h:979-982 btrfs_legacy_root_item_size() = offsetof(root_item, generation_v2)
    assert od.ROOT_ITEM.offset("generation_v2") == od.ROOT_ITEM_LEGACY_SIZE == 239
    # Inline file data starts at offsetof(file_extent_item, disk_bytenr) (btrfs_tree.h:1106-1112)
    assert od.FILE_EXTENT_ITEM.offset("disk_bytenr") == od.FILE_EXTENT_INLINE_DATA_START == 21


# Superblock field offsets (from the btrfs_tree.h:674-735 struct body; research.md §8.1
# independently cites csum_type at 0xC4 and incompat_flags at 0xBC, and the M1 prototype
# branch found the backup roots at 0xB2B with stride 0xA8).
SB_OFFSETS = {
    "csum": 0x00,
    "fsid": 0x20,
    "bytenr": 0x30,
    "flags": 0x38,
    "magic": 0x40,
    "generation": 0x48,
    "root": 0x50,
    "chunk_root": 0x58,
    "total_bytes": 0x70,
    "sectorsize": 0x90,
    "nodesize": 0x94,
    "sys_chunk_array_size": 0xA0,
    "chunk_root_generation": 0xA4,
    "compat_flags": 0xAC,
    "compat_ro_flags": 0xB4,
    "incompat_flags": 0xBC,
    "csum_type": 0xC4,
    "root_level": 0xC6,
    "dev_item": 0xC9,
    "label": 0x12B,
    "metadata_uuid": 0x23B,
    "remap_root": 0x253,
    "remap_root_level": 0x263,
    "sys_chunk_array": 0x32B,
    "super_roots": 0xB2B,
}


@pytest.mark.parametrize(("field", "offset"), SB_OFFSETS.items())
def test_superblock_field_offsets(field, offset):
    assert od.SUPERBLOCK.offset(field) == offset


def test_header_and_inode_offsets():
    assert od.HEADER.offset("bytenr") == 0x30
    assert od.HEADER.offset("chunk_tree_uuid") == 0x40
    assert od.HEADER.offset("level") == 0x64
    assert od.INODE_ITEM.offset("atime_sec") == 112
    assert od.DIR_ITEM.offset("name_len") == 27


def test_superblock_constants():
    assert (
        od.MAGIC == 0x4D5F53665248425F == int.from_bytes(b"_BHRfS_M", "little")
    )  # btrfs_tree.h:14
    assert od.MAX_LEVEL == 8  # btrfs_tree.h:16
    assert od.CSUM_SIZE == 32  # btrfs_tree.h:383
    assert od.FSID_SIZE == od.UUID_SIZE == 16  # btrfs.h:62-63
    assert od.LABEL_SIZE == 256  # btrfs.h:33
    assert od.SYSTEM_CHUNK_ARRAY_SIZE == 2048  # btrfs_tree.h:509
    assert od.NUM_BACKUP_ROOTS == 4  # btrfs_tree.h:515
    assert od.SUPER_INFO_OFFSET == 0x10000  # fs.h:80
    assert od.SUPER_INFO_SIZE == 4096  # fs.h:81
    assert od.SUPER_MIRROR_MAX == 3  # disk-io.h:26
    assert od.SUPER_MIRROR_SHIFT == 12  # disk-io.h:27


def test_superblock_mirror_offsets():
    # disk-io.h:37-43 btrfs_sb_offset(): 64 KiB, then SZ_16K << (12 * mirror)
    assert [od.sb_offset(m) for m in range(od.SUPER_MIRROR_MAX)] == [
        64 * 1024,
        64 * 1024**2,
        256 * 1024**3,
    ]


def test_csum_types():
    # btrfs_tree.h:386-391 enum; fs.c:12-17 btrfs_csums[] sizes and names
    assert od.CSUM_TYPES == {
        0: ("crc32c", 4),
        1: ("xxhash64", 8),
        2: ("sha256", 32),
        3: ("blake2b", 32),
    }


def test_objectids():
    # btrfs_tree.h:38-130
    assert od.ROOT_TREE_OBJECTID == 1
    assert od.EXTENT_TREE_OBJECTID == 2
    assert od.CHUNK_TREE_OBJECTID == 3
    assert od.DEV_TREE_OBJECTID == 4
    assert od.FS_TREE_OBJECTID == 5
    assert od.ROOT_TREE_DIR_OBJECTID == 6
    assert od.CSUM_TREE_OBJECTID == 7
    assert od.QUOTA_TREE_OBJECTID == 8
    assert od.UUID_TREE_OBJECTID == 9
    assert od.FREE_SPACE_TREE_OBJECTID == 10
    assert od.BLOCK_GROUP_TREE_OBJECTID == 11
    assert od.RAID_STRIPE_TREE_OBJECTID == 12
    assert od.REMAP_TREE_OBJECTID == 13
    assert od.ORPHAN_OBJECTID == 2**64 - 5
    assert od.TREE_LOG_OBJECTID == 2**64 - 6
    assert od.TREE_RELOC_OBJECTID == 2**64 - 8
    assert od.DATA_RELOC_TREE_OBJECTID == 2**64 - 9
    assert od.FIRST_FREE_OBJECTID == 256
    assert od.LAST_FREE_OBJECTID == 2**64 - 256
    assert od.FIRST_CHUNK_TREE_OBJECTID == 256
    assert od.DEV_ITEMS_OBJECTID == 1


def test_item_keys():
    # btrfs_tree.h:143-377
    assert od.ITEM_KEYS == {
        "INODE_ITEM": 1,
        "INODE_REF": 12,
        "INODE_EXTREF": 13,
        "XATTR_ITEM": 24,
        "VERITY_DESC_ITEM": 36,
        "VERITY_MERKLE_ITEM": 37,
        "ORPHAN_ITEM": 48,
        "DIR_LOG_ITEM": 60,
        "DIR_LOG_INDEX": 72,
        "DIR_ITEM": 84,
        "DIR_INDEX": 96,
        "EXTENT_DATA": 108,
        "EXTENT_CSUM": 128,
        "ROOT_ITEM": 132,
        "ROOT_BACKREF": 144,
        "ROOT_REF": 156,
        "EXTENT_ITEM": 168,
        "METADATA_ITEM": 169,
        "EXTENT_OWNER_REF": 172,
        "TREE_BLOCK_REF": 176,
        "EXTENT_DATA_REF": 178,
        "SHARED_BLOCK_REF": 182,
        "SHARED_DATA_REF": 184,
        "BLOCK_GROUP_ITEM": 192,
        "FREE_SPACE_INFO": 198,
        "FREE_SPACE_EXTENT": 199,
        "FREE_SPACE_BITMAP": 200,
        "DEV_EXTENT": 204,
        "DEV_ITEM": 216,
        "CHUNK_ITEM": 228,
        "RAID_STRIPE": 230,
        "IDENTITY_REMAP": 234,
        "REMAP": 235,
        "REMAP_BACKREF": 236,
        "QGROUP_STATUS": 240,
        "QGROUP_INFO": 242,
        "QGROUP_LIMIT": 244,
        "QGROUP_RELATION": 246,
        "TEMPORARY_ITEM": 248,
        "PERSISTENT_ITEM": 249,
        "DEV_REPLACE": 250,
        "UUID_KEY_SUBVOL": 251,
        "UUID_KEY_RECEIVED_SUBVOL": 252,
        "STRING_ITEM": 253,
    }


def test_incompat_bits():
    # btrfs.h:317-339; bit 15 is unassigned in v7.0
    assert od.INCOMPAT == {
        "MIXED_BACKREF": 1 << 0,
        "DEFAULT_SUBVOL": 1 << 1,
        "MIXED_GROUPS": 1 << 2,
        "COMPRESS_LZO": 1 << 3,
        "COMPRESS_ZSTD": 1 << 4,
        "BIG_METADATA": 1 << 5,
        "EXTENDED_IREF": 1 << 6,
        "RAID56": 1 << 7,
        "SKINNY_METADATA": 1 << 8,
        "NO_HOLES": 1 << 9,
        "METADATA_UUID": 1 << 10,
        "RAID1C34": 1 << 11,
        "ZONED": 1 << 12,
        "EXTENT_TREE_V2": 1 << 13,
        "RAID_STRIPE_TREE": 1 << 14,
        "SIMPLE_QUOTA": 1 << 16,
        "REMAP_TREE": 1 << 17,
    }


def test_incompat_supp_stable_mask():
    # fs.h:299-313 BTRFS_FEATURE_INCOMPAT_SUPP_STABLE; fs.h:316-330 adds RST, ETv2 and
    # REMAP_TREE only under CONFIG_BTRFS_EXPERIMENTAL
    stable = sum(od.INCOMPAT[n] for n in od.INCOMPAT if n not in od.EXPERIMENTAL_INCOMPAT)
    assert od.INCOMPAT_SUPP_STABLE == stable == 0x11FFF
    assert od.EXPERIMENTAL_INCOMPAT == frozenset(
        {"EXTENT_TREE_V2", "RAID_STRIPE_TREE", "REMAP_TREE"}
    )


def test_compat_ro_bits():
    # btrfs.h:298-315; fs.h:290-294 BTRFS_FEATURE_COMPAT_RO_SUPP
    assert od.COMPAT_RO == {
        "FREE_SPACE_TREE": 1 << 0,
        "FREE_SPACE_TREE_VALID": 1 << 1,
        "VERITY": 1 << 2,
        "BLOCK_GROUP_TREE": 1 << 3,
    }


def test_block_group_flags():
    # btrfs_tree.h:1163-1175
    assert od.BLOCK_GROUP_FLAGS == {
        "DATA": 1 << 0,
        "SYSTEM": 1 << 1,
        "METADATA": 1 << 2,
        "RAID0": 1 << 3,
        "RAID1": 1 << 4,
        "DUP": 1 << 5,
        "RAID10": 1 << 6,
        "RAID5": 1 << 7,
        "RAID6": 1 << 8,
        "RAID1C3": 1 << 9,
        "RAID1C4": 1 << 10,
        "REMAPPED": 1 << 11,
        "METADATA_REMAP": 1 << 12,
    }


def test_misc_constants():
    assert od.HEADER_FLAG_WRITTEN == 1 << 0  # btrfs_tree.h:765
    assert od.HEADER_FLAG_RELOC == 1 << 1  # btrfs_tree.h:766
    assert od.FT_ENCRYPTED == 0x80  # btrfs_tree.h:412
    assert od.FT_REG_FILE == 1 and od.FT_DIR == 2 and od.FT_SYMLINK == 7  # btrfs_tree.h:402-408
    assert (od.FILE_EXTENT_INLINE, od.FILE_EXTENT_REG, od.FILE_EXTENT_PREALLOC) == (0, 1, 2)
    assert od.EXTENT_FLAG_DATA == 1 and od.EXTENT_FLAG_TREE_BLOCK == 2  # btrfs_tree.h:803-804


def test_unpack_from_returns_named_fields():
    buf = bytes(3) + (5).to_bytes(8, "little") + bytes([84]) + (7).to_bytes(8, "little")
    assert od.DISK_KEY.unpack_from(buf, 3) == {"objectid": 5, "type": 84, "offset": 7}
