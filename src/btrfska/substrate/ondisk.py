"""Btrfs on-disk layouts and constants.

Our own `struct` tables (no cstruct, no btrfs library). All values follow Linux
v7.0 (tag object 3131ff5a1174):

- include/uapi/linux/btrfs_tree.h — structs, objectids, item keys, csum types,
  block-group flags;
- include/uapi/linux/btrfs.h — feature flag bits (l.298-339), FSID/UUID/label sizes;
- fs/btrfs/fs.h — superblock offset/size (l.80-82), supported-feature masks (l.286-330);
- fs/btrfs/fs.c — csum sizes and names (l.12-17);
- fs/btrfs/disk-io.h — superblock mirrors (l.26-43).

tests/test_ondisk.py asserts every size, offset and value with its file:line.
All integers are little-endian and all structs are packed.
"""

import struct

# ---------------------------------------------------------------------------
# Sizes and superblock placement
# ---------------------------------------------------------------------------
MAGIC = 0x4D5F53665248425F  # "_BHRfS_M"
MAX_LEVEL = 8
CSUM_SIZE = 32
FSID_SIZE = 16
UUID_SIZE = 16
LABEL_SIZE = 256
SYSTEM_CHUNK_ARRAY_SIZE = 2048
NUM_BACKUP_ROOTS = 4

SUPER_INFO_OFFSET = 0x10000
SUPER_INFO_SIZE = 4096
SUPER_MIRROR_MAX = 3
SUPER_MIRROR_SHIFT = 12
# Geometry bounds used by btrfs_validate_super (fs/btrfs/disk-io.c:2404-2421, 2554-2555).
MIN_BLOCKSIZE = 4096  # fs.h:59-62; 2K only on CONFIG_BTRFS_DEBUG kernels
MAX_METADATA_BLOCKSIZE = 65536
MIN_SYS_CHUNK_ARRAY_SIZE = 17 + 48 + 32  # disk_key + btrfs_chunk incl. its one stripe


def sb_offset(mirror: int) -> int:
    """Byte offset of superblock copy `mirror` (kernel btrfs_sb_offset())."""
    if mirror:
        return (16 * 1024) << (SUPER_MIRROR_SHIFT * mirror)
    return SUPER_INFO_OFFSET


# ---------------------------------------------------------------------------
# Layouts
# ---------------------------------------------------------------------------
class Layout:
    """A packed little-endian struct with named fields.

    `spec` is a sequence of (name, struct-format) pairs; a name of None marks
    padding (use an `x` format), which occupies bytes but yields no field.
    """

    def __init__(self, name: str, spec: list[tuple[str | None, str]]) -> None:
        self.name = name
        self.format = "<" + "".join(fmt for _, fmt in spec)
        self._struct = struct.Struct(self.format)
        self.size = self._struct.size
        self.fields = tuple(field for field, _ in spec if field)
        self._offsets = {}
        prefix = "<"
        for field, fmt in spec:
            if field:
                self._offsets[field] = struct.calcsize(prefix)
            prefix += fmt

    def unpack_from(self, buffer, offset: int = 0) -> dict:
        return dict(zip(self.fields, self._struct.unpack_from(buffer, offset), strict=True))

    def offset(self, field: str) -> int:
        return self._offsets[field]

    def __repr__(self) -> str:
        return f"Layout({self.name}, {self.size} bytes)"


def _key(prefix: str) -> list[tuple[str, str]]:
    return [(f"{prefix}objectid", "Q"), (f"{prefix}type", "B"), (f"{prefix}offset", "Q")]


def _timespec(prefix: str) -> list[tuple[str, str]]:
    return [(f"{prefix}_sec", "Q"), (f"{prefix}_nsec", "I")]


DISK_KEY = Layout("btrfs_disk_key", _key(""))
TIMESPEC = Layout("btrfs_timespec", _timespec("time"))

HEADER = Layout(
    "btrfs_header",
    [
        ("csum", "32s"),
        ("fsid", "16s"),
        ("bytenr", "Q"),
        ("flags", "Q"),
        ("chunk_tree_uuid", "16s"),
        ("generation", "Q"),
        ("owner", "Q"),
        ("nritems", "I"),
        ("level", "B"),
    ],
)

ITEM = Layout("btrfs_item", [*_key("key_"), ("offset", "I"), ("size", "I")])
KEY_PTR = Layout("btrfs_key_ptr", [*_key("key_"), ("blockptr", "Q"), ("generation", "Q")])

_BACKUP_TREES = ("tree_root", "chunk_root", "extent_root", "fs_root", "dev_root", "csum_root")
ROOT_BACKUP = Layout(
    "btrfs_root_backup",
    [(f, "Q") for tree in _BACKUP_TREES for f in (tree, f"{tree}_gen")]
    + [("total_bytes", "Q"), ("bytes_used", "Q"), ("num_devices", "Q"), (None, "32x")]
    + [(f"{tree}_level", "B") for tree in _BACKUP_TREES]
    + [(None, "10x")],
)

DEV_ITEM = Layout(
    "btrfs_dev_item",
    [
        ("devid", "Q"),
        ("total_bytes", "Q"),
        ("bytes_used", "Q"),
        ("io_align", "I"),
        ("io_width", "I"),
        ("sector_size", "I"),
        ("type", "Q"),
        ("generation", "Q"),
        ("start_offset", "Q"),
        ("dev_group", "I"),
        ("seek_speed", "B"),
        ("bandwidth", "B"),
        ("uuid", "16s"),
        ("fsid", "16s"),
    ],
)

STRIPE = Layout("btrfs_stripe", [("devid", "Q"), ("offset", "Q"), ("dev_uuid", "16s")])
# struct btrfs_chunk up to (not including) its first embedded btrfs_stripe.
CHUNK = Layout(
    "btrfs_chunk",
    [
        ("length", "Q"),
        ("owner", "Q"),
        ("stripe_len", "Q"),
        ("type", "Q"),
        ("io_align", "I"),
        ("io_width", "I"),
        ("sector_size", "I"),
        ("num_stripes", "H"),
        ("sub_stripes", "H"),
    ],
)

SUPERBLOCK = Layout(
    "btrfs_super_block",
    [
        ("csum", "32s"),
        ("fsid", "16s"),
        ("bytenr", "Q"),
        ("flags", "Q"),
        ("magic", "Q"),
        ("generation", "Q"),
        ("root", "Q"),
        ("chunk_root", "Q"),
        ("log_root", "Q"),
        ("log_root_transid", "Q"),  # __unused_log_root_transid
        ("total_bytes", "Q"),
        ("bytes_used", "Q"),
        ("root_dir_objectid", "Q"),
        ("num_devices", "Q"),
        ("sectorsize", "I"),
        ("nodesize", "I"),
        ("leafsize", "I"),  # __unused_leafsize
        ("stripesize", "I"),
        ("sys_chunk_array_size", "I"),
        ("chunk_root_generation", "Q"),
        ("compat_flags", "Q"),
        ("compat_ro_flags", "Q"),
        ("incompat_flags", "Q"),
        ("csum_type", "H"),
        ("root_level", "B"),
        ("chunk_root_level", "B"),
        ("log_root_level", "B"),
        ("dev_item", f"{DEV_ITEM.size}s"),
        ("label", f"{LABEL_SIZE}s"),
        ("cache_generation", "Q"),
        ("uuid_tree_generation", "Q"),
        ("metadata_uuid", "16s"),
        ("nr_global_roots", "Q"),
        ("remap_root", "Q"),
        ("remap_root_generation", "Q"),
        ("remap_root_level", "B"),
        (None, "199x"),
        ("sys_chunk_array", f"{SYSTEM_CHUNK_ARRAY_SIZE}s"),
        ("super_roots", f"{NUM_BACKUP_ROOTS * ROOT_BACKUP.size}s"),
        (None, "565x"),
    ],
)

EXTENT_ITEM = Layout("btrfs_extent_item", [("refs", "Q"), ("generation", "Q"), ("flags", "Q")])
TREE_BLOCK_INFO = Layout("btrfs_tree_block_info", [*_key("key_"), ("level", "B")])
EXTENT_DATA_REF = Layout(
    "btrfs_extent_data_ref",
    [("root", "Q"), ("objectid", "Q"), ("offset", "Q"), ("count", "I")],
)
SHARED_DATA_REF = Layout("btrfs_shared_data_ref", [("count", "I")])
EXTENT_OWNER_REF = Layout("btrfs_extent_owner_ref", [("root_id", "Q")])
EXTENT_INLINE_REF = Layout("btrfs_extent_inline_ref", [("type", "B"), ("offset", "Q")])

DEV_EXTENT = Layout(
    "btrfs_dev_extent",
    [
        ("chunk_tree", "Q"),
        ("chunk_objectid", "Q"),
        ("chunk_offset", "Q"),
        ("length", "Q"),
        ("chunk_tree_uuid", "16s"),
    ],
)

INODE_REF = Layout("btrfs_inode_ref", [("index", "Q"), ("name_len", "H")])
INODE_EXTREF = Layout(
    "btrfs_inode_extref", [("parent_objectid", "Q"), ("index", "Q"), ("name_len", "H")]
)

_INODE_SPEC = [
    ("generation", "Q"),
    ("transid", "Q"),
    ("size", "Q"),
    ("nbytes", "Q"),
    ("block_group", "Q"),
    ("nlink", "I"),
    ("uid", "I"),
    ("gid", "I"),
    ("mode", "I"),
    ("rdev", "Q"),
    ("flags", "Q"),
    ("sequence", "Q"),
    (None, "32x"),
    *_timespec("atime"),
    *_timespec("ctime"),
    *_timespec("mtime"),
    *_timespec("otime"),
]
INODE_ITEM = Layout("btrfs_inode_item", _INODE_SPEC)

DIR_ITEM = Layout(
    "btrfs_dir_item",
    [*_key("location_"), ("transid", "Q"), ("data_len", "H"), ("name_len", "H"), ("type", "B")],
)

ROOT_ITEM = Layout(
    "btrfs_root_item",
    [
        ("inode", f"{INODE_ITEM.size}s"),
        ("generation", "Q"),
        ("root_dirid", "Q"),
        ("bytenr", "Q"),
        ("byte_limit", "Q"),
        ("bytes_used", "Q"),
        ("last_snapshot", "Q"),
        ("flags", "Q"),
        ("refs", "I"),
        *_key("drop_progress_"),
        ("drop_level", "B"),
        ("level", "B"),
        ("generation_v2", "Q"),
        ("uuid", "16s"),
        ("parent_uuid", "16s"),
        ("received_uuid", "16s"),
        ("ctransid", "Q"),
        ("otransid", "Q"),
        ("stransid", "Q"),
        ("rtransid", "Q"),
        *_timespec("ctime"),
        *_timespec("otime"),
        *_timespec("stime"),
        *_timespec("rtime"),
        (None, "64x"),
    ],
)
# Root items written by old kernels end where generation_v2 starts.
ROOT_ITEM_LEGACY_SIZE = 239

ROOT_REF = Layout("btrfs_root_ref", [("dirid", "Q"), ("sequence", "Q"), ("name_len", "H")])

FILE_EXTENT_ITEM = Layout(
    "btrfs_file_extent_item",
    [
        ("generation", "Q"),
        ("ram_bytes", "Q"),
        ("compression", "B"),
        ("encryption", "B"),
        ("other_encoding", "H"),
        ("type", "B"),
        ("disk_bytenr", "Q"),
        ("disk_num_bytes", "Q"),
        ("offset", "Q"),
        ("num_bytes", "Q"),
    ],
)
# Inline extent data starts where disk_bytenr would be.
FILE_EXTENT_INLINE_DATA_START = 21

BLOCK_GROUP_ITEM = Layout(
    "btrfs_block_group_item", [("used", "Q"), ("chunk_objectid", "Q"), ("flags", "Q")]
)
BLOCK_GROUP_ITEM_V2 = Layout(
    "btrfs_block_group_item_v2",
    [
        ("used", "Q"),
        ("chunk_objectid", "Q"),
        ("flags", "Q"),
        ("remap_bytes", "Q"),
        ("identity_remap_count", "I"),
    ],
)
FREE_SPACE_INFO = Layout("btrfs_free_space_info", [("extent_count", "I"), ("flags", "I")])
REMAP_ITEM = Layout("btrfs_remap_item", [("address", "Q")])

# ---------------------------------------------------------------------------
# Checksums: type -> (name, size in bytes)
# ---------------------------------------------------------------------------
CSUM_TYPES = {0: ("crc32c", 4), 1: ("xxhash64", 8), 2: ("sha256", 32), 3: ("blake2b", 32)}

# ---------------------------------------------------------------------------
# Objectids
# ---------------------------------------------------------------------------
_U64 = 1 << 64
ROOT_TREE_OBJECTID = 1
EXTENT_TREE_OBJECTID = 2
CHUNK_TREE_OBJECTID = 3
DEV_TREE_OBJECTID = 4
FS_TREE_OBJECTID = 5
ROOT_TREE_DIR_OBJECTID = 6
CSUM_TREE_OBJECTID = 7
QUOTA_TREE_OBJECTID = 8
UUID_TREE_OBJECTID = 9
FREE_SPACE_TREE_OBJECTID = 10
BLOCK_GROUP_TREE_OBJECTID = 11
RAID_STRIPE_TREE_OBJECTID = 12
REMAP_TREE_OBJECTID = 13
ORPHAN_OBJECTID = _U64 - 5
TREE_LOG_OBJECTID = _U64 - 6
TREE_RELOC_OBJECTID = _U64 - 8
DATA_RELOC_TREE_OBJECTID = _U64 - 9
FIRST_FREE_OBJECTID = 256
LAST_FREE_OBJECTID = _U64 - 256
FIRST_CHUNK_TREE_OBJECTID = 256
DEV_ITEMS_OBJECTID = 1

# ---------------------------------------------------------------------------
# Item key types
# ---------------------------------------------------------------------------
ITEM_KEYS = {
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

# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------
COMPAT_RO = {
    "FREE_SPACE_TREE": 1 << 0,
    "FREE_SPACE_TREE_VALID": 1 << 1,
    "VERITY": 1 << 2,
    "BLOCK_GROUP_TREE": 1 << 3,
}

INCOMPAT = {
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
# Accepted only by CONFIG_BTRFS_EXPERIMENTAL kernels (fs.h:316-324).
EXPERIMENTAL_INCOMPAT = frozenset({"EXTENT_TREE_V2", "RAID_STRIPE_TREE", "REMAP_TREE"})
INCOMPAT_SUPP_STABLE = sum(v for k, v in INCOMPAT.items() if k not in EXPERIMENTAL_INCOMPAT)

BLOCK_GROUP_FLAGS = {
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

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
HEADER_FLAG_WRITTEN = 1 << 0
HEADER_FLAG_RELOC = 1 << 1

FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7
FT_XATTR = 8
FT_ENCRYPTED = 0x80

FILE_EXTENT_INLINE = 0
FILE_EXTENT_REG = 1
FILE_EXTENT_PREALLOC = 2

EXTENT_FLAG_DATA = 1 << 0
EXTENT_FLAG_TREE_BLOCK = 1 << 1


def flag_names(value: int, table: dict[str, int]) -> list[str]:
    """Names of the bits set in `value`; bits missing from `table` become `UNKNOWN_BIT_<n>`."""
    names = [name for name, bit in table.items() if value & bit]
    known = sum(table.values())
    names += [f"UNKNOWN_BIT_{n}" for n in range(64) if value & ~known & (1 << n)]
    return names
