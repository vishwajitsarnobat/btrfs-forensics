# utils/constants.py
# Btrfs on-disk format constants
# Reference: https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html

# ─── Superblock ───────────────────────────────────────────────
SUPERBLOCK_OFFSET = 0x10000          # 64 KiB
SUPERBLOCK_MIRROR_1 = 0x4000000     # 64 MiB
SUPERBLOCK_MIRROR_2 = 0x4000000000  # 256 GiB
MAGIC_NUMBER = b"_BHRfS_M"

# Superblock field offsets (relative to superblock start)
SB_CSUM           = 0x00   # 32 bytes
SB_FSID           = 0x20   # 16 bytes (UUID)
SB_BYTENR         = 0x30   # 8 bytes
SB_FLAGS          = 0x38   # 8 bytes
SB_MAGIC          = 0x40   # 8 bytes
SB_GENERATION     = 0x48   # 8 bytes
SB_ROOT_TREE_ADDR = 0x50   # 8 bytes (logical address of root tree root)
SB_CHUNK_TREE_ADDR= 0x58   # 8 bytes (logical address of chunk tree root)
SB_LOG_TREE_ADDR  = 0x60   # 8 bytes
SB_LOG_ROOT_TRANSID = 0x68 # 8 bytes
SB_TOTAL_BYTES    = 0x70   # 8 bytes
SB_BYTES_USED     = 0x78   # 8 bytes
SB_ROOT_DIR_OBJID = 0x80   # 8 bytes (usually 6)
SB_NUM_DEVICES    = 0x88   # 8 bytes
SB_SECTORSIZE     = 0x90   # 4 bytes
SB_NODESIZE       = 0x94   # 4 bytes
SB_LEAFSIZE       = 0x98   # 4 bytes (always equals nodesize)
SB_STRIPESIZE     = 0x9C   # 4 bytes
SB_SYS_CHUNK_ARRAY_SIZE = 0xA0  # 4 bytes
SB_CHUNK_ROOT_GEN = 0xA4   # 8 bytes
SB_ROOT_LEVEL     = 0xC6   # 1 byte
SB_CHUNK_ROOT_LVL = 0xC7   # 1 byte
SB_SYS_CHUNK_ARRAY = 0x32B # 2048 bytes max (starts at offset 811)

# ─── Node Header (btrfs_header) ──────────────────────────────
# Present at the start of every metadata block (leaf or internal node)
# Total size: 101 bytes (0x65)
NODE_HEADER_SIZE  = 0x65   # 101 bytes

NH_CSUM           = 0x00   # 32 bytes
NH_FSID           = 0x20   # 16 bytes
NH_BYTENR         = 0x30   # 8 bytes (logical address of this node)
NH_FLAGS          = 0x38   # 7 bytes
NH_BACKREF_REV    = 0x3F   # 1 byte
NH_CHUNK_TREE_UUID= 0x40   # 16 bytes
NH_GENERATION     = 0x50   # 8 bytes
NH_OWNER          = 0x58   # 8 bytes (tree id that owns this node)
NH_NRITEMS        = 0x60   # 4 bytes
NH_LEVEL          = 0x64   # 1 byte (0 = leaf)

# ─── Leaf Node Item Pointer (btrfs_item) ─────────────────────
# Immediately follows the header in leaf nodes
# Contains: btrfs_disk_key (17 bytes) + data_offset (4 bytes) + data_size (4 bytes)
ITEM_POINTER_SIZE = 25     # 0x19

# Item pointer field offsets (relative to item start)
IP_KEY_OBJECTID   = 0x00   # 8 bytes
IP_KEY_TYPE       = 0x08   # 1 byte
IP_KEY_OFFSET     = 0x09   # 8 bytes
IP_DATA_OFFSET    = 0x11   # 4 bytes (relative to end of header, 0x65)
IP_DATA_SIZE      = 0x15   # 4 bytes

# ─── Internal Node Key Pointer (btrfs_key_ptr) ──────────────
# Used in internal (non-leaf) nodes
# Contains: btrfs_disk_key (17 bytes) + block_number (8 bytes) + generation (8 bytes)
KEY_PTR_SIZE      = 33     # 0x21

# ─── Item Types (btrfs_disk_key.type) ────────────────────────
BTRFS_INODE_ITEM_KEY      = 0x01   # 1   - inode stat data
BTRFS_INODE_REF_KEY       = 0x0C   # 12  - name → inode mapping (from child)
BTRFS_INODE_EXTREF_KEY    = 0x0D   # 13  - extended inode ref
BTRFS_XATTR_ITEM_KEY      = 0x18   # 24  - extended attributes
BTRFS_ORPHAN_ITEM_KEY     = 0x30   # 48  - orphan inode tracking
BTRFS_DIR_LOG_ITEM_KEY    = 0x3C   # 60
BTRFS_DIR_LOG_INDEX_KEY   = 0x48   # 72
BTRFS_DIR_ITEM_KEY        = 0x54   # 84  - maps name hash → directory entry
BTRFS_DIR_INDEX_KEY       = 0x60   # 96  - maps sequence index → directory entry
BTRFS_EXTENT_DATA_KEY     = 0x6C   # 108 - file extent data
BTRFS_EXTENT_CSUM_KEY     = 0x80   # 128
BTRFS_ROOT_ITEM_KEY       = 0x84   # 132
BTRFS_ROOT_BACKREF_KEY    = 0x90   # 144
BTRFS_ROOT_REF_KEY        = 0x9C   # 156
BTRFS_EXTENT_ITEM_KEY     = 0xA8   # 168
BTRFS_METADATA_ITEM_KEY   = 0xA9   # 169
BTRFS_EXTENT_DATA_REF_KEY = 0xB2   # 178
BTRFS_BLOCK_GROUP_ITEM_KEY= 0xC0   # 192
BTRFS_DEV_EXTENT_KEY      = 0xCC   # 204
BTRFS_DEV_ITEM_KEY        = 0xD8   # 216
BTRFS_CHUNK_ITEM_KEY      = 0xE4   # 228

# ─── File Extent Types ───────────────────────────────────────
BTRFS_FILE_EXTENT_INLINE   = 0
BTRFS_FILE_EXTENT_REG      = 1
BTRFS_FILE_EXTENT_PREALLOC = 2

# ─── File Extent Header Size ─────────────────────────────────
# generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)
FILE_EXTENT_HEADER_SIZE = 21  # 0x15

# ─── Directory Item Header Size ──────────────────────────────
# btrfs_disk_key(17) + transid(8) + data_len(2) + name_len(2) + type(1) = 30 bytes
DIR_ITEM_HEADER_SIZE = 30

# ─── INODE_ITEM Size ─────────────────────────────────────────
INODE_ITEM_SIZE = 160  # bytes

# ─── Tree Object IDs ─────────────────────────────────────────
BTRFS_ROOT_TREE_OBJECTID  = 1
BTRFS_EXTENT_TREE_OBJECTID= 2
BTRFS_CHUNK_TREE_OBJECTID = 3
BTRFS_DEV_TREE_OBJECTID   = 4
BTRFS_FS_TREE_OBJECTID    = 5
BTRFS_ROOT_TREE_DIR_OBJECTID = 6
BTRFS_CSUM_TREE_OBJECTID  = 7

# ─── File Types (btrfs_dir_item.type) ────────────────────────
BTRFS_FT_UNKNOWN  = 0
BTRFS_FT_REG_FILE = 1
BTRFS_FT_DIR      = 2
BTRFS_FT_CHRDEV   = 3
BTRFS_FT_BLKDEV   = 4
BTRFS_FT_FIFO     = 5
BTRFS_FT_SOCK     = 6
BTRFS_FT_SYMLINK  = 7
BTRFS_FT_XATTR    = 8

# Human-readable names for item types (for logging)
ITEM_TYPE_NAMES = {
    BTRFS_INODE_ITEM_KEY:      "INODE_ITEM",
    BTRFS_INODE_REF_KEY:       "INODE_REF",
    BTRFS_INODE_EXTREF_KEY:    "INODE_EXTREF",
    BTRFS_XATTR_ITEM_KEY:      "XATTR_ITEM",
    BTRFS_ORPHAN_ITEM_KEY:     "ORPHAN_ITEM",
    BTRFS_DIR_ITEM_KEY:        "DIR_ITEM",
    BTRFS_DIR_INDEX_KEY:       "DIR_INDEX",
    BTRFS_EXTENT_DATA_KEY:     "EXTENT_DATA",
    BTRFS_ROOT_ITEM_KEY:       "ROOT_ITEM",
    BTRFS_ROOT_REF_KEY:        "ROOT_REF",
    BTRFS_EXTENT_ITEM_KEY:     "EXTENT_ITEM",
    BTRFS_CHUNK_ITEM_KEY:      "CHUNK_ITEM",
    BTRFS_DEV_ITEM_KEY:        "DEV_ITEM",
    BTRFS_BLOCK_GROUP_ITEM_KEY:"BLOCK_GROUP_ITEM",
}

FILE_TYPE_NAMES = {
    BTRFS_FT_UNKNOWN:  "unknown",
    BTRFS_FT_REG_FILE: "file",
    BTRFS_FT_DIR:      "dir",
    BTRFS_FT_CHRDEV:   "chrdev",
    BTRFS_FT_BLKDEV:   "blkdev",
    BTRFS_FT_FIFO:     "fifo",
    BTRFS_FT_SOCK:     "sock",
    BTRFS_FT_SYMLINK:  "symlink",
    BTRFS_FT_XATTR:    "xattr",
}
