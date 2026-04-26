# utils/constants.py

# Superblock Constants
SUPERBLOCK_OFFSET = 0x10000
MAGIC_NUMBER = b"_BHRfS_M"

# B-Tree Node Constants
NODE_HEADER_SIZE = 101
ITEM_POINTER_SIZE = 25

# All the below types are inode types, they are stored in inode tree or file tree
# Item Types
BTRFS_INODE_ITEM_KEY = 1
BTRFS_DIR_ITEM_KEY = 84
BTRFS_EXTENT_DATA_KEY = 108

# Directory Items
BTRFS_DIR_ITEM_KEY = 84    # Type 0x54: Maps a string name to an Inode
BTRFS_DIR_INDEX_KEY = 96   # Type 0x60: Same as DIR_ITEM but indexed by sequence


