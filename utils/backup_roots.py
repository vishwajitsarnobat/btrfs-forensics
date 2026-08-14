# utils/backup_roots.py
# Superblock backup-root parsing (M1 — anchored historical walking).
#
# Btrfs writes up to 4 copies of its most important tree roots into the
# superblock at every transaction commit. Each `btrfs_root_backup` records
# the logical address (and generation) of the tree/extent/fs/dev/csum roots
# as of that commit, so the backups are a *history* of filesystem states:
# the newest may equal the current state, the older ones reference complete
# trees that the live superblock no longer points to.
#
# Layout (verified empirically on sandbox.img):
#   - struct btrfs_root_backup: 0xA8 (168) bytes, packed/unaligned fields
#   - 4 entries at superblock offsets 0xB2B, 0xBD3, 0xC7B, 0xD23
#   - field offsets: tree_root@0x00, tree_root_gen@0x08, chunk_root@0x10,
#     chunk_root_gen@0x18, extent_root@0x20, extent_root_gen@0x28,
#     fs_root@0x30, fs_root_gen@0x38, dev_root@0x40, dev_root_gen@0x48,
#     csum_root@0x50, csum_root_gen@0x58, total_bytes@0x60, bytes_used@0x68,
#     num_devices@0x70
#
# The parser validates every referenced root by CRC-checking the node at its
# logical address (translated through the chunk map) and verifying the owner
# field, so garbage slots are never treated as evidence.

import struct
from .constants import (
    SUPERBLOCK_OFFSET,
    BTRFS_ROOT_TREE_OBJECTID, BTRFS_EXTENT_TREE_OBJECTID,
    BTRFS_CHUNK_TREE_OBJECTID, BTRFS_FS_TREE_OBJECTID,
)
from .chunk_parser import translate_logical_to_physical
from .crc32c import crc32c

# Canonical slots in the superblock for this format generation.
BACKUP_ROOT_SLOTS = (0xB2B, 0xBD3, 0xC7B, 0xD23)
BACKUP_ROOT_STRIDE = 0xA8

# (field name, offset within btrfs_root_backup)
BACKUP_ROOT_FIELDS = (
    ("tree_root",       0x00), ("tree_root_gen",   0x08),
    ("chunk_root",      0x10), ("chunk_root_gen",  0x18),
    ("extent_root",     0x20), ("extent_root_gen", 0x28),
    ("fs_root",         0x30), ("fs_root_gen",     0x38),
    ("dev_root",        0x40), ("dev_root_gen",    0x48),
    ("csum_root",       0x50), ("csum_root_gen",   0x58),
    ("total_bytes",     0x60), ("bytes_used",      0x68),
    ("num_devices",     0x70),
)

# owner id expected for each root type (0 = don't check)
_ROOT_OWNERS = {
    "tree_root":   BTRFS_ROOT_TREE_OBJECTID,
    "chunk_root":  BTRFS_CHUNK_TREE_OBJECTID,
    "extent_root": BTRFS_EXTENT_TREE_OBJECTID,
    "fs_root":     BTRFS_FS_TREE_OBJECTID,
}


def _read_superblock(image_path):
    with open(image_path, "rb") as f:
        f.seek(SUPERBLOCK_OFFSET)
        return f.read(4096)


def _parse_slot(raw_sb, slot):
    """Parse the btrfs_root_backup at the given superblock-relative slot."""
    entry = {}
    for name, off in BACKUP_ROOT_FIELDS:
        entry[name] = struct.unpack_from("<Q", raw_sb, slot + off)[0]
    return entry


def _node_matches(image_path, sb_data, laddr, want_owner):
    """CRC-valid node at logical address with the expected owner?"""
    if laddr == 0:
        return False
    phys = translate_logical_to_physical(laddr, sb_data["chunk_map"])
    if phys is None:
        return False
    nodesize = sb_data["nodesize"]
    with open(image_path, "rb") as f:
        f.seek(phys)
        header = f.read(101)
        if len(header) < 101:
            return False
        if header[0x20:0x30] != sb_data["fsid"]:
            return False
        f.seek(phys)
        node_bytes = f.read(nodesize)
        if len(node_bytes) < nodesize:
            return False
        stored_csum = struct.unpack_from("<I", node_bytes, 0)[0]
        if stored_csum != crc32c(node_bytes[32:]):
            return False
        if want_owner is not None:
            owner = struct.unpack_from("<Q", header, 0x58)[0]
            return owner == want_owner
    return True


def validate_backup_entry(image_path, sb_data, entry):
    """
    Determine which roots of a parsed backup entry point to CRC-valid nodes
    with the expected owners. Returns a set of valid root names.
    """
    valid = set()
    for name, want_owner in _ROOT_OWNERS.items():
        if _node_matches(image_path, sb_data, entry[name], want_owner):
            valid.add(name)
    return valid


def parse_backup_roots(image_path, sb_data):
    """
    Parse and validate the backup roots from the primary superblock.

    Returns a list of dicts (one per populated slot), each with:
        - the parsed fields (tree_root, tree_root_gen, ..., num_devices)
        - 'slot': superblock-relative offset
        - 'valid_roots': set of root names that passed CRC+owner validation
        - 'gen': the fs tree generation (0 if none)

    Entries with no valid roots and zeroed tree_root are omitted.
    """
    raw_sb = _read_superblock(image_path)
    total_bytes = sb_data["total_bytes"]
    backups = []

    for slot in BACKUP_ROOT_SLOTS:
        entry = _parse_slot(raw_sb, slot)
        entry["slot"] = slot

        # Skip slots that were never populated for this filesystem.
        if entry["total_bytes"] not in (0, total_bytes):
            continue
        if entry["num_devices"] == 0 and entry["tree_root"] == 0:
            continue

        entry["valid_roots"] = validate_backup_entry(image_path, sb_data, entry)
        entry["gen"] = entry["fs_root_gen"]

        # Only surface entries that reference at least one real tree.
        if entry["valid_roots"] or entry["tree_root"]:
            backups.append(entry)

    return backups
