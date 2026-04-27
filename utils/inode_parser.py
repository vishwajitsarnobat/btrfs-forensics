# utils/inode_parser.py
# Parses btrfs_inode_item structures to extract file metadata
# (timestamps, size, permissions, etc.)
#
# btrfs_inode_item is 160 bytes and contains the traditional stat(2) data.
# Reference: https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html#inode-item-01

import struct
from datetime import datetime, timezone


def parse_inode_item(data):
    """
    Parses a 160-byte btrfs_inode_item structure.

    Layout:
        Offset  Size  Field
        0x00     8    generation
        0x08     8    transid
        0x10     8    size (file size in bytes)
        0x18     8    nbytes (on-disk bytes used)
        0x20     8    block_group
        0x28     4    nlink
        0x2C     4    uid
        0x30     4    gid
        0x34     4    mode
        0x38     8    rdev
        0x40     8    flags
        0x48     8    sequence

        # Timestamps: each is 12 bytes = seconds(8, signed) + nanoseconds(4)
        0x50    12    atime (access time)
        0x5C    12    ctime (change time)
        0x68    12    mtime (modification time)
        0x74    12    otime (creation time)

        0x80    24    reserved
        Total: 160 (0xA0) bytes

    Returns a dict with parsed fields, or None if data is too short.
    """
    if len(data) < 160:
        return None

    generation = struct.unpack_from("<Q", data, 0x00)[0]
    transid    = struct.unpack_from("<Q", data, 0x08)[0]
    size       = struct.unpack_from("<Q", data, 0x10)[0]
    nbytes     = struct.unpack_from("<Q", data, 0x18)[0]
    block_group= struct.unpack_from("<Q", data, 0x20)[0]
    nlink      = struct.unpack_from("<I", data, 0x28)[0]
    uid        = struct.unpack_from("<I", data, 0x2C)[0]
    gid        = struct.unpack_from("<I", data, 0x30)[0]
    mode       = struct.unpack_from("<I", data, 0x34)[0]
    rdev       = struct.unpack_from("<Q", data, 0x38)[0]
    flags      = struct.unpack_from("<Q", data, 0x40)[0]
    sequence   = struct.unpack_from("<Q", data, 0x48)[0]

    atime = _parse_timespec(data, 0x50)
    ctime = _parse_timespec(data, 0x5C)
    mtime = _parse_timespec(data, 0x68)
    otime = _parse_timespec(data, 0x74)

    return {
        "generation": generation,
        "transid":    transid,
        "size":       size,
        "nbytes":     nbytes,
        "block_group":block_group,
        "nlink":      nlink,
        "uid":        uid,
        "gid":        gid,
        "mode":       mode,
        "rdev":       rdev,
        "flags":      flags,
        "sequence":   sequence,
        "atime":      atime,
        "ctime":      ctime,
        "mtime":      mtime,
        "otime":      otime,
    }


def _parse_timespec(data, offset):
    """
    Parses a btrfs_timespec (12 bytes):
        seconds     (8 bytes, signed LE int64)
        nanoseconds (4 bytes, unsigned LE uint32)

    Returns a dict with raw values and a human-readable ISO string.
    """
    sec  = struct.unpack_from("<q", data, offset)[0]      # signed
    nsec = struct.unpack_from("<I", data, offset + 8)[0]   # unsigned

    # Convert to human-readable if reasonable
    try:
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        iso = dt.isoformat()
    except (OSError, OverflowError, ValueError):
        iso = f"<invalid: sec={sec}>"

    return {
        "sec":  sec,
        "nsec": nsec,
        "iso":  iso,
    }


def format_mode(mode):
    """
    Converts a numeric mode (from stat) to a human-readable permission
    string like 'drwxr-xr-x' or '-rw-r--r--'.
    """
    import stat

    file_type = stat.S_IFMT(mode)
    type_char = {
        stat.S_IFDIR:  'd',
        stat.S_IFREG:  '-',
        stat.S_IFLNK:  'l',
        stat.S_IFCHR:  'c',
        stat.S_IFBLK:  'b',
        stat.S_IFIFO:  'p',
        stat.S_IFSOCK: 's',
    }.get(file_type, '?')

    perms = ""
    for who in range(2, -1, -1):
        shift = who * 3
        perms += 'r' if mode & (stat.S_IRUSR >> (2 - who) * 3) else '-'
        perms += 'w' if mode & (stat.S_IWUSR >> (2 - who) * 3) else '-'
        perms += 'x' if mode & (stat.S_IXUSR >> (2 - who) * 3) else '-'

    return type_char + perms
