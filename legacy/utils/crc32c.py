# utils/crc32c.py
# Pure-Python CRC32c (Castagnoli) implementation — zero dependencies.
#
# Btrfs uses CRC32c (polynomial 0x82F63B78) for all on-disk checksums.
# The checksum is stored in the first 4 bytes of the 32-byte csum field
# in every node header (bytes 0x00–0x03). The remaining 28 bytes are zero.
# The CRC covers bytes 32 onward (everything after the csum field).
#
# Reference: https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html

# Precompute the CRC32c lookup table at import time.
# Polynomial: 0x82F63B78 (Castagnoli, reflected)
_TABLE = [0] * 256
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ 0x82F63B78
        else:
            _crc >>= 1
    _TABLE[_i] = _crc


def crc32c(data: bytes) -> int:
    """
    Compute the CRC32c (Castagnoli) checksum of the given data.

    Returns a 32-bit unsigned integer.
    """
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF
