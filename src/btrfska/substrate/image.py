"""Read-only access to evidence images.

This module is the only place in btrfska that opens an evidence file. The
file descriptor is opened O_RDONLY and mapped with ACCESS_READ, so any
attempted write through the map raises TypeError.
"""

import hashlib
import mmap
import os


class ImageHandle:
    """A read-only memory map over an image file or block device."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        self.fd = os.open(self.path, os.O_RDONLY)
        try:
            # lseek, not fstat: block devices report st_size 0.
            self.size = os.lseek(self.fd, 0, os.SEEK_END)
            self.mmap = mmap.mmap(self.fd, self.size, access=mmap.ACCESS_READ)
        except BaseException:
            os.close(self.fd)
            raise

    def sha256(self) -> str:
        """Hex SHA-256 of the whole image."""
        return hashlib.sha256(self.mmap).hexdigest()

    def close(self) -> None:
        self.mmap.close()
        os.close(self.fd)

    def __enter__(self) -> ImageHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_image(path: str | os.PathLike[str]) -> ImageHandle:
    """Open an evidence image read-only."""
    return ImageHandle(path)
