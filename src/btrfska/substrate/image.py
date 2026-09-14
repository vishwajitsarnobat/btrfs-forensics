"""Read-only access to evidence images.

This module is the only place in btrfska that opens an evidence file. The
file descriptor is opened O_RDONLY and mapped with ACCESS_READ, so any
attempted write through the map raises TypeError.
"""

import hashlib
import mmap
import os
import stat


class ImageHandle:
    """A read-only memory map over an image file or block device."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        # O_NONBLOCK so a FIFO cannot hang the open; the type is checked on the fd itself,
        # which also rules out races between checking a path and opening it.
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            mode = os.fstat(self.fd).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISBLK(mode)):
                raise ValueError(f"not a regular file or block device: {self.path}")
            os.set_blocking(self.fd, True)
            # lseek, not fstat: block devices report st_size 0.
            self.size = os.lseek(self.fd, 0, os.SEEK_END)
            if self.size == 0:
                raise ValueError(f"empty image: {self.path}")
            self.mmap = mmap.mmap(self.fd, self.size, access=mmap.ACCESS_READ)
        except BaseException:
            os.close(self.fd)
            raise

    def sha256(self) -> str:
        """Hex SHA-256 of the whole image."""
        return hashlib.sha256(self.mmap).hexdigest()

    def close(self) -> None:
        """Release the map and descriptor. Safe to call more than once."""
        if self.fd < 0:
            return
        self.mmap.close()
        os.close(self.fd)
        self.fd = -1

    def __enter__(self) -> ImageHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_image(path: str | os.PathLike[str]) -> ImageHandle:
    """Open an evidence image read-only."""
    return ImageHandle(path)
