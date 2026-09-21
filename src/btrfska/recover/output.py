"""The only place recovered files are written (plan.md M4b, decision 5).

An `OutputTree` owns one output directory, which it creates and which must not exist before.
Everything below it is created relative to a directory descriptor, with `O_CREAT | O_EXCL |
O_NOFOLLOW` for files and `O_NOFOLLOW` for every directory hop. So:
- nothing that exists is ever opened for writing: not an evidence image, not an earlier output;
- no symlink is followed, and none is ever created here, so no path leaves the directory;
- names come from the caller as single components; a component holding `/` or NUL, or equal to
  `.` or `..`, is refused here as well, whatever the caller did to clean it.

This module imports nothing of the image layer and takes no image path. The read-only test
(tests/test_readonly.py) allowlists it next to `substrate/image.py` and `catalog/db.py`, and
checks that its only write-capable calls are these `os.open` calls and the `os.ftruncate` that
sets the length of a file ending in a hole.
"""

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_ZEROS = bytes(1 << 16)
PERMISSION_BITS = 0o777  # setuid, setgid and sticky are recorded, never applied
PARTIAL = b".partial"  # the suffix of a file that is not, or not yet, completely read


class OutputError(ValueError):
    """The output directory or a name in it cannot be used."""


def _component(name: bytes) -> bytes:
    if not name or name in (b".", b"..") or b"/" in name or b"\0" in name or len(name) > 255:
        raise OutputError(f"unusable file name {name!r}")
    return name


class FileSink:
    """One new file being written: bytes and zero runs in order, hashed as they go."""

    def __init__(self, fd: int) -> None:
        self.fd, self.written, self._hash = fd, 0, hashlib.sha256()

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[os.write(self.fd, view) :]
        self._hash.update(data)
        self.written += len(data)

    def zeros(self, length: int) -> None:
        """A run of zeros, left as a hole in the output file."""
        remaining = length
        while remaining:
            step = min(remaining, len(_ZEROS))
            self._hash.update(_ZEROS[:step])
            remaining -= step
        self.written += length
        os.lseek(self.fd, length, os.SEEK_CUR)

    def close(self, mode: int | None, times_ns: tuple[int, int] | None) -> str:
        """Fix the length, apply permission bits and (atime, mtime); the SHA-256 of the content."""
        try:
            if os.fstat(self.fd).st_size < self.written:  # the file ends in a hole
                os.ftruncate(self.fd, self.written)
            _apply(self.fd, mode, times_ns)
        finally:
            os.close(self.fd)
            self.fd = -1
        return self._hash.hexdigest()


def _apply(fd: int, mode: int | None, times_ns: tuple[int, int] | None) -> None:
    if mode is not None:
        os.fchmod(fd, mode & PERMISSION_BITS)
    if times_ns is not None:
        os.utime(fd, ns=times_ns)


class OutputTree:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        if self.root.exists() or self.root.is_symlink():
            raise OutputError(f"{self.root} already exists; recovery never writes into it")
        if not self.root.parent.is_dir():
            raise OutputError(f"{self.root.parent} is not a directory")
        os.mkdir(self.root, 0o700)
        self.fd = os.open(self.root, _DIR_FLAGS)
        self._manifest = os.open(b"manifest.jsonl", _FILE_FLAGS, 0o600, dir_fd=self.fd)
        self._dirs: list[tuple[tuple[bytes, ...], int | None, tuple[int, int] | None]] = []

    def close(self) -> None:
        """Apply the directories' metadata, deepest first, and release the descriptors."""
        if self.fd < 0:
            return
        for parts, mode, times_ns in sorted(self._dirs, key=lambda d: -len(d[0])):
            fd = self._descend(parts, create=False)
            try:
                # a directory the owner cannot enter or list would make the output unreadable
                _apply(fd, None if mode is None else mode | 0o700, times_ns)
            finally:
                os.close(fd)
        os.close(self._manifest)
        os.close(self.fd)
        self.fd = -1

    def __enter__(self) -> OutputTree:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _descend(self, parts: Iterable[bytes], *, create: bool) -> int:
        """A descriptor of the directory `parts` below the root; the caller closes it."""
        fd = os.dup(self.fd)
        try:
            for part in parts:
                name = _component(part)
                if create:
                    try:
                        os.mkdir(name, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                try:
                    below = os.open(name, _DIR_FLAGS, dir_fd=fd)
                except OSError as exc:  # a file, or a symlink somebody planted: not a directory
                    raise OutputError(f"{part!r} cannot be used as a directory: {exc}") from exc
                os.close(fd)
                fd = below
        except BaseException:
            os.close(fd)
            raise
        return fd

    def make_dir(
        self, parts: tuple[bytes, ...], mode: int | None, times_ns: tuple[int, int] | None
    ) -> None:
        """Create a directory and its parents; its metadata is applied when the tree closes."""
        os.close(self._descend(parts, create=True))
        self._dirs.append((parts, mode, times_ns))

    def create(self, parts: tuple[bytes, ...]) -> FileSink:
        """A new file at `parts` + PARTIAL; FileExistsError when that name is taken.

        Every file starts under its `.partial` name, so an interrupted run leaves nothing that
        looks complete; `promote` gives a completely read file its real name.
        """
        *parents, name = parts
        partial = _component(_component(name) + PARTIAL)
        fd = self._descend(parents, create=True)
        try:
            return FileSink(os.open(partial, _FILE_FLAGS, 0o600, dir_fd=fd))
        finally:
            os.close(fd)

    def promote(self, parts: tuple[bytes, ...]) -> None:
        """Rename `parts` + PARTIAL to `parts`, never replacing anything (link, then unlink)."""
        *parents, name = parts
        fd = self._descend(parents, create=False)
        try:
            os.link(name + PARTIAL, _component(name), src_dir_fd=fd, dst_dir_fd=fd)
            os.unlink(name + PARTIAL, dir_fd=fd)
        finally:
            os.close(fd)

    def record(self, entry: dict) -> None:
        """One line of manifest.jsonl."""
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        view = memoryview(line)
        while view:
            view = view[os.write(self._manifest, view) :]
