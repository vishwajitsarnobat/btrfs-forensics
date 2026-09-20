"""The only place an evidence database is created or opened.

`create` makes a new database file and nothing else: it refuses a path that already exists, so it
can never overwrite an image, an earlier database or any other file. `open_readonly` opens an
existing database with SQLite's `mode=ro`, which cannot write. No function here takes or touches
an evidence image; images are opened only in `substrate/image.py`.

The read-only test (tests/test_readonly.py) bans `sqlite3.connect` in every other module of
`src/`, as it bans file writes everywhere but here and in `substrate/image.py`.
"""

import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

from btrfska.catalog.schema import DDL, SCHEMA_VERSION


class CatalogError(ValueError):
    """The database path cannot be used, or the file is not a database of this schema."""


def create(path: str | os.PathLike[str]) -> sqlite3.Connection:
    """A new, empty database of the current schema at `path`, which must not exist."""
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise CatalogError(f"{target} already exists; an evidence database is never overwritten")
    if not target.parent.is_dir():
        raise CatalogError(f"{target.parent} is not a directory")
    conn = sqlite3.connect(target)
    try:
        # One writer, one pass, and a partial file is deleted on failure: durability per
        # statement buys nothing here and costs most of the build time.
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(DDL)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except BaseException:
        conn.close()
        discard(target)
        raise
    return conn


def discard(path: str | os.PathLike[str]) -> None:
    """Remove a database this process was building and did not finish."""
    Path(path).unlink(missing_ok=True)


def open_readonly(path: str | os.PathLike[str]) -> sqlite3.Connection:
    """An existing database, opened so that it cannot be written."""
    target = Path(path)
    if not target.is_file():
        raise CatalogError(f"{target} is not a file")
    conn = sqlite3.connect(f"file:{quote(str(target.resolve()))}?mode=ro", uri=True)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        runs = conn.execute("SELECT finished_utc FROM scan_runs").fetchall()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise CatalogError(f"{target} is not a btrfska evidence database: {exc}") from exc
    if version != SCHEMA_VERSION:
        conn.close()
        raise CatalogError(
            f"{target} has schema version {version}; this btrfska reads version {SCHEMA_VERSION}"
        )
    if len(runs) != 1 or runs[0][0] is None:
        conn.close()
        raise CatalogError(f"{target} holds no finished scan run: its build did not complete")
    conn.row_factory = sqlite3.Row
    return conn
