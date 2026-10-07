"""What the hiding detector reports: one `Finding` per place where hidden bytes may be.

A finding names its technique, where the bytes are on the image (`physical`, `length`), how many
of them are not zero, a short preview, and the evidence in words: what the rule saw and why a
filesystem written only by mkfs.btrfs and the kernel does not look like that. `detail` holds the
technique's own keys (mirror, tree, inode, ...). The techniques, their rules and their kernel
citations are listed in detect.py.
"""

from dataclasses import asdict, dataclass, field

import numpy as np

PREVIEW = 32  # bytes shown from the first non-zero byte
MAX_RUNS = 16  # runs of non-zero bytes listed per area; the count is always complete


@dataclass(frozen=True)
class Finding:
    technique: str
    physical: int  # image offset of the area the rule examined
    length: int  # its length in bytes
    nonzero: int  # bytes of it that are not zero (for a field rule: the field's bytes)
    where: str  # the area in words, e.g. "superblock mirror 0, reserved bytes 0x264-0x32a"
    evidence: str  # what the rule saw, and why a clean filesystem does not show it
    preview: str = ""  # hex of up to PREVIEW bytes from the first non-zero byte
    text: str = ""  # the same bytes as text, unprintable bytes as '.'
    detail: dict = field(default_factory=dict)

    def record(self) -> dict:
        return {"record": "finding", **asdict(self)}


def nonzero(data) -> int:
    return len(data) - bytes(data).count(0)


def preview(data) -> tuple[str, str]:
    """(hex, text) of up to PREVIEW bytes from the first non-zero byte of `data`, without the
    zero bytes that end them."""
    raw = bytes(data)
    stripped = raw.lstrip(b"\0")
    shown = stripped[:PREVIEW].rstrip(b"\0")
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in shown)
    return shown.hex(), text


def area_finding(technique: str, physical: int, data, where: str, evidence: str, **detail):
    """A finding over a byte area whose non-zero bytes are the evidence; None when all zero."""
    count = nonzero(data)
    if not count:
        return None
    hex_, text = preview(data)
    first = len(data) - len(bytes(data).lstrip(b"\0"))
    return Finding(
        technique, physical, len(data), count, where, evidence, hex_, text,
        {"first_nonzero": physical + first, **detail},
    )  # fmt: skip


def nonzero_runs(img, start: int, end: int, unit: int = 4096, window: int = 1 << 24):
    """(runs, non-zero bytes, runs not listed) of [start, end) of the image. A run is the [first,
    end) offsets of consecutive `unit`-sized blocks holding a non-zero byte; at most MAX_RUNS are
    listed, and the byte count covers every run. Read a window at a time, without copying."""
    runs: list[list[int]] = []
    count = more = 0
    tail = None  # end of the last run seen, listed or not
    position = start
    while position < end:
        stop = min(position + window, end)
        data = np.frombuffer(img.mmap, dtype=np.uint8, count=stop - position, offset=position)
        whole = (len(data) // unit) * unit
        blocks = data[:whole].reshape(-1, unit) if whole else data[:0].reshape(0, unit)
        flags = blocks.any(axis=1) if whole else np.zeros(0, dtype=bool)
        count += int(np.count_nonzero(data))
        marks = [position + int(i) * unit for i in np.flatnonzero(flags)]
        if whole < len(data) and data[whole:].any():
            marks.append(position + whole)
        for mark in marks:
            block_end = min(mark + unit, stop)
            if mark == tail:
                if runs and runs[-1][1] == mark:
                    runs[-1][1] = block_end
            elif len(runs) < MAX_RUNS:
                runs.append([mark, block_end])
            else:
                more += 1
            tail = block_end
        position = stop
    return [tuple(run) for run in runs], count, more
