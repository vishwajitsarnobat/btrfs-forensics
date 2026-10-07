"""The ground truth of a scenario image: its serial log, parsed (docs/plan.md M7a).

    uv run python corpus/groundtruth.py images/scenarios/mx_delete_none.log   # JSON on stdout

The log of a matrix image (corpus/vm/scenarios/matrix.guest.sh) holds:
  - what the host did: `=== HOST-MKFS` (mkfs version), `=== HOST-MKFS-ARGS`, `=== HOST-SIZE`,
    `=== HOST-DEVICES`, `=== HOST-DISCARD` (corpus/vm/make_image.sh);
  - the guest kernel (`=== GUEST`), the mount options asked for (`=== SCENARIO`) and the effective
    ones, from /proc/mounts (`=== MOUNTED`);
  - the configuration (`=== MATRIX axis=value ...`) and what reclaim did (`=== RECLAIM`);
  - every file state: `=== EVENT KIND INODE GENERATION PATH [NEW PATH] [sha256=HEX]`, the format of
    scenario deep (deep logs carry no sha256), and `=== PHASE NAME GENERATION`;
  - before each sync's events, `=== COMMIT GENERATION PREVIOUS`: those events happened after
    generation PREVIOUS and are on disk from GENERATION on (exactly GENERATION when it is
    PREVIOUS + 1). Deep logs have no such line.

A malformed line of a known kind raises LogError with its line number; lines of other kinds
(the guest's console, the boot firmware) are ignored. `check` then tests the history for
consistency: generations never go back, a path is created before it changes, and so on.
"""

import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

KINDS = ("create", "modify", "overwrite", "rename", "delete", "unlink")
CONTENT_KINDS = ("create", "modify", "overwrite")
_SHA = re.compile(r"sha256=([0-9a-f]{64})")
_PATH = re.compile(r"[^\s=]+")
_PAIR = re.compile(r"([a-z_0-9]+)=(\S*)")


class LogError(ValueError):
    pass


@dataclass(frozen=True)
class Event:
    kind: str
    inode: int
    generation: int
    path: str
    new_path: str | None = None
    sha256: str | None = None
    after: int | None = None  # the event happened in a generation above this one (COMMIT line)

    @property
    def exact(self) -> bool:
        """Whether GENERATION is the transaction the event happened in, not only a bound."""
        return self.after is not None and self.after + 1 == self.generation


@dataclass
class Truth:
    host: dict[str, str] = field(default_factory=dict)
    guest_kernel: str | None = None
    mount_options_asked: str | None = None
    mount_options: list[str] = field(default_factory=list)  # effective, from /proc/mounts
    matrix: dict[str, str] = field(default_factory=dict)
    reclaim: list[dict[str, str]] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    commits: list[tuple[int, int]] = field(default_factory=list)  # (generation, previous)
    phases: list[tuple[str, int]] = field(default_factory=list)
    done: bool = False


def _event(words: list[str], number: int, after: int | None) -> Event:
    if len(words) < 4 or words[0] not in KINDS or not words[1].isdigit() or not words[2].isdigit():
        raise LogError(f"line {number}: malformed EVENT: {' '.join(words)}")
    kind, inode, generation, *rest = words
    digest = None
    if rest and (match := _SHA.fullmatch(rest[-1])):
        digest = match[1]
        rest = rest[:-1]
    if not rest or len(rest) > 2 or not all(_PATH.fullmatch(p) for p in rest):
        raise LogError(f"line {number}: malformed EVENT path: {' '.join(words)}")
    if (len(rest) == 2) != (kind == "rename"):
        raise LogError(f"line {number}: only a rename has a new path: {' '.join(words)}")
    if digest is not None and kind not in CONTENT_KINDS:
        raise LogError(f"line {number}: a {kind} has no content hash")
    return Event(kind, int(inode), int(generation), rest[0], rest[1] if len(rest) == 2 else None,
                 digest, after)  # fmt: skip


def parse(text: str) -> Truth:
    truth, after = Truth(), None
    for number, raw in enumerate(text.splitlines(), 1):
        # the serial console can glue terminal escapes in front of a marker
        start = raw.find("=== ")
        if start < 0:
            continue
        line = raw[start + 4 :].strip()
        tag, _, rest = line.partition(" ")
        words = rest.split()
        if tag == "EVENT":
            truth.events.append(_event(words, number, after))
        elif tag == "COMMIT":
            if len(words) != 2 or not all(w.isdigit() for w in words):
                raise LogError(f"line {number}: malformed COMMIT: {rest}")
            truth.commits.append((int(words[0]), int(words[1])))
            after = int(words[1])
        elif tag == "PHASE":
            if len(words) != 2 or not words[1].isdigit():
                raise LogError(f"line {number}: malformed PHASE: {rest}")
            truth.phases.append((words[0], int(words[1])))
        elif tag.startswith("HOST-"):
            truth.host[tag.removeprefix("HOST-").lower().replace("-", "_")] = rest
        elif tag == "GUEST":
            truth.guest_kernel = (
                words[2] if words[:2] == ["Linux", "version"] and len(words) > 2 else rest
            )
        elif tag == "SCENARIO" and "MOUNTOPTS" in words:
            truth.mount_options_asked = rest.split("MOUNTOPTS", 1)[1].strip()
        elif tag == "MOUNTED":
            if len(words) < 4:
                raise LogError(f"line {number}: malformed MOUNTED: {rest}")
            truth.mount_options = words[3].split(",")
        elif tag in ("MATRIX", "RECLAIM"):
            pairs = dict(_PAIR.findall(rest))
            if not pairs:
                raise LogError(f"line {number}: malformed {tag}: {rest}")
            if tag == "MATRIX":
                truth.matrix = pairs
            else:
                truth.reclaim.append(pairs)
        elif tag == "SCENARIO-DONE":
            truth.done = True
    return truth


def check(truth: Truth) -> list[str]:
    """Inconsistencies in the history of `truth`; empty when it is consistent."""
    problems, live, last = [], {}, 0
    for event in truth.events:
        where = f"{event.kind} {event.path} at generation {event.generation}"
        if event.generation < last:
            problems.append(f"{where}: generation goes back from {last}")
        if event.after is not None and event.after >= event.generation:
            problems.append(f"{where}: not after generation {event.after}")
        last = max(last, event.generation)
        if event.kind == "create":
            if event.path in live:
                problems.append(f"{where}: the path exists already")
            live[event.path] = event.inode
            continue
        if live.get(event.path) != event.inode:
            problems.append(f"{where}: no live path with inode {event.inode}")
            continue
        if event.kind == "rename":
            if event.new_path in live:
                problems.append(f"{where}: {event.new_path} exists already")
            live[event.new_path] = live.pop(event.path)
        elif event.kind in ("delete", "unlink"):
            del live[event.path]
    for event in truth.events:
        if event.kind in ("modify", "overwrite") and event.sha256 is None:
            problems.append(f"{event.kind} {event.path}: no content hash")
    return problems


def final_states(truth: Truth) -> dict[str, Event]:
    """The last content event of every path still live after the last event, by path."""
    states: dict[str, Event] = {}
    for event in truth.events:
        if event.kind in CONTENT_KINDS:
            states[event.path] = event
        elif event.kind == "rename" and event.path in states:
            states[event.new_path] = states.pop(event.path)
        elif event.kind in ("delete", "unlink"):
            states.pop(event.path, None)
    return states


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: groundtruth.py LOG", file=sys.stderr)
        return 2
    truth = parse(Path(args[0]).read_text(errors="replace"))
    print(json.dumps(asdict(truth) | {"problems": check(truth)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
