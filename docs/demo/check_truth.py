"""Compare a recovery manifest with the hashes a scenario logged while it ran.

usage: uv run python docs/demo/check_truth.py OUT/manifest.jsonl images/scenarios/m4_deep.log
"""

import collections
import json
import sys
from pathlib import Path


def main(manifest, log):
    truth = {}
    for line in Path(log).read_text().splitlines():
        if line.startswith(("=== VICTIM", "=== FLASH", "=== ORPHAN")):
            _, kind, name, digest, *_ = line.split()
            truth[name] = (kind, digest)

    by_hash = collections.defaultdict(set)
    for line in Path(manifest).read_text().splitlines():
        row = json.loads(line)
        if row.get("status") == "complete" and row.get("sha256"):
            by_hash[row["sha256"]].add(row["source"])

    hit = 0
    for name, (kind, digest) in truth.items():
        sources = sorted(by_hash.get(digest, ()))
        hit += bool(sources)
        verdict = "hash-exact" if sources else "NOT FOUND"
        print(f"{kind:7} {name:22} {verdict:10} {', '.join(sources[:2]) or '-'}")
    print(f"\n{hit} of {len(truth)} ground-truth files recovered hash-exact")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip())
    main(*sys.argv[1:])
