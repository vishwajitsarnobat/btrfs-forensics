#!/bin/sh
# The demo of docs/demo/README.md, in order. Run from the repository root after ./setup.sh.
# Output goes under images/scratch/demo/; no image is written.
set -e
OUT=images/scratch/demo
mkdir -p $OUT
rm -rf $OUT/deep.db $OUT/deep-out

echo "## 1. Trust gate: every superblock copy validated; unknown features refused"
uv run btrfska info sandbox.img | sed -n '1,10p'
uv run btrfska info images/scenarios/m1_mirror_damage.img | sed -n '4,9p'
uv run btrfska info images/scenarios/m1_unknown_incompat.img | tail -2 || true

echo; echo "## 2. Every physical copy checked: one corrupt DUP copy reported, the good one used"
uv run btrfska walk images/scenarios/m1_badnode.img --root current --tree 256 | head -1 | python3 -c '
import json,sys; n=json.loads(sys.stdin.read())["node"]
print("node", n["bytenr"], "valid", n["valid"])
for c in n["copies"]: print("  mirror", c["mirror"], "physical", c["physical"], "valid", c["valid"], "failed:", [k for k,v in c["checks"].items() if v is False])'

echo; echo "## 3. Read one LZO-compressed file with a provenance record per extent"
uv run btrfska cat images/scenarios/m1_lzo.img --inode 257 --tree 256 2>$OUT/cat.err | head -c 100; echo
head -1 $OUT/cat.err | cut -c1-300

echo; echo "## 4. Scan: every tree block on the device, even in removed chunks"
uv run btrfska scan images/scenarios/m4_deep.img | head -4

echo; echo "## 5. Old roots: every state the scan found, not only the superblock and its four backups"
uv run btrfska roots images/scenarios/m4_deep.img | sed -n '5,12p'

echo; echo "## 6. The evidence database, one pass, chain of custody"
uv run btrfska catalog build images/scenarios/m4_deep.img --db $OUT/deep.db

echo; echo "## 7. Recover every state, orphan leaf and log tree"
uv run btrfska recover images/scenarios/m4_deep.img --db $OUT/deep.db --out $OUT/deep-out --root all --tree all --orphans --logs 2>/dev/null | tail -2

echo; echo "## 8. Against the ground truth the guest logged while it ran"
uv run python docs/demo/check_truth.py $OUT/deep-out/manifest.jsonl images/scenarios/m4_deep.log

echo; echo "## 9. The lifecycle of one deleted file"
uv run btrfska timeline $OUT/deep.db 2>/dev/null | grep -A3 'victim_4.txt'

echo; echo "## 10. The image is unchanged"
sha256sum images/scenarios/m4_deep.img
