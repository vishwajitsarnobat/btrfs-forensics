#!/bin/sh
# Run one built baseline tool on a read-only copy of an image, inside the pinned guest.
#
# Usage: corpus/baselines/run.sh TOOL IMAGE [OUT_DIR]
#   OUT_DIR defaults to images/baselines/runs/TOOL/<image stem>; an existing one is replaced.
#
# IMAGE is copied under images/baselines/evidence/, the copy is attached with QEMU readonly=on as
# /dev/vdb, and the guest refuses to start the tool unless the kernel sees it read-only. The
# copy's SHA-256 is taken before and after the run and must not change; the copy is then deleted.
# OUT_DIR gets files.tsv and run.tsv (format in corpus/baselines/README.md), files/ (what the tool
# wrote), logs/ and the serial log. Score it with corpus/baselines/score.py.
# Environment: MEM (default 2048), SMP (default 2), TIMEOUT (default 3600), plus vm.sh's.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${BASELINES_DIR:-$REPO/images/baselines}
[ $# -ge 2 ] || { echo "usage: run.sh TOOL IMAGE [OUT_DIR]" >&2; exit 2; }
TOOL=$1 IMAGE=$2
STEM=$(basename "$IMAGE" .img)
OUT=${3:-$WORK/runs/$TOOL/$STEM}
[ -d "$WORK/built/$TOOL/tool" ] || { echo "run.sh: build $TOOL first (build.sh $TOOL)" >&2; exit 1; }
[ -f "$IMAGE" ] || { echo "run.sh: no image $IMAGE" >&2; exit 1; }

J=$WORK/jobs/run-$TOOL-$STEM
rm -rf "$J" "$OUT"
mkdir -p "$J/deps" "$J/dl" "$WORK/evidence" "$(dirname "$OUT")"
cp "$HERE/guest/job.sh" "$HERE/guest/fls-tree.awk" "$J/"
printf 'MODE=run\nTOOL=%s\n' "$TOOL" > "$J/job.env"
cp -R "$HERE/tools/$TOOL" "$J/recipe"
ln -s "$WORK/built/$TOOL/tool" "$J/tool"
if [ -r "$HERE/tools/$TOOL/needs" ]; then
    for dep in $(cat "$HERE/tools/$TOOL/needs"); do
        ln -s "$WORK/built/$dep/tool" "$J/deps/$dep"
    done
fi

COPY=$WORK/evidence/$TOOL-$STEM.img
rm -f "$COPY"
cp "$IMAGE" "$COPY"
chmod a-w "$COPY"
before=$(sha256sum "$COPY" | cut -d' ' -f1)
status=0
"$HERE/vm.sh" "$J" "$OUT" "$COPY" > /dev/null || status=$?
after=$(sha256sum "$COPY" | cut -d' ' -f1)
rm -f "$COPY"
rm -rf "$J"
[ "$before" = "$after" ] || { echo "run.sh: the evidence copy changed during the run" >&2; exit 1; }
[ -r "$OUT/run.tsv" ] || { echo "run.sh: $TOOL wrote no run.tsv, see $OUT" >&2; exit 1; }
{
    printf 'image\t%s\n' "$STEM"
    printf 'image_sha256\t%s\n' "$before"
    printf 'source_sha256\t%s\n' "$(awk -F '\t' -v t="$TOOL" '$1 == t {print $2; exit}' \
        "$WORK/built/$TOOL/pins.tsv")"
    printf 'guest_mem_mib\t%s\n' "${MEM:-2048}"
    printf 'guest_cpus\t%s\n' "${SMP:-2}"
    printf 'host_cpu\t%s\n' "$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
    printf 'qemu\t%s\n' "$(${QEMU:-qemu-system-x86_64} --version | head -n 1)"
} >> "$OUT/run.tsv"
echo "$OUT"
exit $status
