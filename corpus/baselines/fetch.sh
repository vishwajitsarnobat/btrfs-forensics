#!/bin/sh
# Fetch the pinned inputs of the baseline harness into images/baselines/dl/ (gitignored). No root
# and no package manager: every entry of corpus/baselines/baselines.lock is downloaded with curl
# and checked against its SHA-256. A file that is present with the right hash is not downloaded
# again.
#
# Usage: corpus/baselines/fetch.sh [GROUP ...]     (default: every group)
# Host requirements: curl, sha256sum.
# Environment: BASELINES_DIR (default <repo>/images/baselines), UBUNTU_MIRROR (default: the
# fixed snapshot of corpus/vm/fetch_vm.sh).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${BASELINES_DIR:-$REPO/images/baselines}
LOCK=$HERE/baselines.lock
MIRROR=${UBUNTU_MIRROR:-https://snapshot.ubuntu.com/ubuntu/20260919T000000Z}

for tool in curl sha256sum; do
    command -v "$tool" >/dev/null || { echo "fetch.sh needs $tool on the host" >&2; exit 1; }
done

TAB=$(printf '\t')
hash_ok() {
    [ -f "$1" ] && [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ]
}
wanted() {
    [ -z "$WANT" ] && return 0
    for g in $WANT; do [ "$g" = "$1" ] && return 0; done
    return 1
}

WANT="$*"
fetched=0 have=0
grep -v '^#' "$LOCK" | {
    while IFS=$TAB read -r group sha file src; do
        [ -n "$group" ] || continue
        wanted "$group" || continue
        case $file in /*|*..*) echo "baselines.lock: unsafe file name $file" >&2; exit 1;; esac
        dest=$WORK/dl/$group/$file
        if hash_ok "$dest" "$sha"; then
            have=$((have + 1))
            continue
        fi
        case $src in
            https://*) url=$src ;;
            *) url=$MIRROR/$src ;;
        esac
        echo "fetch $group/$file"
        mkdir -p "$(dirname "$dest")"
        curl -fsSL --retry 3 -o "$dest.part" "$url"
        hash_ok "$dest.part" "$sha" || {
            echo "SHA-256 mismatch for $url" >&2; rm -f "$dest.part"; exit 1; }
        mv "$dest.part" "$dest"
        fetched=$((fetched + 1))
    done
    echo "baseline inputs: $fetched fetched, $have present, in $WORK/dl"
}
