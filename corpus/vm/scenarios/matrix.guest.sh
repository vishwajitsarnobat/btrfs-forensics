# Guest scenario matrix (sourced by /init with the filesystem mounted at $MNT).
# One workload of the M7 corpus matrix (docs/plan.md M7a; host side: scenarios/matrix.sh). The
# kernel command line chooses it, through run_scenario.sh SCENARIO_ARGS:
#
#   sc_op=OP           delete | overwrite | stress | snapshot | balance | defrag
#   sc_reclaim=PCT     0 (default: off) or the bg_reclaim_threshold written to allocation/data
#   sc_idle=SECONDS    0 (default) or how long to wait before the unmount (the async-idle rows)
#
# Every operation starts from the same population in subvolume `data`: 8 inline files, 6 regular
# files from 20 to 170 KiB, 128 KiB of random bytes, one 4.4 MiB file, and 40 bulk files of 1 MiB
# of random bytes. The bulk fills whole data block groups, so deleting most of it drops their
# usage from full to below any reclaim threshold, which is what makes reclaim relocate them.
#
# Ground truth. Every create, modify, overwrite, rename and delete, of files and directories, is
# logged after the sync that committed it, in the format of scenario deep:
#
#   === EVENT KIND INODE GENERATION PATH [NEW PATH] [sha256=HEX]
#
# KIND is create, modify (part of the file rewritten or appended), overwrite (all of it
# replaced), rename or delete. GENERATION is the superblock's generation read after the sync with
# dump-super (which only reads the device): the transaction the change was committed in. PATH is
# relative to the mount point; inode numbers repeat between subvolumes, the path tells them
# apart. sha256= follows every create, modify and overwrite of a regular file: the content in that
# transaction. A workload never changes one file twice in one transaction, so every logged state
# is a committed state. A snapshot logs a create for each file it contains, and its deletion a
# delete for each. Balance, defragmentation and reclaim move extents without changing any file,
# and are logged as `=== PHASE NAME GENERATION`.
#
# Mount with a long commit interval (MOUNT_OPTS commit=300), so that every commit is a sync of
# the scenario's own.
gen() { btrfs inspect-internal dump-super /dev/vda | sed -n 's/^generation[[:space:]]*//p'; }
ino() { stat -c %i "$MNT/$1"; }
sha() { sha256sum < "$MNT/$1" | cut -d' ' -f1; }
PENDING=/tmp/pending
: > $PENDING
# note KIND PATH...: queue an event for the next commit, inode and content read now
note() {
    kind=$1; path=$2
    if [ "$kind" = delete ]; then
        echo "$kind $(ino "$path") $path" >> $PENDING
    elif [ "$kind" = rename ]; then
        echo "$kind $(ino "$3") $path $3" >> $PENDING
    elif [ -f "$MNT/$path" ]; then
        echo "$kind $(ino "$path") $path sha256=$(sha "$path")" >> $PENDING
    else
        echo "$kind $(ino "$path") $path" >> $PENDING
    fi
}
# commit: sync, then log the queued events with the generation that committed them
commit() {
    sync
    g=$(gen)
    while read -r kind inode rest; do echo "=== EVENT $kind $inode $g $rest"; done < $PENDING
    : > $PENDING
}
phase() { echo "=== PHASE $1 $(gen)"; }
# created PATH: note the create of a file just written
created() { note create "$1"; }
# rm_noted PATH...: note the delete of each file, then remove them
rm_noted() { for p in "$@"; do note delete "$p"; done; for p in "$@"; do rm "$MNT/$p"; done; }
# churn: three more commits of a small new file each, so the last changes are behind newer roots
churn() {
    for i in 1 2 3; do echo "churn $i of $1" > $MNT/data/churn_$i; created data/churn_$i; commit; done
}
# data_space: the sysfs directory of the space info that holds data: allocation/data, or
# allocation/mixed on a MIXED_GROUPS filesystem (alloc_name, fs/btrfs/sysfs.c:1902-1931 v7.0)
data_space() {
    for d in /sys/fs/btrfs/*/allocation/data /sys/fs/btrfs/*/allocation/mixed; do
        [ -d "$d" ] && echo "$d"
    done
}
# reclaim_stats: the reclaim knobs and what the reclaim worker did (sysfs.c:906-908, 1023-1046)
reclaim_stats() {
    for d in $(data_space); do
        echo "=== RECLAIM space=${d##*/} bg_reclaim_threshold=$(cat $d/bg_reclaim_threshold)" \
            "dynamic_reclaim=$(cat $d/dynamic_reclaim) periodic_reclaim=$(cat $d/periodic_reclaim)" \
            "reclaim_count=$(cat $d/reclaim_count) reclaim_bytes=$(cat $d/reclaim_bytes)"
    done
}

# settle NAME: let the cleaner thread run, as it does on any mounted filesystem. It drops deleted
# subvolumes, takes block groups off the unused list and queues the reclaim work
# (cleaner_kthread, fs/btrfs/disk-io.c:1420-1499 v7.0), and only the transaction thread wakes
# it, once per commit interval (disk-io.c:1549-1550), which is 300 s here. For 10 s the interval
# is 5 s; a remount wakes the transaction thread (super.c:1566). A deleted subvolume is then
# waited for, at most 120 s more. Nothing is pending when this runs, so the commits it allows
# change no file.
#
# It runs after the population too, and must: a new data block group goes on the unused list
# when it is created, empty, and stays there until the cleaner runs. While it is on that list it
# cannot be queued for reclaim (btrfs_link_bg_list, block-group.c:1535-1548, shares bg_list), so
# a deletion before any cleaner run would never be reclaimed.
settle() {
    mount -o remount,commit=5 $MNT
    sleep 10
    t=0; while [ $t -lt 120 ] && [ -n "$(btrfs subvolume list -d $MNT)" ]; do
        sleep 1; t=$((t + 1))
    done
    mount -o remount,commit=300 $MNT
    sync
    phase settled-$1
}

OP=${sc_op:-delete}
RECLAIM=${sc_reclaim:-0}
IDLE=${sc_idle:-0}
# every axis of the row (scenarios/matrix.sh passes them all), for the log
echo "=== MATRIX op=$OP size=$sc_size compress=$sc_compress csum=$sc_csum bgt=$sc_bgt" \
    "discard=$sc_discard reclaim=$RECLAIM idle=$IDLE layout=$sc_layout"

btrfs subvolume create $MNT/data > /dev/null
mkdir $MNT/data/docs $MNT/data/bulk
note create data; note create data/docs; note create data/bulk
i=1; while [ $i -le 8 ]; do seq 1 $((40 * i)) > $MNT/data/docs/small_$i.txt; created data/docs/small_$i.txt; i=$((i + 1)); done
i=1; while [ $i -le 6 ]; do seq 1 $((4000 * i)) > $MNT/data/docs/reg_$i.txt; created data/docs/reg_$i.txt; i=$((i + 1)); done
head -c 131072 /dev/urandom > $MNT/data/docs/rand.bin; created data/docs/rand.bin
seq 1 600000 > $MNT/data/docs/big.txt; created data/docs/big.txt
i=1; while [ $i -le 40 ]; do head -c 1048576 /dev/urandom > $MNT/data/bulk/b_$i; created data/bulk/b_$i; i=$((i + 1)); done
commit
settle after-population

# Reclaim on: the threshold of the data space info, written before the operation. A data block
# group whose usage falls from at least PCT % to below it is queued for relocation
# (should_reclaim_block_group, fs/btrfs/block-group.c:1874-1893 v7.0; the store at
# fs/btrfs/sysfs.c:925-950). dynamic_reclaim and periodic_reclaim (sysfs.c:961-1016) stay off:
# with periodic reclaim on, a free no longer queues the block group (block-group.c:3873-3876).
if [ "$RECLAIM" != 0 ]; then
    for d in $(data_space); do echo "$RECLAIM" > $d/bg_reclaim_threshold; done
fi
reclaim_stats

# delete_set: the files the delete and balance operations remove: half of the documents and
# three quarters of the bulk
delete_set() {
    set -- data/docs/small_2.txt data/docs/small_4.txt data/docs/small_6.txt \
        data/docs/small_8.txt data/docs/reg_2.txt data/docs/reg_4.txt data/docs/reg_6.txt \
        data/docs/rand.bin data/docs/big.txt
    i=1; while [ $i -le 40 ]; do
        [ $((i % 4)) -eq 0 ] || set -- "$@" data/bulk/b_$i
        i=$((i + 1))
    done
    rm_noted "$@"
    commit
}

case $OP in
delete)
    delete_set
    ;;
overwrite)
    # part of a file rewritten in place, a file replaced through truncation, random bytes written
    # over a file of the same size, an inline file replaced, a large file appended to
    dd if=/dev/urandom of=$MNT/data/docs/reg_1.txt bs=4096 seek=2 count=1 conv=notrunc 2>/dev/null
    note modify data/docs/reg_1.txt
    seq 7 31000 > $MNT/data/docs/reg_2.txt; note overwrite data/docs/reg_2.txt
    dd if=/dev/urandom of=$MNT/data/docs/rand.bin bs=131072 count=1 conv=notrunc 2>/dev/null
    note overwrite data/docs/rand.bin
    seq 5 90 > $MNT/data/docs/small_1.txt; note overwrite data/docs/small_1.txt
    seq 1 20000 >> $MNT/data/docs/big.txt; note modify data/docs/big.txt
    commit
    # a second state of two of them, one transaction later
    seq 11 45000 > $MNT/data/docs/reg_2.txt; note overwrite data/docs/reg_2.txt
    dd if=/dev/urandom of=$MNT/data/docs/reg_1.txt bs=4096 seek=0 count=1 conv=notrunc 2>/dev/null
    note modify data/docs/reg_1.txt
    commit
    ;;
stress)
    # 12 rounds: 25 new files (inline and regular), then the odd ones of this round and the even
    # ones of the round before are deleted, and file 10 of this round is renamed
    mkdir $MNT/data/stress; note create data/stress; commit
    r=1
    while [ $r -le 12 ]; do
        k=1; while [ $k -le 25 ]; do
            if [ $((k % 3)) -eq 0 ]; then n=$((3000 * k + 100 * r)); else n=$((20 * k + r)); fi
            seq 1 $n > $MNT/data/stress/s_${r}_$k; created data/stress/s_${r}_$k
            k=$((k + 1))
        done
        commit
        set --
        k=1; while [ $k -le 25 ]; do
            [ $((k % 2)) -eq 1 ] && set -- "$@" data/stress/s_${r}_$k
            [ $r -gt 1 ] && [ $((k % 2)) -eq 0 ] && [ $k -ne 10 ] && \
                set -- "$@" data/stress/s_$((r - 1))_$k
            k=$((k + 1))
        done
        rm_noted "$@"
        mv $MNT/data/stress/s_${r}_10 $MNT/data/stress/s_${r}_10.moved
        note rename data/stress/s_${r}_10 data/stress/s_${r}_10.moved
        commit
        r=$((r + 1))
    done
    ;;
snapshot)
    # a read-only snapshot keeps the files the live subvolume then deletes; the snapshot is
    # deleted in turn and the cleaner drops its tree
    btrfs subvolume snapshot -r $MNT/data $MNT/snap > /dev/null
    for p in $(cd $MNT && find snap | sort); do note create $p; done
    commit
    rm_noted data/docs/small_1.txt data/docs/small_3.txt data/docs/reg_1.txt \
        data/docs/reg_3.txt data/docs/big.txt
    commit
    for p in $(cd $MNT && find snap -mindepth 1 | sort -r); do note delete $p; done
    echo "delete $(ino snap) snap" >> $PENDING
    btrfs subvolume delete $MNT/snap > /dev/null
    commit
    ;;
balance)
    delete_set
    btrfs balance start --full-balance $MNT > /dev/null 2>&1
    sync
    phase balance
    ;;
defrag)
    # a file grown in 16 commits with a spacer file written between its appends, so its extents
    # are scattered; the spacers are deleted and the file is defragmented
    : > $MNT/data/docs/frag.txt; created data/docs/frag.txt; commit
    i=1; while [ $i -le 16 ]; do
        seq $((i * 10000)) $((i * 10000 + 9000)) >> $MNT/data/docs/frag.txt
        note modify data/docs/frag.txt
        seq 1 12000 > $MNT/data/docs/spacer_$i; created data/docs/spacer_$i
        commit
        i=$((i + 1))
    done
    set --
    i=1; while [ $i -le 16 ]; do set -- "$@" data/docs/spacer_$i; i=$((i + 1)); done
    rm_noted "$@"
    commit
    btrfs filesystem defragment -f $MNT/data/docs/frag.txt
    sync
    phase defrag
    ;;
*)
    echo "=== NO-SUCH-OP $OP"
    ;;
esac

settle after-op
churn "$OP"
reclaim_stats
btrfs filesystem df $MNT | sed 's/^/=== DF /'
if [ "$IDLE" -gt 0 ]; then
    echo "=== IDLE $IDLE"
    sleep "$IDLE"
fi
