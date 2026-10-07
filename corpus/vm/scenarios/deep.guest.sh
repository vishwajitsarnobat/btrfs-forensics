# Guest scenario deep (sourced by /init with the filesystem mounted at $MNT).
# History that runs deeper than the four backup roots, without a balance. 48 subvolumes give the
# root tree a second level (EXP-004 §6.8 needs a root-tree node that can be lost while its leaves
# survive). Then 24 rounds; each round creates one victim file, commits, prints its SHA-256 as
# ground truth, deletes it, commits, and then rewrites a seventh of 400 small padding files and
# commits again. A victim therefore exists in exactly one committed generation. About 90
# generations pass in all, and the last victim is deleted six commits before the end, so no
# backup root holds any victim.
#
# Odd victims are inline (about 1 KiB). Even victims are regular and grow from round to round,
# and a small regular separator file is written behind each one before it is deleted: the hole
# a deleted victim leaves is then too small for any later victim, so its data is not reused.
# The padding files are inline, so the churn reuses metadata space only. Mount without
# compression (one extent per victim) and with a long commit interval, so that every commit is
# one of the scenario's own: MOUNT_OPTS=commit=300.
#
# Every sixth round also writes two flash files: created, fsynced and deleted within one
# transaction. They reach the disk only through the log tree, which the next commit drops.
#
# Every round also renames a file, so that timelines have renames to find (EXP-009):
# moves/m_R.txt is created in round R's padding commit, renamed to moves/m_R.moved in round
# R + 1's and deleted in round R + 2's. These files are inline and ride on a commit the round
# makes anyway, so the number of commits and the data space are as without them.
#
# Every create, rename and delete in the top-level tree is logged for EXP-009 as
# `=== EVENT KIND INODE GENERATION PATH [NEW PATH]`, after the sync that committed it:
# GENERATION is then the superblock's, read with dump-super (which only reads the device), and
# is the transaction the event happened in. A flash file is logged after the sync that commits
# the transaction it lived in. The file unlinked while open is logged as `unlink`: its inode
# stays.
#
# The last file is unlinked while still open and the guest powers off after the commit without
# unmounting (sysrq 'o', as in scenario logtree), so the last committed fs tree lists it under
# ORPHAN_ITEM with its INODE_ITEM and extents intact. make_image.sh is run with
# DONE_MARKER='=== DEEP-POWEROFF'.
gen() { btrfs inspect-internal dump-super /dev/vda | sed -n 's/^generation[[:space:]]*//p'; }
ino() { stat -c %i "$1"; }
event() { echo "=== EVENT $*"; }
i=1; while [ $i -le 48 ]; do btrfs subvolume create $MNT/sv$i > /dev/null; i=$((i + 1)); done
mkdir $MNT/pad $MNT/victims $MNT/moves
i=1; while [ $i -le 400 ]; do seq 1 300 > $MNT/pad/p$i; i=$((i + 1)); done
sync
g=$(gen)
for d in pad victims moves; do event create $(ino $MNT/$d) $g $d; done
i=1; while [ $i -le 400 ]; do event create $(ino $MNT/pad/p$i) $g pad/p$i; i=$((i + 1)); done
r=1
while [ $r -le 24 ]; do
    if [ $((r % 2)) -eq 1 ]; then
        seq 1 $((200 + r)) > $MNT/victims/victim_$r.txt
    else
        seq 1 $((20000 + 3000 * r)) > $MNT/victims/victim_$r.txt
    fi
    sync
    echo "=== VICTIM victim_$r.txt $(sha256sum < $MNT/victims/victim_$r.txt)"
    v=$(ino $MNT/victims/victim_$r.txt)
    event create $v $(gen) victims/victim_$r.txt
    if [ $((r % 2)) -eq 0 ]; then
        seq 1 1000 > $MNT/victims/separator_$r; sync
        event create $(ino $MNT/victims/separator_$r) $(gen) victims/separator_$r
    fi
    rm $MNT/victims/victim_$r.txt
    sync
    event delete $v $(gen) victims/victim_$r.txt
    flashed=
    if [ $((r % 6)) -eq 0 ]; then
        # A flash file: written and fsynced, then deleted before any commit. It exists only in
        # the log tree of this transaction, which the next commit drops. No root tree ever
        # names it. The regular one gets a separator too, and is smaller than every victim.
        seq 1 $((250 + r)) | dd of=$MNT/flash_inline_$r.txt conv=fsync 2>/dev/null
        seq 1 $((9000 + r)) | dd of=$MNT/flash_regular_$r.txt conv=fsync 2>/dev/null
        echo "=== FLASH flash_inline_$r.txt $(sha256sum < $MNT/flash_inline_$r.txt)"
        echo "=== FLASH flash_regular_$r.txt $(sha256sum < $MNT/flash_regular_$r.txt)"
        seq 1 1000 | dd of=$MNT/victims/separator_flash_$r conv=fsync 2>/dev/null
        flashed="$(ino $MNT/flash_inline_$r.txt) $(ino $MNT/flash_regular_$r.txt)"
        flashed="$flashed $(ino $MNT/victims/separator_flash_$r)"
        rm $MNT/flash_inline_$r.txt $MNT/flash_regular_$r.txt
    fi
    old=$MNT/moves/m_$((r - 1)) older=$MNT/moves/m_$((r - 2)).moved
    seq 1 $((100 + r)) > $MNT/moves/m_$r.txt
    if [ $r -gt 1 ]; then mv $old.txt $old.moved; fi
    if [ $r -gt 2 ]; then gone=$(ino $older); rm $older; fi
    i=$((r % 7 + 1)); while [ $i -le 400 ]; do seq $r $((300 + r)) > $MNT/pad/p$i; i=$((i + 7)); done
    sync
    g=$(gen)
    if [ -n "$flashed" ]; then
        set -- $flashed
        event create $1 $g flash_inline_$r.txt
        event delete $1 $g flash_inline_$r.txt
        event create $2 $g flash_regular_$r.txt
        event delete $2 $g flash_regular_$r.txt
        event create $3 $g victims/separator_flash_$r
    fi
    event create $(ino $MNT/moves/m_$r.txt) $g moves/m_$r.txt
    if [ $r -gt 1 ]; then event rename $(ino $old.moved) $g ${old#$MNT/}.txt ${old#$MNT/}.moved; fi
    if [ $r -gt 2 ]; then event delete $gone $g ${older#$MNT/}; fi
    r=$((r + 1))
done
seq 1 5000 > $MNT/open_unlinked.txt
sync
echo "=== ORPHAN open_unlinked.txt $(sha256sum < $MNT/open_unlinked.txt)"
o=$(ino $MNT/open_unlinked.txt)
event create $o $(gen) open_unlinked.txt
exec 3< $MNT/open_unlinked.txt
rm $MNT/open_unlinked.txt
sync; btrfs filesystem sync $MNT
event unlink $o $(gen) open_unlinked.txt
echo "=== DEEP-POWEROFF"
echo o > /proc/sysrq-trigger
sleep 60
