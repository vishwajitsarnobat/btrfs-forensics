# Turn the recursive listing of btrForensics' fls (and of FKIE-TSK's pool fls, which uses the same
# code: Trees/FilesystemTree.cpp listDirItemsById) into `TYPE<TAB>INODE<TAB>PATH` lines. A line is
#   [+++ ]T/T INODE:<padding> NAME
# where the number of `+` is the depth below the listed directory. Lines of another shape (the
# headers, error text) are skipped.
{
    line = $0
    depth = 0
    if (match(line, /^\++ /)) {
        depth = RLENGTH - 1
        line = substr(line, RLENGTH + 1)
    }
    if (!match(line, /^[^\/ ]\/[^\/ ] [0-9]+:/)) next
    type = substr(line, 1, 1)
    rest = substr(line, 5)
    inode = rest
    sub(/:.*/, "", inode)
    name = rest
    sub(/^[0-9]+: */, "", name)
    dirs[depth] = name
    path = name
    for (i = depth - 1; i >= 0; i--) path = dirs[i] "/" path
    printf "%s\t%s\t%s\n", type, inode, path
}
