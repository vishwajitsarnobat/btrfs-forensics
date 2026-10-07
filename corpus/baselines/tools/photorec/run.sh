# PhotoRec carves the whole device: it has no btrfs free-space support, so `wholespace`. It opens
# the source with TESTDISK_O_RDONLY (src/phmain.c:170); /dev/vdb is read-only anyway. The DFXML
# report.xml it writes next to the carved files is moved to the logs, so files/ holds only carved
# files. Carved files have no names (names: none).
cd "$LOGS"
"$PREFIX/bin/photorec_static" /log /d "$OUT/recup_dir" /cmd "$EVIDENCE" \
    partition_none,options,keep_corrupted_file,fileopt,everything,enable,wholespace,search
status=$?
find "$OUT" -name report.xml | while read -r report; do
    mv "$report" "$LOGS/$(basename "$(dirname "$report")")-report.xml"
done
exit $status
