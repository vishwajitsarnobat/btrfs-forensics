"""Hiding places outside the trees: superblock copies, the boot area, backup roots, device slack.

Every superblock slot inside the device is read raw, valid or not, so a copy whose checksum the
hider did not recompute is still examined. The rules and their citations are in detect.py.

Superblock bytes the kernel never sets (kernel v7.0):
- the kernel reads the primary superblock once and copies all of it, `sizeof(struct
  btrfs_super_block)` = 4096 bytes, into the in-memory copy it later writes to every mirror
  (fs/btrfs/disk-io.c:3369-3380); fields it does not know survive every commit, but it never sets
  them. mkfs.btrfs writes them as zeros (every corpus image, both btrfs-progs 6.6.3 and the mkfs
  of sandbox.img). Hence non-zero bytes in
  - `reserved[199]` at 0x264-0x32A (include/uapi/linux/btrfs_tree.h:729);
  - `padding[565]` at 0xDCB-0xFFF (btrfs_tree.h:734);
  - the feature-gated fields, only when their feature flag is clear: `metadata_uuid` (btrfs_tree.h
    :721; read only with METADATA_UUID, fs/btrfs/volumes.c:734-740), `nr_global_roots`
    (btrfs_tree.h:723; extent-tree-v2, which kernel v7.0 neither reads nor writes in the
    superblock: only the accessor exists, fs/btrfs/accessors.h:884), `remap_root`,
    `remap_root_generation`, `remap_root_level` (btrfs_tree.h:724-726; read only with REMAP_TREE,
    disk-io.c:2669-2673). The paper's range of 0xF0 bytes at 0x23B is the pre-5.0 layout
    (research.md §10.13): taken literally it reports every filesystem changed by `btrfstune -m`;
  - the padding of each backup root slot, `unused_64[4]` and `unused_8[10]` (btrfs_tree.h:539,
    :548), which the kernel zeroes before it fills a slot (disk-io.c:1605).
- `sys_chunk_array` beyond `sys_chunk_array_size`. The kernel appends at the end
  (volumes.c:5344-5367) and removes an entry with a memmove that does **not** clear the bytes it
  frees (volumes.c:3204, `btrfs_del_sys_chunk`); mkfs.btrfs does the same when it drops its
  temporary system chunk. So the tail legitimately holds stale bytes, and exactly two shapes of
  them: the removed entry itself, when it was the last one (it then parses as whole chunk
  entries), or a copy of the last bytes of the live array, when it was not (the memmove shifted
  them down by the removed length). Every corpus image carries the second shape (45 to 51 bytes).
  Anything else in the tail is reported.

A superblock slot inside the device always holds a superblock: every commit writes every mirror
that fits (disk-io.c:3789-3808, `write_dev_supers`, which stops only at the device end).
A slot with non-zero bytes but no magic is reported; an all-zero slot is damage, not hiding, and
`btrfska info` already says so.

The boot area. The kernel allocates device extents from 1 MiB on (fs.h:108
BTRFS_DEVICE_RANGE_RESERVED, volumes.c:1664-1671), and writes nothing below it except the primary
superblock at 64 KiB. mkfs.btrfs zeroes the start of the device. What else legitimately lives
there is a boot loader: GRUB 2 puts its boot sector in sector 0 and embeds core.img in the first
MiB around the superblock (grub-core/fs/btrfs.c, `grub_btrfs_embed`, GRUB 2.12). So the first
64 KiB and the rest of the first MiB are reported when not zero, and a boot-sector signature
(0x55 0xAA at byte 510) is named in the evidence, because a boot loader explains such bytes.
"""

from btrfska.hiding.findings import Finding, area_finding, nonzero, nonzero_runs, preview
from btrfska.substrate import ondisk, superblock
from btrfska.substrate.chunks import parse_chunk, stripe_size

SB = ondisk.SUPERBLOCK
RESERVED = (0x264, 0x32B)
PADDING = (0xDCB, ondisk.SUPER_INFO_SIZE)
ARRAY = SB.offset("sys_chunk_array")
# Feature-gated fields: (name, start, end, incompat flag that gives them a meaning).
GATED = (
    ("metadata_uuid", SB.offset("metadata_uuid"), SB.offset("nr_global_roots"), "METADATA_UUID"),
    ("nr_global_roots", SB.offset("nr_global_roots"), SB.offset("remap_root"), "EXTENT_TREE_V2"),
    ("remap_root", SB.offset("remap_root"), RESERVED[0], "REMAP_TREE"),
)
# Padding inside one btrfs_root_backup: unused_64[4] and unused_8[10].
_BACKUP = ondisk.ROOT_BACKUP
_BACKUP_PADDING = (
    (_BACKUP.offset("num_devices") + 8, _BACKUP.offset("tree_root_level")),
    (_BACKUP.offset("csum_root_level") + 1, _BACKUP.size),
)
BOOT_AREAS = (
    (0, ondisk.SUPER_INFO_OFFSET, "the first 64 KiB, before the primary superblock"),
    (
        ondisk.SUPER_INFO_OFFSET + ondisk.SUPER_INFO_SIZE,
        1 << 20,
        "the rest of the first MiB, after the primary superblock",
    ),
)
_CHUNK_KEY = ondisk.DISK_KEY.size
_STRIPE = ondisk.STRIPE.size


def _copy_where(mirror: int, offset: int, what: str, start: int, end: int) -> str:
    return f"superblock mirror {mirror} at {offset}, {what} bytes {start:#x}-{end - 1:#x}"


def stale_tail(array: bytes, size: int, tail: bytes, sectorsize: int) -> str | None:
    """How the kernel or mkfs could have left `tail` beyond the live `size` bytes of the array,
    or None. See the module docstring for the two shapes."""
    last = len(tail.rstrip(b"\0"))
    if last == 0:
        return "zero"
    for length in range(last, min(size, len(tail)) + 1):
        if tail[:length] == array[size - length : size] and not any(tail[length:]):
            return "shifted_copy"
    position = 0
    while position < last:
        key = ondisk.DISK_KEY.unpack_from(tail.ljust(position + _CHUNK_KEY, b"\0"), position)
        if (key["objectid"], key["type"]) != (
            ondisk.FIRST_CHUNK_TREE_OBJECTID,
            ondisk.ITEM_KEYS["CHUNK_ITEM"],
        ):
            return None
        body = tail[position + _CHUNK_KEY :]
        if len(body) < ondisk.CHUNK.size:
            return None
        stripes = ondisk.CHUNK.unpack_from(body)["num_stripes"]
        length = ondisk.CHUNK.size + stripes * _STRIPE
        if not stripes or len(body) < length:
            return None
        if parse_chunk(key["offset"], body[:length], sectorsize=sectorsize).problems:
            return None
        position += _CHUNK_KEY + length
    return "removed_entries"


def superblock_findings(img, fields: dict) -> tuple[list[Finding], dict]:
    """Findings over every superblock slot of the image, and what was examined. A copy with the
    magic is examined wherever it is; a slot without one only inside the device (`fields` is the
    selected superblock), since past the device's size it is device slack."""
    found, checked = [], {"copies": 0, "slots_without_superblock": 0, "stale_array_tails": {}}
    device_end = ondisk.DEV_ITEM.unpack_from(fields["dev_item"])["total_bytes"] or img.size
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset + ondisk.SUPER_INFO_SIZE > img.size:
            continue
        block = bytes(img.mmap[offset : offset + ondisk.SUPER_INFO_SIZE])
        copy = superblock.parse_copy(block, mirror)
        if not copy.magic_ok:
            if nonzero(block) and offset + ondisk.SUPER_INFO_SIZE <= device_end:
                checked["slots_without_superblock"] += 1
                found.append(
                    area_finding(
                        "superblock_slot",
                        offset,
                        block,
                        f"superblock mirror {mirror} slot at {offset} ({ondisk.SUPER_INFO_SIZE} "
                        "bytes)",
                        "the slot lies inside the device, where every commit writes a superblock "
                        "copy, but it holds no superblock magic and is not all zero: it was "
                        "overwritten",
                        mirror=mirror,
                    )  # fmt: skip
                )
            continue
        checked["copies"] += 1
        found += _copy_findings(copy, block, offset, checked)
    return found, checked


def _copy_findings(copy, block: bytes, offset: int, checked: dict) -> list[Finding]:
    mirror, fields = copy.mirror, copy.fields
    common = {"mirror": mirror, "copy_valid": copy.valid, "csum_ok": copy.csum_ok}
    incompat = fields["incompat_flags"]
    candidates = [
        area_finding(
            "superblock_reserved",
            offset + RESERVED[0],
            block[slice(*RESERVED)],
            _copy_where(mirror, offset, "reserved", *RESERVED),
            "reserved[199] (btrfs_tree.h:729) is written as zeros by mkfs.btrfs and never set by "
            "the kernel, which only copies it from commit to commit (disk-io.c:3369-3380)",
            field="reserved",
            **common,
        ),  # fmt: skip
        area_finding(
            "superblock_padding",
            offset + PADDING[0],
            block[slice(*PADDING)],
            _copy_where(mirror, offset, "padding", *PADDING),
            "padding[565] (btrfs_tree.h:734) is written as zeros by mkfs.btrfs and never set by "
            "the kernel (disk-io.c:3369-3380)",
            field="padding",
            **common,
        ),  # fmt: skip
    ]
    for name, start, end, flag in GATED:
        if incompat & ondisk.INCOMPAT[flag]:
            continue
        candidates.append(
            area_finding(
                "superblock_reserved",
                offset + start,
                block[start:end],
                _copy_where(mirror, offset, name, start, end),
                f"{name} is non-zero but incompat flag {flag} is clear: without the flag the "
                "kernel never reads or writes the field, so it is spare room (research.md "
                "§10.13; btrfs_tree.h:721-726)",
                field=name,
                **common,
            )  # fmt: skip
        )
    raw = fields["super_roots"]
    base = SB.offset("super_roots")
    for slot in range(ondisk.NUM_BACKUP_ROOTS):
        for start, end in _BACKUP_PADDING:
            lo, hi = slot * _BACKUP.size + start, slot * _BACKUP.size + end
            candidates.append(
                area_finding(
                    "superblock_reserved",
                    offset + base + lo,
                    raw[lo:hi],
                    _copy_where(
                        mirror, offset, f"backup root slot {slot} padding", base + lo, base + hi
                    ),
                    "the kernel zeroes a backup root slot before it fills it (disk-io.c:1605), "
                    "so its unused_64 and unused_8 padding (btrfs_tree.h:539, :548) is always "
                    "zero",
                    field="backup_root_padding",
                    slot=slot,
                    **common,
                )  # fmt: skip
            )
    size = min(fields["sys_chunk_array_size"], ondisk.SYSTEM_CHUNK_ARRAY_SIZE)
    array = block[ARRAY : ARRAY + ondisk.SYSTEM_CHUNK_ARRAY_SIZE]
    tail = array[size:]
    shape = stale_tail(array, size, tail, fields["sectorsize"])
    if shape in ("shifted_copy", "removed_entries"):
        tails = checked["stale_array_tails"]
        tails[shape] = tails.get(shape, 0) + 1
    elif shape is None:
        candidates.append(
            area_finding(
                "sys_chunk_array_slack",
                offset + ARRAY + size,
                tail,
                _copy_where(
                    mirror,
                    offset,
                    f"sys_chunk_array beyond its size {size}",
                    ARRAY + size,
                    ARRAY + ondisk.SYSTEM_CHUNK_ARRAY_SIZE,
                ),
                "the bytes beyond sys_chunk_array_size are neither zero nor what removing a "
                "system chunk leaves there (the removed entry, or a copy of the array's last "
                "bytes: volumes.c:3204)",
                field="sys_chunk_array",
                array_size=size,
                **common,
            )  # fmt: skip
        )
    return [finding for finding in candidates if finding is not None]


def boot_area_findings(img) -> list[Finding]:
    found = []
    for start, end, what in BOOT_AREAS:
        end = min(end, img.size)
        if end <= start:
            continue
        data = bytes(img.mmap[start:end])
        evidence = (
            "the kernel writes nothing below 1 MiB but the primary superblock (fs.h:108, "
            "volumes.c:1664-1671) and mkfs.btrfs leaves it zero"
        )
        signature = start == 0 and data[510:512] == b"\x55\xaa"
        if signature:
            evidence += (
                "; sector 0 ends in the boot signature 0x55 0xAA, so a boot loader may "
                "have written these bytes (GRUB 2 embeds core.img in the first MiB)"
            )
        finding = area_finding(
            "pre_superblock", start, data, f"{what}: bytes {start:#x}-{end - 1:#x}", evidence,
            boot_signature=signature,
        )  # fmt: skip
        if finding is not None:
            found.append(finding)
    return found


def backup_root_findings(selection: superblock.Selection) -> list[Finding]:
    """Backup-root divergence (SecurityRonin/btrfs-forensic `BTRFS-BACKUP-ROOT-DIVERGENCE`, made
    precise against the kernel's commit path; see detect.py)."""
    selected = selection.selected
    fields = selected.fields
    generation = fields["generation"]
    roots = superblock.backup_roots(fields)
    used = [root for root in roots if root["tree_root"] or root["tree_root_gen"]]
    reasons = []
    for root in used:
        for tree in ("tree_root", "chunk_root", "extent_root", "fs_root", "dev_root", "csum_root"):
            if root[f"{tree}_gen"] > generation:
                reasons.append(
                    f"slot {root['slot']} {tree} generation {root[f'{tree}_gen']} is newer than "
                    f"the superblock's generation {generation}"
                )
    newest = [root for root in used if root["tree_root_gen"] == generation]
    if used and not newest:
        reasons.append(
            f"no slot holds the superblock's generation {generation}: every commit fills one "
            "(disk-io.c:4065-4069, 1594-1605) and the kernel looks for it at mount "
            "(disk-io.c:1572-1588)"
        )
    for root in newest[:1]:
        pairs = (
            ("tree_root", "root"), ("tree_root_level", "root_level"),
            ("chunk_root", "chunk_root"), ("chunk_root_gen", "chunk_root_generation"),
            ("chunk_root_level", "chunk_root_level"), ("total_bytes", "total_bytes"),
            ("bytes_used", "bytes_used"), ("num_devices", "num_devices"),
        )  # fmt: skip
        differing = [f"{a} {root[a]} != {b} {fields[b]}" for a, b in pairs if root[a] != fields[b]]
        if differing:
            reasons.append(
                f"slot {root['slot']}, of the superblock's generation, disagrees with the "
                f"superblock it was written with: {', '.join(differing)} (both are set from the "
                "same trees in one commit, disk-io.c:1609-1673)"
            )
    generations = sorted(root["tree_root_gen"] for root in used)
    if len(set(generations)) != len(generations):
        reasons.append(f"two slots hold the same generation: {generations}")
    elif generations and generations != list(
        range(generations[-1] - len(generations) + 1, generations[-1] + 1)
    ):
        reasons.append(
            f"slot generations {generations} are not consecutive: each commit advances the "
            "generation by one and fills the next slot of the ring"
        )
    for copy in selection.copies:
        if (
            copy is not selected and copy.valid and copy not in selection.foreign
            and copy.fields["generation"] == generation
            and copy.fields["super_roots"] != fields["super_roots"]
        ):  # fmt: skip
            reasons.append(
                f"mirror {copy.mirror} has the same generation but other backup roots: every "
                "mirror is written from the same buffer (disk-io.c:4071, 4089-4123)"
            )
    if not reasons:
        return []
    offset = selected.offset + SB.offset("super_roots")
    length = ondisk.NUM_BACKUP_ROOTS * _BACKUP.size
    hex_, text = preview(fields["super_roots"])
    return [
        Finding(
            "backup_root_divergence",
            offset,
            length,
            len(reasons),
            f"superblock mirror {selected.mirror}, backup roots",
            "; ".join(reasons),
            hex_,
            text,
            {"mirror": selected.mirror, "generations": generations, "reasons": reasons},
        )  # fmt: skip
    ]


def intervals_minus(pieces, cut):
    """[lo, hi) pieces with every [a, b) of `cut` taken out, and the parts taken out."""
    outside, inside = [], []
    for lo, hi in pieces:
        position = lo
        for a, b in sorted(cut):
            if b <= position or a >= hi:
                continue
            if a > position:
                outside.append((position, a))
            inside.append((max(a, position), min(b, hi)))
            position = max(position, min(b, hi))
        if position < hi:
            outside.append((position, hi))
    return outside, inside


def _scan(img, pieces):
    runs, count, more = [], 0, 0
    for lo, hi in pieces:
        if hi > lo:
            got, found, extra = nonzero_runs(img, lo, hi)
            free = MAX_LISTED - len(runs)
            runs += got[:free]
            more += extra + max(0, len(got) - free)
            count += found
    return runs, count, more


MAX_LISTED = 16


def removed_stripes(chunk_maps, devid: int) -> list[tuple[int, int]]:
    """[start, end) on device `devid` of every stripe of every chunk the historical chunk maps
    (plan.md M5a) hold, accepted or not: places where a chunk once was."""
    found = set()
    for chunk_map in chunk_maps:
        for chunk in (*chunk_map.chunks, *getattr(chunk_map, "rejected", ())):
            size = stripe_size(chunk) or chunk.length
            for stripe in chunk.stripes:
                if stripe.devid == devid:
                    found.add((stripe.offset, stripe.offset + size))
    return sorted(found)


def device_slack_findings(img, fields: dict, extents, history=None) -> tuple[list, dict]:
    """Non-zero bytes past this device's last device extent, and past the device's size.

    `extents` are this device's (physical start, length) from the current dev tree. Superblock
    slots are skipped: they are examined on their own. `history`, when given, returns the
    historical chunk maps; it is called only when bytes past the last extent are not zero, and
    the bytes that lie in a stripe of a chunk those maps hold are counted as explained (a chunk
    that was there and was removed), not reported.
    """
    device = ondisk.DEV_ITEM.unpack_from(fields["dev_item"])
    devid, total = device["devid"], device["total_bytes"]
    last = max((start + length for start, length in extents), default=1 << 20)
    checked = {"devid": devid, "total_bytes": total, "last_extent_end": last,
               "explained_bytes": 0, "history": None}  # fmt: skip
    found = []
    areas = [
        ("past_last_extent", min(last, img.size), min(total, img.size),
         "past the last device extent",
         "the kernel writes a device only through its chunks' device extents and the superblock "
         "copies; bytes past the last device extent belong to no chunk, now or in any "
         "historical chunk map found"),
        ("past_device_size", min(total, img.size), img.size, "past the device's size",
         "the device item gives the device a total_bytes, and the kernel never writes past it"),
    ]  # fmt: skip
    for area, start, end, what, why in areas:
        if end <= start:
            continue
        pieces, position = [], start
        for mirror in range(ondisk.SUPER_MIRROR_MAX):
            slot = ondisk.sb_offset(mirror)
            if start <= slot < end and slot + ondisk.SUPER_INFO_SIZE <= total:
                pieces.append((position, slot))
                position = slot + ondisk.SUPER_INFO_SIZE
        pieces.append((position, end))
        runs, count, more = _scan(img, pieces)
        if count and area == "past_last_extent" and history is not None:
            maps = history()
            covered = removed_stripes(maps, devid)
            checked["history"] = {"chunk_maps": len(maps), "stripes_on_device": len(covered)}
            outside, inside = intervals_minus(pieces, covered)
            checked["explained_bytes"] += _scan(img, inside)[1]
            runs, count, more = _scan(img, outside)
        if not count:
            continue
        first = runs[0][0]
        hex_, text = preview(img.mmap[first : min(first + 4096, end)])
        found.append(
            Finding(
                "device_slack",
                start,
                end - start,
                count,
                f"devid {devid}, {what}: bytes {start}-{end - 1}",
                f"{why}; {count} non-zero bytes in {len(runs) + more} runs",
                hex_,
                text,
                {
                    "devid": devid,
                    "area": area,
                    "runs": [list(run) for run in runs],
                    "runs_not_listed": more,
                },
            )  # fmt: skip
        )
    return found, checked
