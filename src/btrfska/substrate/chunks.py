"""Chunk maps: logical-to-physical translation from the sys_chunk_array and chunk items.

A `ChunkMap` is built from parsed chunk items and names its `source` ("sys_chunk_array" for the
bootstrap map, "current" for the chunk tree; later milestones add historical and reconstructed
maps). `copies()` turns a logical range into every physical copy that holds it. Walking the chunk
tree needs the node reader, so it lives in `fs.open_filesystem`, not here.

Kernel v7.0 references:
- BTRFS_STRIPE_LEN is 64 KiB (volumes.h:46); stripe_nr = offset >> 16 and
  stripe_offset = offset & 0xffff (volumes.c:6639-6640);
- per profile: map_blocks_raid0 (volumes.c:6722-6729), _raid1 (l.6731-6749), _dup (l.6751-6765),
  _raid10 (l.6767-6793), _raid56_read (l.6826-6842), _single (l.6844-6849); the physical address
  is stripes[stripe_index].physical + stripe_offset + (stripe_nr << 16) (l.6695-6697);
- ncopies, nparity and stripe counts per profile: btrfs_raid_array (volumes.c:53-170);
- chunk item checks: valid_stripe_count and btrfs_check_chunk_valid (tree-checker.c:825-1014);
- the sys_chunk_array holds (disk key, chunk item) pairs (volumes.c:7632-7690).

Profiles:
- SINGLE, DUP and RAID1/1C3/1C4: every stripe is a full copy, returned in stripe order;
- RAID0 and RAID10: the stripe, or the sub_stripes mirrors, holding the range;
- RAID5/6: the data stripe only. Parity reconstruction is not supported, so a data stripe on a
  missing device cannot be read.
Striped reads must not cross a 64 KiB stripe boundary; callers split longer ranges. A stripe is
readable only when its devid and device uuid are in `devices`; other copies are returned flagged
`missing_device`. Every lookup failure is a `MappingError`, including stripe geometry the math
cannot use (RAID10 stripes not a non-zero multiple of sub_stripes, RAID5/6 without a data stripe).
"""

import bisect
from dataclasses import dataclass, replace

from btrfska.substrate import ondisk

BG = ondisk.BLOCK_GROUP_FLAGS
STRIPE_LEN = 1 << 16
TYPE_MASK = BG["DATA"] | BG["SYSTEM"] | BG["METADATA"] | BG["METADATA_REMAP"]
PROFILE_MASK = (
    BG["RAID0"] | BG["RAID1"] | BG["RAID1C3"] | BG["RAID1C4"]
    | BG["RAID5"] | BG["RAID6"] | BG["DUP"] | BG["RAID10"]
)  # fmt: skip
VALID_TYPE = TYPE_MASK | PROFILE_MASK | BG["REMAPPED"]
# profile bits -> (name, ncopies, nparity) from btrfs_raid_array; "single" is spelled as progs does.
PROFILES = {
    0: ("single", 1, 0),
    BG["DUP"]: ("DUP", 2, 0),
    BG["RAID0"]: ("RAID0", 1, 0),
    BG["RAID1"]: ("RAID1", 2, 0),
    BG["RAID1C3"]: ("RAID1C3", 3, 0),
    BG["RAID1C4"]: ("RAID1C4", 4, 0),
    BG["RAID10"]: ("RAID10", 2, 0),
    BG["RAID5"]: ("RAID5", 1, 1),
    BG["RAID6"]: ("RAID6", 1, 2),
}
_STRIPED = BG["RAID0"] | BG["RAID10"] | BG["RAID5"] | BG["RAID6"]
_TYPE_NAMES = ("DATA", "SYSTEM", "METADATA", "METADATA_REMAP", "REMAPPED")


class MappingError(Exception):
    """A logical range cannot be translated to physical copies."""


class UnmappedAddress(MappingError):
    """No chunk (with stripes) covers the logical range."""


@dataclass(frozen=True)
class Stripe:
    devid: int
    offset: int  # physical offset on the device
    dev_uuid: bytes


@dataclass(frozen=True)
class Chunk:
    logical: int
    length: int
    type: int
    stripes: tuple[Stripe, ...]
    sub_stripes: int = 1
    origin: str = ""  # where the item was read, for provenance
    problems: tuple[str, ...] = ()  # any problem rejects the chunk from a ChunkMap

    @property
    def num_stripes(self) -> int:
        return len(self.stripes)

    @property
    def end(self) -> int:
        return self.logical + self.length


@dataclass(frozen=True)
class PhysicalCopy:
    mirror: int  # 1-based position among the copies returned (the kernel's mirror_num)
    devid: int
    physical: int
    missing_device: bool = False


def type_name(type_: int) -> str:
    """Block-group type as btrfs-progs dump-tree prints it, e.g. METADATA|DUP or DATA|single."""
    names = [name for name in _TYPE_NAMES if type_ & BG[name]]
    names += [n for n in ondisk.flag_names(type_ & ~VALID_TYPE, {}) if n]
    profile = type_ & PROFILE_MASK
    names.append(PROFILES[profile][0] if profile in PROFILES else f"PROFILES_{profile:#x}")
    return "|".join(names)


def _valid_stripe_count(profile: int, num_stripes: int, sub_stripes: int) -> bool:
    """tree-checker.c:825-849 valid_stripe_count, with btrfs_raid_array's devs_min values."""
    if profile == BG["RAID0"]:
        return True
    if profile == BG["RAID10"]:
        return sub_stripes == 2
    if profile & (BG["RAID1"] | BG["RAID1C3"] | BG["RAID1C4"]):
        return num_stripes == PROFILES[profile][1]
    if profile == BG["RAID5"]:
        return num_stripes >= 2
    if profile == BG["RAID6"]:
        return num_stripes >= 3
    return num_stripes == (2 if profile == BG["DUP"] else 1)


def _geometry_problem(chunk: Chunk) -> str | None:
    """Why the stripe math cannot run on a chunk that has stripes, whatever its recorded problems.

    Guards the divisions in `ChunkMap.copies`: RAID10 divides by sub_stripes and by
    num_stripes // sub_stripes, RAID5/6 by the data stripe count.
    """
    n, profile, sub = chunk.num_stripes, chunk.type & PROFILE_MASK, chunk.sub_stripes
    if profile not in PROFILES:
        return f"profile flags {profile:#x} are not one profile"
    if profile == BG["RAID10"] and (sub <= 0 or n % sub):
        return f"num_stripes {n} is not a non-zero multiple of sub_stripes {sub}"
    nparity = PROFILES[profile][2]
    if nparity and n <= nparity:
        return f"num_stripes {n} leaves no data stripe beside {nparity} parity"
    return None


def parse_chunk(
    logical: int, data: bytes, *, sectorsize: int, incompat: int = 0, origin: str = ""
) -> Chunk:
    """Parse a chunk item (key offset `logical`) and record every btrfs_check_chunk_valid failure.

    Never raises on content: a short item yields a zero-length chunk with a problem.
    """
    if len(data) < ondisk.CHUNK.size:
        return Chunk(logical, 0, 0, (), origin=origin, problems=(f"item size {len(data)} < 48",))
    fields = ondisk.CHUNK.unpack_from(data)
    n, sub, length, type_ = (
        fields["num_stripes"],
        fields["sub_stripes"],
        fields["length"],
        fields["type"],
    )
    present = min(n, (len(data) - ondisk.CHUNK.size) // ondisk.STRIPE.size)
    stripes = tuple(
        Stripe(**ondisk.STRIPE.unpack_from(data, ondisk.CHUNK.size + i * ondisk.STRIPE.size))
        for i in range(present)
    )
    profile, remapped = type_ & PROFILE_MASK, type_ & BG["REMAPPED"]
    name, ncopies, nparity = PROFILES.get(profile, (f"{profile:#x}", 1, 0))

    problems = []
    expected_size = ondisk.CHUNK.size + n * ondisk.STRIPE.size
    if len(data) != expected_size:
        problems.append(f"item size {len(data)} != {expected_size} for {n} stripes")
    if n == 0 and not remapped:
        problems.append("num_stripes 0 without REMAPPED")
    if n and n < ncopies:
        problems.append(f"num_stripes {n} < ncopies {ncopies}")
    if nparity and n == nparity:
        problems.append(f"num_stripes {n} == nparity {nparity}")
    if nparity and 0 < n < nparity:  # btrfska: no data stripe at all (the kernel checks == only)
        problems.append(f"num_stripes {n} < nparity {nparity}")
    if logical % sectorsize:
        problems.append(f"logical {logical} not aligned to sectorsize {sectorsize}")
    if fields["sector_size"] != sectorsize:
        problems.append(f"sector_size {fields['sector_size']} != {sectorsize}")
    if not length or length % sectorsize:
        problems.append(f"invalid length {length}")
    if logical + length >= 1 << 64:
        problems.append(f"logical {logical} + length {length} overflows")
    if fields["stripe_len"] != STRIPE_LEN:
        problems.append(f"stripe_len {fields['stripe_len']} != {STRIPE_LEN}")
    if length >= STRIPE_LEN * 0xFFFFFFFF:
        problems.append(f"length {length} too large")
    if type_ & ~VALID_TYPE:
        problems.append(f"unknown type bits {type_ & ~VALID_TYPE:#x}")
    if profile & (profile - 1):
        problems.append(f"profile flags {profile:#x} have more than one bit set")
    if not type_ & TYPE_MASK:
        problems.append(f"no type flag in {type_:#x}")
    if type_ & BG["SYSTEM"] and type_ & (BG["METADATA"] | BG["DATA"]):
        problems.append(f"system chunk with data or metadata type {type_:#x}")
    mixed_ok = incompat & ondisk.INCOMPAT["MIXED_GROUPS"]
    if not mixed_ok and type_ & BG["METADATA"] and type_ & BG["DATA"]:
        problems.append(f"mixed chunk type {type_:#x} without MIXED_GROUPS")
    # The kernel skips valid_stripe_count for REMAPPED chunks (tree-checker.c:1002-1009), but a
    # REMAPPED address covered by an identity remap item is still mapped through the chunk's own
    # stripes (relocation.c:5164-5165, volumes.c:6914-6930), so btrfska checks every chunk that
    # has stripes.
    if (n or not remapped) and profile in PROFILES and not _valid_stripe_count(profile, n, sub):
        suffix = " (checked although REMAPPED)" if remapped else ""
        problems.append(f"num_stripes {n} sub_stripes {sub} invalid for {name}{suffix}")
    # btrfska: the allocator adds RAID10 stripes in pairs (btrfs_raid_array devs_increment 2,
    # volumes.c:54-66); the kernel checker does not test it.
    if profile == BG["RAID10"] and sub and n % sub:
        problems.append(f"num_stripes {n} is not a multiple of sub_stripes {sub}")
    return Chunk(logical, length, type_, stripes, sub, origin, tuple(problems))


def parse_sys_chunk_array(fields: dict) -> tuple[list[Chunk], tuple[str, ...]]:
    """The superblock's bootstrap chunks and any structural problem. Never raises on content."""
    raw, size = fields["sys_chunk_array"], fields["sys_chunk_array_size"]
    problems = []
    if size > len(raw):
        problems.append(f"sys_chunk_array_size {size} > {len(raw)}")
        size = len(raw)
    found, pos = [], 0
    while pos < size:
        if pos + ondisk.DISK_KEY.size > size:
            problems.append(f"truncated key at sys_chunk_array offset {pos}")
            break
        key = ondisk.DISK_KEY.unpack_from(raw, pos)
        if key["type"] != ondisk.ITEM_KEYS["CHUNK_ITEM"]:
            problems.append(
                f"sys_chunk_array offset {pos}: key type {key['type']} is not CHUNK_ITEM"
            )
            break
        pos += ondisk.DISK_KEY.size
        if pos + ondisk.CHUNK.size > size:
            problems.append(f"truncated chunk item at sys_chunk_array offset {pos}")
            break
        stripes = ondisk.CHUNK.unpack_from(raw, pos)["num_stripes"]
        length = ondisk.CHUNK.size + stripes * ondisk.STRIPE.size
        if pos + length > size:
            problems.append(f"truncated chunk item at sys_chunk_array offset {pos}")
            break
        chunk = parse_chunk(
            key["offset"],
            bytes(raw[pos : pos + length]),
            sectorsize=fields["sectorsize"],
            incompat=fields["incompat_flags"],
            origin="sys_chunk_array",
        )
        if not chunk.type & BG["SYSTEM"]:
            chunk = replace(chunk, problems=(*chunk.problems, "not a SYSTEM chunk"))
        found.append(chunk)
        pos += length
    return found, tuple(problems)


class ChunkMap:
    """Valid chunks sorted by logical address, the rejected invalid chunks, and the problems found
    while building the map.

    Only valid chunks take part in lookup and overlap resolution, so a corrupt item (an inflated
    length, say) cannot shadow later valid chunks. Rejected chunks are kept for reporting.
    """

    def __init__(self, source: str, chunks, devices: dict[int, bytes], problems=()) -> None:
        self.source = source
        self.devices = dict(devices)  # devid -> device uuid of every readable device
        found, accepted, rejected = list(problems), [], []
        for chunk in sorted(chunks, key=lambda c: c.logical):
            where = f"chunk {chunk.logical}"
            if chunk.problems:
                found.append(
                    f"{where} ({chunk.origin}, {type_name(chunk.type)}, length {chunk.length}) "
                    f"is invalid and rejected: {'; '.join(chunk.problems)}"
                )
                rejected.append(chunk)
                continue
            if accepted and chunk.logical < accepted[-1].end:
                found.append(f"{where} overlaps chunk {accepted[-1].logical}; ignored")
                continue
            if not chunk.stripes:
                found.append(
                    f"{where} has no stripes (REMAPPED): its addresses resolve through the remap "
                    "tree, which btrfska does not read"
                )
            for index, stripe in enumerate(chunk.stripes):
                if stripe.devid not in self.devices:
                    found.append(f"{where} stripe {index}: devid {stripe.devid} is missing")
                elif self.devices[stripe.devid] != stripe.dev_uuid:
                    found.append(
                        f"{where} stripe {index}: devid {stripe.devid} has device uuid "
                        f"{stripe.dev_uuid.hex()}, not the readable device's"
                    )
            accepted.append(chunk)
        self.chunks = tuple(accepted)
        self.rejected = tuple(rejected)
        self.problems = tuple(found)
        self._starts = [chunk.logical for chunk in accepted]

    def chunk_for(self, logical: int) -> Chunk:
        index = bisect.bisect_right(self._starts, logical) - 1
        if index >= 0 and logical < self.chunks[index].end:
            return self.chunks[index]
        covering = [c for c in self.rejected if c.logical <= logical < c.end]
        if covering:
            names = "; ".join(
                f"rejected chunk {c.logical} is invalid: {', '.join(c.problems)}" for c in covering
            )
            raise UnmappedAddress(
                f"logical {logical} is not in any valid chunk of the {self.source} chunk map "
                f"({names})"
            )
        raise UnmappedAddress(
            f"logical {logical} is not in any chunk of the {self.source} chunk map"
        )

    def pieces(self, logical: int, length: int) -> tuple[tuple[int, int], ...]:
        """[logical, logical + length) as (logical, length) pieces that `copies` accepts: split at
        chunk ends and, in striped profiles, at 64 KiB stripe boundaries. Raises UnmappedAddress
        when any part is outside the valid chunks."""
        pieces, end = [], logical + length
        while logical < end:
            chunk = self.chunk_for(logical)
            step = min(end, chunk.end) - logical
            if chunk.type & _STRIPED:
                step = min(step, STRIPE_LEN - (logical - chunk.logical) % STRIPE_LEN)
            pieces.append((logical, step))
            logical += step
        return tuple(pieces)

    def copies(self, logical: int, length: int) -> tuple[PhysicalCopy, ...]:
        """Every physical copy of [logical, logical + length), in mirror order."""
        chunk = self.chunk_for(logical)
        if logical + length > chunk.end:
            raise UnmappedAddress(
                f"logical range {logical}+{length} crosses the end of chunk {chunk.logical} "
                f"of the {self.source} chunk map"
            )
        if not chunk.stripes:
            raise UnmappedAddress(
                f"chunk {chunk.logical} has no stripes (REMAPPED): logical {logical} is mapped "
                "by the remap tree"
            )
        n, profile = chunk.num_stripes, chunk.type & PROFILE_MASK
        if problem := _geometry_problem(chunk):
            raise MappingError(f"chunk {chunk.logical} geometry is not computable: {problem}")
        stripe_nr, stripe_offset = divmod(logical - chunk.logical, STRIPE_LEN)
        if profile & _STRIPED and stripe_offset + length > STRIPE_LEN:
            raise MappingError(
                f"logical range {logical}+{length} crosses a stripe boundary of "
                f"{PROFILES[profile][0]} chunk {chunk.logical}"
            )
        if profile == BG["RAID0"]:
            indices, stripe_nr = [stripe_nr % n], stripe_nr // n
        elif profile == BG["RAID10"]:
            factor = n // chunk.sub_stripes
            first = (stripe_nr % factor) * chunk.sub_stripes
            indices, stripe_nr = range(first, first + chunk.sub_stripes), stripe_nr // factor
        elif profile & (BG["RAID5"] | BG["RAID6"]):
            data_stripes = n - PROFILES[profile][2]
            index, stripe_nr = stripe_nr % data_stripes, stripe_nr // data_stripes
            indices = [(stripe_nr + index) % n]  # parity rotates across the stripes
        else:  # SINGLE, DUP, RAID1*: each stripe holds the whole chunk
            indices = range(n)
        return tuple(
            PhysicalCopy(
                mirror=mirror,
                devid=stripe.devid,
                physical=stripe.offset + (stripe_nr << 16) + stripe_offset,
                missing_device=self.devices.get(stripe.devid) != stripe.dev_uuid,
            )
            for mirror, stripe in enumerate((chunk.stripes[i] for i in indices), start=1)
        )
