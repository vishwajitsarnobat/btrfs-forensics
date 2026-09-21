"""Which chunk maps a recovery reads a root's file data through (plan.md M5a, decision 3).

The maps come from the evidence database (`chunk_maps`, `chunks`, `stripes`), except the current
one, which is the opened filesystem's. A root whose own map is the current one is read through
it alone, as the kernel would. Any other root gets a `chunks.MapOrder`: its own map, the newer
maps oldest first, and last the map assembled from DEV_EXTENTs. The extent reader names the map
each extent went through; nothing here changes what the current map says.
"""

import sqlite3

from btrfska.catalog.schema import u64
from btrfska.recover.dbtree import Root
from btrfska.scan.chunkmaps import order_for
from btrfska.substrate.chunks import Chunk, ChunkMap, MapOrder, Stripe
from btrfska.substrate.node import NodeReader

_NEWEST = 1 << 64  # the current map's place in time when its chunk root is not recorded


def _stored_map(conn: sqlite3.Connection, map_id: int, name: str, devices) -> ChunkMap:
    chunks = []
    rows = conn.execute(
        "SELECT chunk_id, logical, length, type, sub_stripes, origin FROM chunks"
        " WHERE map_id = ? AND accepted ORDER BY chunk_id",
        (map_id,),
    ).fetchall()
    for chunk_id, logical, length, type_, sub_stripes, origin in rows:
        stripes = tuple(
            Stripe(u64(devid), u64(physical), bytes.fromhex(dev_uuid))
            for devid, physical, dev_uuid in conn.execute(
                "SELECT devid, physical, dev_uuid FROM stripes WHERE chunk_id = ?"
                " ORDER BY stripe_index",
                (chunk_id,),
            )
        )
        chunks.append(Chunk(u64(logical), u64(length), u64(type_), stripes, sub_stripes, origin))
    return ChunkMap(name, chunks, devices)


class Readers:
    """The node reader for each root of one recovery; `own` False keeps to the current map."""

    def __init__(self, conn: sqlite3.Connection, current: NodeReader, *, own: bool = True) -> None:
        self.conn, self.current, self.own = conn, current, own
        self.dated: list[tuple[str, int | None, ChunkMap]] = []
        self.fallback: list[ChunkMap] = []
        self.by_id: dict[int, tuple[str, str]] = {}
        self.cache: dict[tuple, NodeReader] = {}
        if not own:
            return
        devices = current.chunk_map.devices
        rows = conn.execute(
            "SELECT map_id, name, kind, root_generation FROM chunk_maps ORDER BY map_id"
        ).fetchall()
        for map_id, name, kind, generation in rows:
            self.by_id[map_id] = (name, kind)
            if kind == "current":
                place = _NEWEST if generation is None else u64(generation)
                self.dated.append((name, place, current.chunk_map))
            elif kind == "historical":
                self.dated.append((name, u64(generation), _stored_map(conn, map_id, name, devices)))
            else:
                self.fallback.append(_stored_map(conn, map_id, name, devices))

    def reader(self, root: Root) -> NodeReader:
        if not self.own:
            return self.current
        own = None
        if root.state_id is not None:
            row = self.conn.execute(
                "SELECT map_id FROM states WHERE state_id = ?", (root.state_id,)
            ).fetchone()
            own = self.by_id.get(row[0], (None,))[0] if row else None
        key = (own, None if own else root.generation)
        if key not in self.cache:
            order = order_for(root.generation, own, self.dated)
            if not order or order[0] is self.current.chunk_map:
                self.cache[key] = self.current
            else:
                self.cache[key] = NodeReader(
                    self.current.img, MapOrder(order, self.fallback), self.current.ctx
                )
        return self.cache[key]
