"""BKTR: the bucket-tree tables of update (patch) NCAs, and the storages built on them.

An update's RomFS section does not hold a whole RomFS. Its PatchInfo (FS header
0x100) points at two bucket trees stored inside the section:

* the **relocation** table (IndirectStorage) maps every range of the patched,
  virtual section image to the base game's section (storage 0) or to the update's
  own patch data (storage 1);
* the **subsection** table (AesCtrExStorage) splits that patch data into ranges,
  each encrypted with its own counter generation, or not encrypted at all.

The patched image is then hashed (IVFC) and read as a RomFS like any other section.

Spec: https://switchbrew.org/wiki/NCA (PatchInfo, BucketTreeHeader, the relocation
and subsection table and entry layouts).
Reference: hactool ``bktr.h``/``nca.c`` and nxdumptool ``bktr.c``/``nca.c``/``aes.h``,
for what the wiki leaves out: entry-node capacity, the subsection encryption flag
(the wiki's "Padding/Unused?" byte at 0x8), the AES-CTR-EX counter, both tables
being read with the section's normal counter, and an entry ending where the next
one starts. The second offset level follows Atmosphère ``fssystem_bucket_tree``
(nxdumptool's port has the lookup but refuses such tables; Switchbrew and hactool
do not have it).

Bucket tree layout (0x4000-byte nodes): node storage, then entry storage.

* The L1 offset node: index (u32, 0), count (u32), end offset (u64), then up to
  0x7FE u64 offsets.
* Entry sets: index (u32), entry count (u32), end offset (u64), then the entries.
  There are ceil(entries / entries per set) of them; every set but the last is full.
* Up to 0x7FE entry sets, L1 holds one start offset per entry set. With more, there
  are L2 offset nodes right after L1 (header index = L2 node number). L1's first
  ``count`` offsets are those L2 nodes' start offsets, its remaining slots index the
  first ``0x7FE - count`` entry sets directly, and each L2 node indexes the next
  0x7FE entry sets.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from itertools import pairwise

from .crypto import ctr_crypt
from .errors import FormatError, UnsupportedError
from .io import Storage, u32, u64

BKTR_MAGIC = b"BKTR"
NODE_SIZE = 0x4000
NODE_HEADER_SIZE = 0x10
INDIRECT_ENTRY_SIZE = 0x14  # virtual offset u64, physical offset u64, storage index u32
AES_CTR_EX_ENTRY_SIZE = 0x10  # offset u64, encryption u8, reserved, generation u32
STORAGE_BASE, STORAGE_PATCH = 0, 1
ENCRYPTED, NOT_ENCRYPTED = 0, 1
CACHED_SETS = 64  # decoded entry sets kept per tree


def _div_up(a: int, b: int) -> int:
    return -(-a // b)


def l2_node_count(entry_sets: int, node_size: int = NODE_SIZE) -> int:
    """How many L2 offset nodes a tree with ``entry_sets`` entry sets has.

    Reference: Atmosphère ``BucketTree::GetNodeL2Count``.
    """
    per_node = (node_size - NODE_HEADER_SIZE) // 8
    if entry_sets <= per_node:
        return 0
    estimate = _div_up(entry_sets, per_node)
    if estimate > per_node:
        raise UnsupportedError(f"bucket tree with {entry_sets} entry sets: too large")
    return _div_up(entry_sets - (per_node - (estimate - 1)), per_node)


@dataclass(frozen=True)
class TableInfo:
    """One half of PatchInfo: where a bucket tree is in the section, and its entry count."""

    offset: int
    size: int
    entry_count: int

    @classmethod
    def parse(cls, raw: bytes, what: str) -> TableInfo:
        """``raw`` is 0x20 bytes: offset, size, then the 0x10-byte BucketTreeHeader."""
        if raw[0x10:0x14] != BKTR_MAGIC:
            raise FormatError(f"{what} table: bad BKTR magic")
        return cls(u64(raw, 0), u64(raw, 0x8), u32(raw, 0x18))


class BucketTree:
    """A bucket tree read from ``section``: offset nodes up front, entry sets on demand.

    Only the offset nodes are read when the tree is opened; each entry set is read
    and checked the first time it is needed, and a few are kept decoded. Memory is
    bounded by the table, not by its entry count.
    """

    def __init__(
        self,
        section: Storage,
        info: TableInfo,
        entry_size: int,
        what: str,
        node_size: int = NODE_SIZE,
    ) -> None:
        self.what = what
        self._section = section
        self._offset = info.offset
        self._entry_size = entry_size
        self._node_size = node_size
        self._per_set = (node_size - NODE_HEADER_SIZE) // entry_size
        self._entry_count = info.entry_count
        if info.entry_count == 0:
            raise FormatError(f"{what} table is empty")
        sets = _div_up(info.entry_count, self._per_set)
        l2 = l2_node_count(sets, node_size)
        self._entry_base = node_size * (1 + l2)
        need = self._entry_base + node_size * sets
        if info.size < need:
            raise FormatError(f"{what} table is smaller than its {info.entry_count} entries need")
        nodes = section.read_at(info.offset, self._entry_base)
        self.end = u64(nodes, 0x8)
        self._set_starts = self._offset_nodes(nodes, sets, l2)
        self.start = self._set_starts[0]
        if any(b <= a for a, b in pairwise(self._set_starts)) or self._set_starts[-1] >= self.end:
            raise FormatError(f"{what} table: entry sets are not in order")
        self._cache: dict[int, tuple[list[int], list[bytes]]] = {}

    def _offset_nodes(self, nodes: bytes, sets: int, l2: int) -> list[int]:
        """The start offset of every entry set, from L1 (and the L2 nodes)."""
        per_node = (self._node_size - NODE_HEADER_SIZE) // 8
        count = u32(nodes, 4)
        if u32(nodes, 0) != 0 or count != (l2 or sets):
            raise FormatError(f"{self.what} table: bad offset node")

        def offsets(node: int, first: int, n: int) -> list[int]:
            base = node * self._node_size + NODE_HEADER_SIZE + 8 * first
            return [u64(nodes, base + 8 * i) for i in range(n)]

        if not l2:
            return offsets(0, 0, sets)
        starts = offsets(0, count, per_node - count)  # L1's tail: the first entry sets
        for k in range(l2):
            n = min(per_node, sets - len(starts))
            header = (k + 1) * self._node_size
            if u32(nodes, header) != k or u32(nodes, header + 4) != n:
                raise FormatError(f"{self.what} table: bad L2 offset node {k}")
            node_starts = offsets(k + 1, 0, n)
            if offsets(0, k, 1)[0] != node_starts[0]:
                raise FormatError(f"{self.what} table: L1 and L2 offsets disagree")
            starts += node_starts
        return starts

    def _entry_set(self, i: int) -> tuple[list[int], list[bytes]]:
        """Entry set ``i``: its entries' start offsets and raw entries, checked."""
        if (hit := self._cache.get(i)) is not None:
            return hit
        size = self._entry_size
        node = self._section.read_at(
            self._offset + self._entry_base + i * self._node_size, self._node_size
        )
        count = u32(node, 4)
        expected = min(self._per_set, self._entry_count - i * self._per_set)
        if u32(node, 0) != i or count != expected:
            raise FormatError(f"{self.what} table: bad entry set {i}")
        raw = [
            node[NODE_HEADER_SIZE + j * size : NODE_HEADER_SIZE + (j + 1) * size]
            for j in range(count)
        ]
        starts = [u64(e, 0) for e in raw]
        set_end = self._set_starts[i + 1] if i + 1 < len(self._set_starts) else self.end
        if (
            starts[0] != self._set_starts[i]
            or any(b <= a for a, b in pairwise(starts))
            or starts[-1] >= set_end
        ):
            raise FormatError(f"{self.what} table: entries are not in order")
        if len(self._cache) >= CACHED_SETS:
            del self._cache[next(iter(self._cache))]
        self._cache[i] = (starts, raw)
        return starts, raw

    def pieces(self, offset: int, size: int) -> list[tuple[bytes, int, int, int]]:
        """Split ``[offset, offset + size)`` at entry boundaries.

        Returns ``(entry, entry start, piece offset, piece length)`` per piece.
        """
        out = []
        pos, stop = offset, offset + size
        s = bisect.bisect_right(self._set_starts, pos) - 1
        if s < 0:
            raise FormatError(f"read at {pos:#x} is before the first {self.what} entry")
        starts, raw = self._entry_set(s)
        e = bisect.bisect_right(starts, pos) - 1
        while pos < stop:
            if e + 1 < len(starts):
                entry_end = starts[e + 1]
            elif s + 1 < len(self._set_starts):
                entry_end = self._set_starts[s + 1]
            else:
                entry_end = self.end
            n = min(stop, entry_end) - pos
            out.append((raw[e], starts[e], pos, n))
            pos += n
            e += 1
            if e == len(starts) and pos < stop:
                s, e = s + 1, 0
                starts, raw = self._entry_set(s)
        return out


class AesCtrExStorage(Storage):
    """The update's own patch data: each subsection has its own counter generation.

    Counter: SecureValue (big-endian, from the FS header) | the entry's generation
    (big-endian) | absolute NCA offset >> 4. Reference: hactool
    ``nca_update_bktr_ctr``, nxdumptool ``aes128CtrUpdatePartialCtrEx``.
    """

    def __init__(
        self,
        raw: Storage,
        section_offset: int,
        key: bytes | None,
        secure_value: bytes,
        tree: BucketTree,
    ) -> None:
        self._raw = raw
        self._section_offset = section_offset
        self._key = key
        self._secure_value = secure_value
        self._tree = tree
        self.size = tree.end
        if tree.end > raw.size:
            raise FormatError("subsection table reaches past the end of the section")

    def describe(self) -> str:
        return "patch data (AES-CTR-EX)"

    def _read(self, offset: int, size: int) -> bytes:
        out = bytearray()
        for entry, _, pos, n in self._tree.pieces(offset, size):
            encryption = entry[8]
            if encryption not in (ENCRYPTED, NOT_ENCRYPTED):
                raise FormatError(f"subsection table: unknown encryption value {encryption}")
            if self._key is None or encryption == NOT_ENCRYPTED:
                out += self._raw.read_at(pos, n)
                continue
            start = pos - pos % 16
            stop = min(-(-(pos + n) // 16) * 16, self._raw.size)
            data = self._raw.read_at(start, stop - start)
            upper = self._secure_value + u32(entry, 0xC).to_bytes(4, "big")  # generation
            plain = ctr_crypt(self._key, upper, self._section_offset + start, data)
            out += plain[pos - start : pos - start + n]
        return bytes(out)


class IndirectStorage(Storage):
    """The patched section image: every range comes from the base or from the patch."""

    def __init__(self, base: Storage, patch: Storage, tree: BucketTree) -> None:
        self._sources = (base, patch)
        self._tree = tree
        self.size = tree.end

    def describe(self) -> str:
        return "patched section"

    def _read(self, offset: int, size: int) -> bytes:
        out = bytearray()
        for entry, start, pos, n in self._tree.pieces(offset, size):
            storage = u32(entry, 0x10)
            if storage not in (STORAGE_BASE, STORAGE_PATCH):
                raise FormatError(f"relocation table: unknown storage index {storage}")
            out += self._sources[storage].read_at(u64(entry, 0x8) + pos - start, n)
        return bytes(out)
