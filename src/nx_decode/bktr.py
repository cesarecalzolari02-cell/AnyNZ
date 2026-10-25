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
one starts.

Bucket tree layout, 0x4000-byte nodes:

* offset node: index (u32, 0), entry-set count (u32), end offset (u64), then one
  u64 start offset per entry set (at most 0x7FE);
* entry sets: index (u32), entry count (u32), end offset (u64), then the entries.
  Every set but the last is full.

Tables needing a second offset level (more than 0x7FE entry sets, about 1.6 million
relocation entries) are reported as unsupported.
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
OFFSETS_PER_NODE = (NODE_SIZE - NODE_HEADER_SIZE) // 8
INDIRECT_ENTRY_SIZE = 0x14  # virtual offset u64, physical offset u64, storage index u32
AES_CTR_EX_ENTRY_SIZE = 0x10  # offset u64, encryption u8, reserved, generation u32
STORAGE_BASE, STORAGE_PATCH = 0, 1
ENCRYPTED, NOT_ENCRYPTED = 0, 1


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


def read_bucket_tree(
    section: Storage, info: TableInfo, entry_size: int, what: str
) -> tuple[list[bytes], int, int]:
    """Read and check a bucket tree. Returns ``(entries, start offset, end offset)``.

    Only the nodes the entry count calls for are read, so a corrupt table size
    cannot make this allocate more than the table itself (32 MiB at most).
    """
    per_set = (NODE_SIZE - NODE_HEADER_SIZE) // entry_size
    if info.entry_count == 0:
        raise FormatError(f"{what} table is empty")
    sets = -(-info.entry_count // per_set)
    if sets > OFFSETS_PER_NODE:
        raise UnsupportedError(
            f"{what} table with {info.entry_count} entries needs a second index level: "
            "not supported"
        )
    need = NODE_SIZE * (1 + sets)
    if info.size < need:
        raise FormatError(f"{what} table is smaller than its {info.entry_count} entries need")
    table = section.read_at(info.offset, need)
    if u32(table, 0) != 0 or u32(table, 4) != sets:
        raise FormatError(f"{what} table: bad offset node")
    end = u64(table, 0x8)
    starts = [u64(table, NODE_HEADER_SIZE + 8 * i) for i in range(sets)]
    entries: list[bytes] = []
    for i in range(sets):
        node = table[NODE_SIZE * (1 + i) : NODE_SIZE * (2 + i)]
        count = u32(node, 4)
        expected = min(per_set, info.entry_count - i * per_set)
        if u32(node, 0) != i or count != expected or u64(node, NODE_HEADER_SIZE) != starts[i]:
            raise FormatError(f"{what} table: bad entry set {i}")
        entries += [
            node[NODE_HEADER_SIZE + j * entry_size : NODE_HEADER_SIZE + (j + 1) * entry_size]
            for j in range(count)
        ]
    offsets = [u64(e, 0) for e in entries]
    if any(b <= a for a, b in pairwise(offsets)) or offsets[-1] >= end:
        raise FormatError(f"{what} table: entries are not in order")
    return entries, starts[0], end


class _BucketStorage(Storage):
    """A storage whose ranges are described by sorted bucket-tree entry offsets."""

    _starts: list[int]  # first offset covered by each entry
    _what: str

    def _pieces(self, offset: int, size: int) -> list[tuple[int, int, int]]:
        """Split a read into ``(entry index, offset, length)`` pieces, one per entry."""
        out = []
        pos, stop = offset, offset + size
        i = bisect.bisect_right(self._starts, pos) - 1
        if i < 0:
            raise FormatError(f"read at {pos:#x} is before the first {self._what} entry")
        while pos < stop:
            entry_end = self._starts[i + 1] if i + 1 < len(self._starts) else self.size
            n = min(stop, entry_end) - pos
            out.append((i, pos, n))
            pos += n
            i += 1
        return out


class AesCtrExStorage(_BucketStorage):
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
        table: tuple[list[bytes], int, int],
    ) -> None:
        entries, _, end = table
        self._raw = raw
        self._section_offset = section_offset
        self._key = key
        self._secure_value = secure_value
        self._starts = [u64(e, 0) for e in entries]
        self._encryption = [e[8] for e in entries]
        self._generation = [u32(e, 0xC) for e in entries]
        if any(enc not in (ENCRYPTED, NOT_ENCRYPTED) for enc in self._encryption):
            raise FormatError("subsection table: unknown encryption value")
        self._what, self.size = "subsection", end
        if end > raw.size:
            raise FormatError("subsection table reaches past the end of the section")

    def describe(self) -> str:
        return "patch data (AES-CTR-EX)"

    def _read(self, offset: int, size: int) -> bytes:
        out = bytearray()
        for i, pos, n in self._pieces(offset, size):
            if self._key is None or self._encryption[i] == NOT_ENCRYPTED:
                out += self._raw.read_at(pos, n)
                continue
            start = pos - pos % 16
            stop = min(-(-(pos + n) // 16) * 16, self._raw.size)
            data = self._raw.read_at(start, stop - start)
            upper = self._secure_value + self._generation[i].to_bytes(4, "big")
            plain = ctr_crypt(self._key, upper, self._section_offset + start, data)
            out += plain[pos - start : pos - start + n]
        return bytes(out)


class IndirectStorage(_BucketStorage):
    """The patched section image: every range comes from the base or from the patch."""

    def __init__(self, base: Storage, patch: Storage, table: tuple[list[bytes], int, int]) -> None:
        entries, _, end = table
        self._sources = (base, patch)
        self._starts = [u64(e, 0) for e in entries]
        self._physical = [u64(e, 0x8) for e in entries]
        self._storage = [u32(e, 0x10) for e in entries]
        if any(s not in (STORAGE_BASE, STORAGE_PATCH) for s in self._storage):
            raise FormatError("relocation table: unknown storage index")
        self._what, self.size = "relocation", end

    def describe(self) -> str:
        return "patched section"

    def _read(self, offset: int, size: int) -> bytes:
        out = bytearray()
        for i, pos, n in self._pieces(offset, size):
            source = self._sources[self._storage[i]]
            out += source.read_at(self._physical[i] + pos - self._starts[i], n)
        return bytes(out)
