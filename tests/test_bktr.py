from __future__ import annotations

import os
import random
import struct
from collections.abc import Sequence

import pytest
from builders import (
    _ctr_enc,
    aes_ctr_ex_entry,
    bucket_header,
    build_bucket_tree,
    indirect_entry,
)

from nx_decode.bktr import (
    AES_CTR_EX_ENTRY_SIZE,
    INDIRECT_ENTRY_SIZE,
    NODE_SIZE,
    AesCtrExStorage,
    BucketTree,
    IndirectStorage,
    TableInfo,
    l2_node_count,
)
from nx_decode.errors import FormatError, UnsupportedError
from nx_decode.io import MemoryStorage


def tree(
    entries: Sequence[bytes], end: int, entry_size: int, node_size: int = NODE_SIZE
) -> BucketTree:
    blob = build_bucket_tree(entries, end, node_size)
    info = TableInfo(0, len(blob), len(entries))
    return BucketTree(MemoryStorage(blob), info, entry_size, "test", node_size)


def relocations(rng: random.Random, count: int, base_size: int, patch_size: int):
    """Random relocation entries on 0x10 boundaries, plus the image they describe."""
    base, patch = os.urandom(base_size), os.urandom(patch_size)
    entries, image, virt = [], bytearray(), 0
    for _ in range(count):
        length = rng.randrange(1, 5) * 0x10
        storage = rng.randrange(2)
        source = (base, patch)[storage]
        phys = rng.randrange(0, len(source) - length)
        entries.append(indirect_entry(virt, phys, storage))
        image += source[phys : phys + length]
        virt += length
    return entries, bytes(image), MemoryStorage(base), MemoryStorage(patch)


def check_reads(rng: random.Random, storage, image: bytes, reads: int = 300) -> None:
    assert storage.size == len(image)
    for _ in range(reads):
        off = rng.randrange(len(image))
        size = rng.randrange(1, min(0x900, len(image) - off) + 1)
        assert storage.read_at(off, size) == image[off : off + size]


def test_indirect_storage_across_entry_sets() -> None:
    # 2000 entries need three entry sets (0x332 entries each).
    rng = random.Random(5)
    entries, image, base, patch = relocations(rng, 2000, 0x8000, 0x8000)
    storage = IndirectStorage(base, patch, tree(entries, len(image), INDIRECT_ENTRY_SIZE))
    assert storage.read_at(0, len(image)) == image
    check_reads(rng, storage, image)


@pytest.mark.parametrize(("count", "l2_nodes"), [(9000, 1), (30000, 4)])
def test_second_offset_level(count: int, l2_nodes: int) -> None:
    # 0x400-byte nodes reach the L2 layout with thousands of entries instead of
    # millions: 126 offsets and 50 relocation entries per node.
    rng = random.Random(count)
    entries, image, base, patch = relocations(rng, count, 0x4000, 0x4000)
    sets = -(-count // 50)
    assert l2_node_count(sets, 0x400) == l2_nodes
    t = tree(entries, len(image), INDIRECT_ENTRY_SIZE, node_size=0x400)
    storage = IndirectStorage(base, patch, t)
    assert storage.read_at(0, len(image)) == image
    check_reads(rng, storage, image)


class PatternEntries(Sequence):
    """Relocation entry i: virtual i*0x10, physical (i*0x10) % 0x1000, alternating storage.
    Generated on demand, so a 1.6-million-entry table needs no list of entries."""

    def __init__(self, count: int) -> None:
        self.count = count

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self.count))]
        return struct.pack("<QQI", index * 0x10, index * 0x10 % 0x1000, index % 2)


def test_real_size_table_with_a_second_offset_level() -> None:
    count = 0x7FE * 0x332 + 1000  # just past what L1 alone can index
    assert l2_node_count(-(-count // 0x332)) == 1
    base, patch = os.urandom(0x1010), os.urandom(0x1010)
    storage = IndirectStorage(
        MemoryStorage(base),
        MemoryStorage(patch),
        tree(PatternEntries(count), count * 0x10, INDIRECT_ENTRY_SIZE),
    )

    def expected(offset: int, size: int) -> bytes:
        out = b""
        for pos in range(offset, offset + size):
            i = pos // 0x10
            out += (base, patch)[i % 2][i * 0x10 % 0x1000 + pos % 0x10 :][:1]
        return out

    last_l1_set = (0x7FE - 1) * 0x332  # first entry of the last set indexed from L1
    for entry in (0, 1, last_l1_set - 1, last_l1_set, 0x7FE * 0x332 - 1, count - 1):
        offset = min(max(entry * 0x10 - 8, 0), storage.size - 0x20)
        assert storage.read_at(offset, 0x20) == expected(offset, 0x20), hex(entry)


def test_aes_ctr_ex_storage_uses_each_subsection_generation() -> None:
    key, secure_value, section_offset = os.urandom(16), os.urandom(4), 0x4C00
    plain = os.urandom(0x3000)
    # (start, generation, encrypted): the counter's generation changes per subsection
    subsections = [(0x0, 7, True), (0x1230, 0x10000, True), (0x2000, 9, False), (0x2800, 3, True)]
    cipher = bytearray()
    for i, (start, gen, enc) in enumerate(subsections):
        end = subsections[i + 1][0] if i + 1 < len(subsections) else len(plain)
        chunk = plain[start:end]
        if enc:
            upper = secure_value + gen.to_bytes(4, "big")
            aligned = start - start % 16
            pad = start - aligned
            chunk = _ctr_enc(key, upper, section_offset + aligned, bytes(pad) + chunk)[pad:]
        cipher += chunk
    entries = [aes_ctr_ex_entry(s, g, e) for s, g, e in subsections]
    storage = AesCtrExStorage(
        MemoryStorage(bytes(cipher)),
        section_offset,
        key,
        secure_value,
        tree(entries, len(plain), AES_CTR_EX_ENTRY_SIZE),
    )
    assert storage.read_at(0, len(plain)) == plain
    for off, size in [(1, 15), (0x1220, 0x20), (0x1FF8, 0x10), (0x27F1, 0x30), (0x2FFF, 1)]:
        assert storage.read_at(off, size) == plain[off : off + size]


def test_plaintext_aes_ctr_ex_storage() -> None:
    data = os.urandom(0x800)
    table = tree([aes_ctr_ex_entry(0, 1), aes_ctr_ex_entry(0x400, 2)], len(data), 0x10)
    storage = AesCtrExStorage(MemoryStorage(data), 0, None, bytes(4), table)
    assert storage.read_at(0x3F0, 0x20) == data[0x3F0:0x410]


def test_table_info_needs_bktr_magic() -> None:
    raw = (0x100).to_bytes(8, "little") + (0x8000).to_bytes(8, "little") + bucket_header(3)
    assert TableInfo.parse(raw, "relocation") == TableInfo(0x100, 0x8000, 3)
    with pytest.raises(FormatError, match="magic"):
        TableInfo.parse(raw[:0x10] + b"XXXX" + raw[0x14:], "relocation")


def test_corrupt_tables_are_format_errors() -> None:
    entries = [indirect_entry(0, 0, 0), indirect_entry(0x100, 0, 1)]
    blob = build_bucket_tree(entries, 0x200)
    st = MemoryStorage(blob)
    with pytest.raises(FormatError, match="empty"):
        BucketTree(st, TableInfo(0, len(blob), 0), INDIRECT_ENTRY_SIZE, "relocation")
    with pytest.raises(FormatError, match="smaller"):
        BucketTree(st, TableInfo(0, 0x4000, 2), INDIRECT_ENTRY_SIZE, "relocation")
    # The entry count disagrees with the entry set: found when the set is read.
    short = BucketTree(st, TableInfo(0, len(blob), 1), INDIRECT_ENTRY_SIZE, "relocation")
    with pytest.raises(FormatError, match="entry set"):
        short.pieces(0, 0x10)
    unordered = build_bucket_tree([indirect_entry(0x100, 0, 0), indirect_entry(0x80, 0, 0)], 0x200)
    t = BucketTree(MemoryStorage(unordered), TableInfo(0, len(unordered), 2), 0x14, "x")
    with pytest.raises(FormatError, match="order"):
        t.pieces(0x100, 0x10)
    bad_index = tree([indirect_entry(0, 0, 2)], 0x100, INDIRECT_ENTRY_SIZE)
    storage = IndirectStorage(MemoryStorage(bytes(0x100)), MemoryStorage(bytes(0x100)), bad_index)
    with pytest.raises(FormatError, match="storage index"):
        storage.read_at(0, 0x10)


def test_corrupt_l2_nodes_are_format_errors() -> None:
    entries, image, _, _ = relocations(random.Random(2), 9000, 0x4000, 0x4000)
    blob = bytearray(build_bucket_tree(entries, len(image), 0x400))
    blob[0x400] = 7  # the L2 node's index
    info = TableInfo(0, len(blob), len(entries))
    with pytest.raises(FormatError, match="L2 offset node"):
        BucketTree(MemoryStorage(bytes(blob)), info, INDIRECT_ENTRY_SIZE, "relocation", 0x400)
    blob[0x400] = 0
    blob[0x10:0x18] = (1).to_bytes(8, "little")  # L1's pointer to the L2 node
    with pytest.raises(FormatError, match="disagree"):
        BucketTree(MemoryStorage(bytes(blob)), info, INDIRECT_ENTRY_SIZE, "relocation", 0x400)


def test_huge_tables_are_refused_before_anything_is_read() -> None:
    # Needs more entry sets than two offset levels can index.
    with pytest.raises(UnsupportedError, match="too large"):
        BucketTree(MemoryStorage(b""), TableInfo(0, 1 << 40, 0xFFFFFFFF), 0x14, "relocation")
    # Two levels would do, but the table is far smaller than its entry count needs.
    with pytest.raises(FormatError, match="smaller"):
        BucketTree(MemoryStorage(b""), TableInfo(0, 0x8000, 2_000_000), 0x14, "relocation")


def test_reads_past_the_mapped_range_are_format_errors() -> None:
    entries, image, base, patch = relocations(random.Random(1), 4, 0x100, 0x100)
    storage = IndirectStorage(base, patch, tree(entries, len(image), INDIRECT_ENTRY_SIZE))
    with pytest.raises(FormatError):
        storage.read_at(len(image) - 4, 8)
    # An entry pointing past the end of its source is caught when read.
    bad = tree([indirect_entry(0, 0xF0, 1)], 0x40, INDIRECT_ENTRY_SIZE)
    with pytest.raises(FormatError):
        IndirectStorage(base, patch, bad).read_at(0, 0x40)
